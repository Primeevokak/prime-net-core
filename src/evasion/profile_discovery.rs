//! Automatic native desync profile discovery.
//!
//! On first run (or when explicitly triggered) the engine probes each native
//! desync profile against a small set of well-known HTTPS test domains.  Profiles
//! that successfully complete a TLS handshake are marked as *working* and sorted
//! to the front of the profile list so the ML scorer encounters them first.
//!
//! # Persistence
//!
//! Discovery results are stored in JSON at:
//! `<data_dir>/prime-net/profile_wins.json`
//!
//! A result is considered fresh for [`CACHE_TTL_SECS`] seconds.  Stale results
//! trigger a re-probe in the background.
//!
//! # Test domains
//!
//! The probe list (`TEST_DOMAINS`) targets services that are commonly censored
//! and always respond with a TLS ServerHello when reached.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::evasion::dpi_bypass::{send_fake_sni_probe, send_tcb_desync_probe};

use crate::evasion::tcp_desync::{NativeDesyncProfile, TcpDesyncEngine};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Domains tested during profile discovery (IP:port for deterministic probing).
///
/// Using IPs avoids DNS dependency during discovery.  These IPs are stable
/// infrastructure endpoints unlikely to change addresses frequently.
const TEST_ENDPOINTS: &[(&str, &str)] = &[
    ("162.159.136.234:443", "discord.com"), // Cloudflare / Discord
    ("208.65.153.238:443", "rutracker.org"), // RuTracker
    ("93.184.216.34:443", "example.com"),   // IANA example (always up)
];

/// How long (seconds) cached discovery results remain valid before re-probing.
const CACHE_TTL_SECS: u64 = 86_400; // 24 hours

/// Timeout per profile probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// Minimum response size to count as a valid TLS ServerHello.
const MIN_SERVER_HELLO_BYTES: usize = 6;

// ── Cache types ───────────────────────────────────────────────────────────────

/// Persisted discovery cache entry for one profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileWinEntry {
    /// Number of test probes that produced a TLS ServerHello response.
    pub wins: u32,
    /// Total probes attempted (wins + failures).
    pub probes: u32,
    /// Unix timestamp of the last discovery run for this profile.
    pub last_run: u64,
}

/// Full discovery cache: profile name → win entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileDiscoveryCache {
    entries: HashMap<String, ProfileWinEntry>,
}

impl ProfileDiscoveryCache {
    /// Load the cache from `path`, returning an empty cache on error.
    pub async fn load(path: &PathBuf) -> Self {
        tokio::fs::read_to_string(path)
            .await
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist the cache to `path`.
    pub async fn save(&self, path: &PathBuf) {
        if let Some(dir) = path.parent() {
            let _ = tokio::fs::create_dir_all(dir).await;
        }
        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                if let Err(e) = tokio::fs::write(path, json).await {
                    warn!(
                        "profile discovery: could not save cache to {}: {e}",
                        path.display()
                    );
                }
            }
            Err(e) => warn!("profile discovery: could not serialise cache: {e}"),
        }
    }

    /// Replace the entry for `profile_name` with fresh results.
    ///
    /// Unlike [`record`] this **overwrites** rather than accumulates so that a
    /// stale "3/3 wins" from a previous run cannot inflate the score if the
    /// current run found "0/3 wins".
    pub fn record_overwrite(&mut self, profile_name: &str, wins: u32, probes: u32) {
        self.entries.insert(
            profile_name.to_owned(),
            ProfileWinEntry {
                wins,
                probes,
                last_run: now_secs(),
            },
        );
    }

    /// Record `wins` wins and `probes` total probes for `profile_name`.
    pub fn record(&mut self, profile_name: &str, wins: u32, probes: u32) {
        let now = now_secs();
        self.entries
            .entry(profile_name.to_owned())
            .and_modify(|e| {
                e.wins += wins;
                e.probes += probes;
                e.last_run = now;
            })
            .or_insert(ProfileWinEntry {
                wins,
                probes,
                last_run: now,
            });
    }

    /// True when `profile_name` has a fresh (non-stale) cache entry.
    pub fn is_fresh(&self, profile_name: &str) -> bool {
        self.entries
            .get(profile_name)
            .map(|e| now_secs().saturating_sub(e.last_run) < CACHE_TTL_SECS)
            .unwrap_or(false)
    }

    /// Win count for `profile_name` (0 if unknown).
    pub fn wins(&self, profile_name: &str) -> u32 {
        self.entries.get(profile_name).map(|e| e.wins).unwrap_or(0)
    }

    /// True when all profiles in `names` have fresh entries (no re-probe needed).
    pub fn all_fresh<'a>(&self, names: impl Iterator<Item = &'a str>) -> bool {
        names.into_iter().all(|n| self.is_fresh(n))
    }
}

// ── Discovery runner ──────────────────────────────────────────────────────────

/// Probe all profiles in `engine` against the test endpoints, update `cache`,
/// and return a new profile list sorted by win count (highest first).
///
/// Profiles are probed **in parallel** (one task per profile) so discovery
/// completes in `O(1 round)` rather than `O(profiles)` rounds.  Spawn this as
/// a background task so it does not block proxy startup.
pub async fn run_profile_discovery(
    engine: &TcpDesyncEngine,
    cache: &mut ProfileDiscoveryCache,
) -> Vec<NativeDesyncProfile> {
    let count = engine.profile_count();
    info!(
        "profile discovery: probing {} profiles against {} endpoints (parallel)",
        count,
        TEST_ENDPOINTS.len()
    );

    // Collect per-profile data upfront so we can move it into spawned tasks.
    let profiles_to_probe: Vec<(usize, String)> = (0..count)
        .filter(|&idx| {
            let name = engine.profile_name(idx);
            if cache.is_fresh(name) {
                debug!("profile discovery: '{}' cache is fresh, skipping", name);
                false
            } else {
                true
            }
        })
        .map(|idx| (idx, engine.profile_name(idx).to_owned()))
        .collect();

    if profiles_to_probe.is_empty() {
        return sort_profiles_by_cache(engine, cache);
    }

    // Clone the engine so each task can probe independently.
    let engine_arc = std::sync::Arc::new(engine.clone());
    let mut tasks = tokio::task::JoinSet::new();

    for (idx, name) in profiles_to_probe {
        let eng = engine_arc.clone();
        tasks.spawn(async move {
            let (wins, probes) = probe_profile(&eng, idx).await;
            (name, wins, probes)
        });
    }

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((name, wins, probes)) => {
                // Overwrite (not accumulate) so stale wins from prior runs are discarded.
                cache.record_overwrite(&name, wins, probes);
                debug!(
                    "profile discovery: '{}' — {}/{} probes succeeded",
                    name, wins, probes
                );
            }
            Err(e) => warn!("profile discovery: task panicked: {e}"),
        }
    }

    sort_profiles_by_cache(engine, cache)
}

/// Probe profile `idx` against all `TEST_ENDPOINTS`.
///
/// Returns `(wins, total_probes)`.
async fn probe_profile(engine: &TcpDesyncEngine, profile_idx: usize) -> (u32, u32) {
    let mut wins = 0u32;
    let mut total = 0u32;

    for (endpoint, sni) in TEST_ENDPOINTS {
        total += 1;
        if probe_single(engine, profile_idx, endpoint, sni).await {
            wins += 1;
        }
    }

    (wins, total)
}

/// Connect to `endpoint`, apply the profile's desync technique (including its
/// fake probe if configured), and check whether the server responds with a TLS
/// ServerHello.
///
/// Returns `true` on success.
async fn probe_single(
    engine: &TcpDesyncEngine,
    profile_idx: usize,
    endpoint: &str,
    sni: &str,
) -> bool {
    let result = tokio::time::timeout(PROBE_TIMEOUT, async {
        let addr: std::net::SocketAddr = endpoint
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;

        // Send the profile's fake probe BEFORE the real connection — this is what
        // actually desynchronises DPI state; without it, profiles with fake_probe
        // would score identically to their simpler counterparts.
        if let Some(fp) = engine.profile_fake_probe(profile_idx) {
            if let Some(ref fake_sni) = fp.fake_sni {
                let _ = send_fake_sni_probe(addr, fp.ttl, fake_sni).await;
            } else {
                let _ = send_tcb_desync_probe(addr, fp.ttl).await;
            }
        }

        let mut stream = TcpStream::connect(addr).await?;
        let hello = build_probe_client_hello(sni);

        engine
            .apply_to_tcp_stream(profile_idx, &mut stream, &hello)
            .await?;
        stream.flush().await?;

        let mut resp = [0u8; 64];
        let n = stream.read(&mut resp).await?;

        // A TLS ServerHello starts with 0x16 (handshake record).
        let success = n >= MIN_SERVER_HELLO_BYTES && resp[0] == 0x16;
        Ok::<bool, std::io::Error>(success)
    })
    .await;

    matches!(result, Ok(Ok(true)))
}

/// Sort profiles from `engine` by descending win count in `cache`.
///
/// Profiles not in the cache (win=0) go to the end.  Within equal win counts
/// the original order is preserved (stable sort).
fn sort_profiles_by_cache(
    engine: &TcpDesyncEngine,
    cache: &ProfileDiscoveryCache,
) -> Vec<NativeDesyncProfile> {
    let mut indexed: Vec<(usize, u32)> = (0..engine.profile_count())
        .map(|i| {
            let name = engine.profile_name(i);
            let wins = cache.wins(name);
            (i, wins)
        })
        .collect();

    // Stable descending sort: highest wins first, original order as tie-breaker.
    indexed.sort_by(|a, b| b.1.cmp(&a.1));

    indexed
        .into_iter()
        .map(|(i, _)| engine.profile_at(i).clone())
        .collect()
}

// ── Discovery cache path ──────────────────────────────────────────────────────

/// Return the path to the persisted profile discovery cache JSON file.
pub fn cache_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("prime-net")
        .join("profile_wins.json")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build a minimal TLS ClientHello for probing.
fn build_probe_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len();
    let sni_list_len = 3 + sni_len;
    let sni_ext_data = 2 + sni_list_len;
    let sni_ext_wire = 4 + sni_ext_data;

    let ch_body_len = 2 + 32 + 1 + 2 + 4 + 1 + 1 + 2 + sni_ext_wire;
    let hs_len = 4 + ch_body_len;

    let mut buf = Vec::with_capacity(5 + hs_len);
    buf.extend_from_slice(&[0x16, 0x03, 0x01]);
    buf.extend_from_slice(&(hs_len as u16).to_be_bytes());
    buf.push(0x01);
    buf.extend_from_slice(&[
        (ch_body_len >> 16) as u8,
        (ch_body_len >> 8) as u8,
        ch_body_len as u8,
    ]);
    buf.extend_from_slice(&[0x03, 0x03]);
    buf.extend_from_slice(&[0u8; 32]);
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
    buf.extend_from_slice(&[0x01, 0x00]);
    buf.extend_from_slice(&(sni_ext_wire as u16).to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&(sni_ext_data as u16).to_be_bytes());
    buf.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&(sni_len as u16).to_be_bytes());
    buf.extend_from_slice(sni_bytes);
    buf
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod profile_discovery_tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn cache_record_and_retrieve() {
        let mut cache = ProfileDiscoveryCache::default();
        cache.record("tlsrec-into-sni", 2, 3);
        assert_eq!(cache.wins("tlsrec-into-sni"), 2);
        assert!(cache.is_fresh("tlsrec-into-sni"));
        assert_eq!(cache.wins("nonexistent"), 0);
    }

    #[tokio::test]
    async fn cache_round_trip_json() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let mut cache = ProfileDiscoveryCache::default();
        cache.record("split-into-sni", 3, 3);
        cache.record("tlsrec-into-sni", 1, 3);
        cache.save(&path).await;

        let loaded = ProfileDiscoveryCache::load(&path).await;
        assert_eq!(loaded.wins("split-into-sni"), 3);
        assert_eq!(loaded.wins("tlsrec-into-sni"), 1);
    }

    #[test]
    fn probe_client_hello_starts_with_tls_record() {
        let hello = build_probe_client_hello("discord.com");
        assert_eq!(hello[0], 0x16); // TLS record type: Handshake
        assert_eq!(hello[5], 0x01); // Handshake type: ClientHello
    }
}
