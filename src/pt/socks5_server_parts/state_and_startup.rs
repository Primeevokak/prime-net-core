use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::Duration;
use tracing::{error, info, warn};

use crate::blocklist::expand_tilde;
use crate::error::{EngineError, Result};
use crate::evasion::{FragmentConfig, FragmentingIo};

use super::{BoxStream, DynOutbound, TargetAddr, TargetEndpoint};

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);
#[cfg(windows)]
static PID_NAME_CACHE: OnceLock<Mutex<HashMap<u32, String>>> = OnceLock::new();
static WARNED_SOCKS4_LIMITATIONS: AtomicBool = AtomicBool::new(false);
static WARNED_SOCKS4_AGGRESSIVE: AtomicBool = AtomicBool::new(false);
static DEST_FAILURES: OnceLock<Mutex<HashMap<String, u8>>> = OnceLock::new();
static DEST_PREFERRED_STAGE: OnceLock<Mutex<HashMap<String, u8>>> = OnceLock::new();
static DEST_CLASSIFIER: OnceLock<Mutex<HashMap<String, DestinationClassifier>>> = OnceLock::new();
static DEST_BYPASS_PROFILE_IDX: OnceLock<Mutex<HashMap<String, u8>>> = OnceLock::new();
static DEST_BYPASS_PROFILE_FAILURES: OnceLock<Mutex<HashMap<String, u8>>> = OnceLock::new();
static GLOBAL_BYPASS_PROFILE_HEALTH: OnceLock<Mutex<HashMap<String, BypassProfileHealth>>> =
    OnceLock::new();
static DEST_ROUTE_WINNER: OnceLock<Mutex<HashMap<String, RouteWinner>>> = OnceLock::new();
static DEST_ROUTE_HEALTH: OnceLock<Mutex<HashMap<String, HashMap<String, RouteHealth>>>> =
    OnceLock::new();
static STAGE_RACE_STATS: OnceLock<Mutex<HashMap<u8, StageRaceStats>>> = OnceLock::new();
static RACE_SOURCE_COUNTERS: OnceLock<Mutex<RaceSourceCounters>> = OnceLock::new();
static ROUTE_METRICS: OnceLock<Mutex<RouteMetrics>> = OnceLock::new();
static ROUTE_CAPABILITIES: OnceLock<Mutex<RouteCapabilities>> = OnceLock::new();
static LAST_CLASSIFIER_EMIT_UNIX: AtomicU64 = AtomicU64::new(0);
static CLASSIFIER_STORE_CFG: OnceLock<Option<ClassifierStoreConfig>> = OnceLock::new();
static CLASSIFIER_STORE_LOADED: AtomicBool = AtomicBool::new(false);
static CLASSIFIER_STORE_DIRTY: AtomicBool = AtomicBool::new(false);
static CLASSIFIER_STORE_LAST_FLUSH_UNIX: AtomicU64 = AtomicU64::new(0);
const CLASSIFIER_PERSIST_DEBOUNCE_SECS: u64 = 30;
const UDP_POLICY_DISABLE_THRESHOLD: u64 = 6;
const UDP_POLICY_DISABLE_SECS: u64 = 120;
const LEARNED_BYPASS_MIN_FAILURES_DOMAIN: u8 = 2;
const LEARNED_BYPASS_MIN_FAILURES_IP: u8 = 1;
const ROUTE_WINNER_TTL_SECS: u64 = 15 * 60;
const ROUTE_WEAK_BASE_SECS: u64 = 45;
const ROUTE_WEAK_MAX_SECS: u64 = 5 * 60;
const ROUTE_FAILS_BEFORE_WEAK: u8 = 2;
const ROUTE_SOFT_ZERO_REPLY_MIN_C2U: u64 = 256;
const ROUTE_CAPABILITY_NET_UNREACHABLE_SECS: u64 = 3 * 60;
const ROUTE_CAPABILITY_BYPASS_REP03_SECS: u64 = 10 * 60;
const ROUTE_CAPABILITY_BYPASS_REP_OTHER_SECS: u64 = 4 * 60;
const GLOBAL_BYPASS_HARD_WEAK_SCORE: i64 = -80;
const ROUTE_RACE_BASE_DELAY_MS: u64 = 60;
const ROUTE_RACE_BYPASS_EXTRA_DELAY_MS: u64 = 120;
const ROUTE_RACE_BYPASS_EXTRA_DELAY_BUILTIN_MS: u64 = 40;
const ROUTE_RACE_BYPASS_EXTRA_DELAY_LEARNED_MS: u64 = 20;

#[derive(Debug, Clone)]
pub struct RelayOptions {
    pub fragment_client_hello: bool,
    pub split_at_sni: bool,
    pub client_hello_split_offsets: Vec<usize>,
    pub fragment_size: usize,
    pub fragment_sleep_ms: u64,
    pub fragment_budget_bytes: usize,
    pub stage1_failures: u8,
    pub stage2_failures: u8,
    pub stage3_failures: u8,
    pub stage4_failures: u8,
    pub suspicious_zero_reply_min_c2u: usize,
    pub classifier_emit_interval_secs: u64,
    pub classifier_persist_enabled: bool,
    pub classifier_cache_path: Option<String>,
    pub classifier_entry_ttl_secs: u64,
    pub strategy_race_enabled: bool,
    pub upstream_socks5: Option<SocketAddr>,
    pub bypass_socks5: Option<SocketAddr>,
    pub bypass_socks5_pool: Vec<SocketAddr>,
    pub bypass_domain_check: Option<fn(&str) -> bool>,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            fragment_client_hello: false,
            split_at_sni: true,
            client_hello_split_offsets: vec![1, 5, 40],
            fragment_size: 64,
            fragment_sleep_ms: 0,
            fragment_budget_bytes: 8192,
            stage1_failures: 1,
            stage2_failures: 2,
            stage3_failures: 3,
            stage4_failures: 5,
            suspicious_zero_reply_min_c2u: 700,
            classifier_emit_interval_secs: 15,
            classifier_persist_enabled: true,
            classifier_cache_path: None,
            classifier_entry_ttl_secs: 7 * 24 * 60 * 60,
            strategy_race_enabled: true,
            upstream_socks5: None,
            bypass_socks5: None,
            bypass_socks5_pool: Vec::new(),
            bypass_domain_check: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BlockingSignal {
    Reset,
    Timeout,
    EarlyClose,
    BrokenPipe,
    SuspiciousZeroReply,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct DestinationClassifier {
    failures: u64,
    resets: u64,
    timeouts: u64,
    early_closes: u64,
    broken_pipes: u64,
    suspicious_zero_replies: u64,
    successes: u64,
    #[serde(default)]
    last_seen_unix: u64,
}

#[derive(Debug, Clone)]
struct TunedRelay {
    options: RelayOptions,
    stage: u8,
    source: StageSelectionSource,
}

#[derive(Debug, Clone, Copy)]
enum StageSelectionSource {
    Cache,
    Probe,
    Adaptive,
}

#[derive(Debug, Clone)]
struct ClassifierStoreConfig {
    path: PathBuf,
    entry_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ClassifierSnapshot {
    #[serde(default)]
    version: u8,
    #[serde(default)]
    updated_at_unix: u64,
    #[serde(default)]
    entries: HashMap<String, ClassifierSnapshotEntry>,
    #[serde(default)]
    global_bypass_health: HashMap<String, BypassProfileHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ClassifierSnapshotEntry {
    #[serde(default)]
    failures: u8,
    #[serde(default)]
    preferred_stage: u8,
    #[serde(default)]
    stats: DestinationClassifier,
    #[serde(default)]
    bypass_profile_idx: Option<u8>,
    #[serde(default)]
    bypass_profile_failures: u8,
    #[serde(default)]
    route_winner: Option<RouteWinner>,
    #[serde(default)]
    route_health: HashMap<String, RouteHealth>,
}

#[derive(Debug, Clone, Default)]
struct StageRaceStats {
    successes: u64,
    failures: u64,
}

#[derive(Debug, Clone, Default)]
struct RaceSourceCounters {
    cache: u64,
    probe: u64,
    adaptive: u64,
}

#[derive(Debug, Clone, Default)]
struct RouteMetrics {
    race_started: u64,
    race_skipped: u64,
    race_reason_non_tls: u64,
    race_reason_single_candidate: u64,
    race_reason_no_winner: u64,
    race_reason_empty_winner: u64,
    race_reason_winner_stale: u64,
    race_reason_winner_missing: u64,
    race_reason_winner_weak: u64,
    race_reason_winner_healthy: u64,
    winner_cache_hits: u64,
    winner_cache_misses: u64,
    route_selected_direct: u64,
    route_selected_bypass: u64,
    race_winner_direct: u64,
    race_winner_bypass: u64,
    route_success_direct: u64,
    route_success_bypass: u64,
    route_failure_direct: u64,
    route_failure_bypass: u64,
    route_soft_zero_reply_direct: u64,
    route_soft_zero_reply_bypass: u64,
    connect_failure_direct: u64,
    connect_failure_bypass: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteRaceReason {
    NonTlsPort,
    SingleCandidate,
    NoWinner,
    EmptyWinner,
    WinnerStale,
    WinnerMissingFromCandidates,
    WinnerWeak,
    WinnerHealthy,
}

#[derive(Debug, Clone, Default)]
struct UdpDestinationPolicy {
    sent: u64,
    recv: u64,
    disabled_until_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteKind {
    Direct,
    Bypass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteIpFamily {
    Any,
    V4,
    V6,
}

impl RouteIpFamily {
    fn label(self) -> &'static str {
        match self {
            RouteIpFamily::Any => "any",
            RouteIpFamily::V4 => "v4",
            RouteIpFamily::V6 => "v6",
        }
    }
}

#[derive(Debug, Clone)]
struct RouteCandidate {
    kind: RouteKind,
    source: &'static str,
    family: RouteIpFamily,
    bypass_addr: Option<SocketAddr>,
    bypass_profile_idx: u8,
    bypass_profile_total: u8,
}

impl RouteCandidate {
    #[cfg(test)]
    fn direct(source: &'static str) -> Self {
        Self::direct_with_family(source, RouteIpFamily::Any)
    }

    fn direct_with_family(source: &'static str, family: RouteIpFamily) -> Self {
        Self {
            kind: RouteKind::Direct,
            source,
            family,
            bypass_addr: None,
            bypass_profile_idx: 0,
            bypass_profile_total: 1,
        }
    }

    #[cfg(test)]
    fn bypass(source: &'static str, addr: SocketAddr, profile_idx: u8, profile_total: u8) -> Self {
        Self::bypass_with_family(source, addr, profile_idx, profile_total, RouteIpFamily::Any)
    }

    fn bypass_with_family(
        source: &'static str,
        addr: SocketAddr,
        profile_idx: u8,
        profile_total: u8,
        family: RouteIpFamily,
    ) -> Self {
        Self {
            kind: RouteKind::Bypass,
            source,
            family,
            bypass_addr: Some(addr),
            bypass_profile_idx: profile_idx,
            bypass_profile_total: profile_total,
        }
    }

    fn route_id(&self) -> String {
        match self.kind {
            RouteKind::Direct => "direct".to_owned(),
            RouteKind::Bypass => format!("bypass:{}", self.bypass_profile_idx + 1),
        }
    }

    fn route_label(&self) -> &'static str {
        match self.kind {
            RouteKind::Direct => "direct",
            RouteKind::Bypass => "bypass",
        }
    }

    fn kind_rank(&self) -> u8 {
        match self.kind {
            RouteKind::Direct => 0,
            RouteKind::Bypass => 1,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct RouteCapabilities {
    direct_v4_weak_until_unix: u64,
    direct_v6_weak_until_unix: u64,
    bypass_v4_weak_until_unix: u64,
    bypass_v6_weak_until_unix: u64,
}

struct ConnectedRoute {
    candidate: RouteCandidate,
    stream: BoxStream,
    route_key: String,
    raced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RouteHealth {
    #[serde(default)]
    successes: u64,
    #[serde(default)]
    failures: u64,
    #[serde(default)]
    consecutive_failures: u8,
    #[serde(default)]
    weak_until_unix: u64,
    #[serde(default)]
    last_success_unix: u64,
    #[serde(default)]
    last_failure_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BypassProfileHealth {
    #[serde(default)]
    successes: u64,
    #[serde(default)]
    failures: u64,
    #[serde(default)]
    connect_failures: u64,
    #[serde(default)]
    soft_zero_replies: u64,
    #[serde(default)]
    io_errors: u64,
    #[serde(default)]
    last_success_unix: u64,
    #[serde(default)]
    last_failure_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RouteWinner {
    #[serde(default)]
    route_id: String,
    #[serde(default)]
    updated_at_unix: u64,
}

#[derive(Debug)]
pub struct Socks5ServerGuard {
    listen_addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Socks5ServerGuard {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

impl Drop for Socks5ServerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        maybe_flush_classifier_store(true);
        self.handle.abort();
    }
}

pub async fn start_socks5_server(
    bind: &str,
    outbound: DynOutbound,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<Socks5ServerGuard> {
    init_classifier_store(&relay_opts);
    load_classifier_store_if_needed();
    let listener = TcpListener::bind(bind).await?;
    let listen_addr = listener.local_addr()?;
    info!(target: "socks5", listen_addr = %listen_addr, silent_drop, "SOCKS5 server started");
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let Ok((tcp, peer)) = res else { continue; };
                    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                    let outbound = outbound.clone();
                    let relay_opts = relay_opts.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(conn_id, tcp, peer, listen_addr, outbound, silent_drop, relay_opts).await {
                            error!(target: "socks5", conn_id, peer = %peer, error = %e, "SOCKS5 session failed");
                        }
                    });
                }
            }
        }
    });

    Ok(Socks5ServerGuard {
        listen_addr,
        shutdown_tx: Some(shutdown_tx),
        handle,
    })
}

async fn connect_bypass_upstream(
    conn_id: u64,
    target: &TargetEndpoint,
    target_label: &str,
    bypass_addr: SocketAddr,
    bypass_profile_idx: u8,
    bypass_profile_total: u8,
) -> Result<TcpStream> {
    let connect =
        tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(bypass_addr)).await;
    let mut bypass = match connect {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(
                target: "socks5",
                conn_id,
                destination = %target_label,
                bypass = %bypass_addr,
                error = %e,
                "bypass connect failed"
            );
            record_bypass_profile_failure(
                target_label,
                bypass_profile_idx,
                bypass_profile_total,
                "connect-failed",
            );
            return Err(e.into());
        }
        Err(_) => {
            warn!(
                target: "socks5",
                conn_id,
                destination = %target_label,
                bypass = %bypass_addr,
                "bypass connect timeout"
            );
            record_bypass_profile_failure(
                target_label,
                bypass_profile_idx,
                bypass_profile_total,
                "connect-timeout",
            );
            return Err(EngineError::Internal("bypass connect timeout".to_owned()));
        }
    };
    let _ = bypass.set_nodelay(true);

    if let Err(e) = bypass.write_all(&[0x05, 0x01, 0x00]).await {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "handshake-io",
        );
        return Err(e.into());
    }
    let mut method = [0u8; 2];
    if let Err(e) = bypass.read_exact(&mut method).await {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "handshake-io",
        );
        return Err(e.into());
    }
    if method[0] != 0x05 || method[1] != 0x00 {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "auth-rejected",
        );
        return Err(EngineError::Internal(format!(
            "bypass socks5 auth rejected: {:02x} {:02x}",
            method[0], method[1]
        )));
    }

    let mut req: Vec<u8> = vec![0x05, 0x01, 0x00];
    match &target.addr {
        TargetAddr::Domain(host) => {
            let b = host.as_bytes();
            if b.len() > 255 {
                return Err(EngineError::Internal("bypass domain too long".to_owned()));
            }
            req.push(0x03);
            req.push(b.len() as u8);
            req.extend_from_slice(b);
        }
        TargetAddr::Ip(std::net::IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port.to_be_bytes());
    if let Err(e) = bypass.write_all(&req).await {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "handshake-io",
        );
        return Err(e.into());
    }

    let mut reply_hdr = [0u8; 4];
    if let Err(e) = bypass.read_exact(&mut reply_hdr).await {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "handshake-io",
        );
        return Err(e.into());
    }
    if reply_hdr[0] != 0x05 {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "invalid-reply-version",
        );
        return Err(EngineError::Internal(format!(
            "bypass socks5 invalid reply version: 0x{:02x}",
            reply_hdr[0]
        )));
    }
    if reply_hdr[1] != 0x00 {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "rep-nonzero",
        );
        return Err(EngineError::Internal(format!(
            "ciadpi rejected connect: REP=0x{:02x}",
            reply_hdr[1]
        )));
    }
    match reply_hdr[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            if let Err(e) = bypass.read_exact(&mut b).await {
                record_bypass_profile_failure(
                    target_label,
                    bypass_profile_idx,
                    bypass_profile_total,
                    "handshake-io",
                );
                return Err(e.into());
            }
        }
        0x03 => {
            let mut l = [0u8; 1];
            if let Err(e) = bypass.read_exact(&mut l).await {
                record_bypass_profile_failure(
                    target_label,
                    bypass_profile_idx,
                    bypass_profile_total,
                    "handshake-io",
                );
                return Err(e.into());
            }
            let mut b = vec![0u8; l[0] as usize + 2];
            if let Err(e) = bypass.read_exact(&mut b).await {
                record_bypass_profile_failure(
                    target_label,
                    bypass_profile_idx,
                    bypass_profile_total,
                    "handshake-io",
                );
                return Err(e.into());
            }
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            if let Err(e) = bypass.read_exact(&mut b).await {
                record_bypass_profile_failure(
                    target_label,
                    bypass_profile_idx,
                    bypass_profile_total,
                    "handshake-io",
                );
                return Err(e.into());
            }
        }
        other => {
            record_bypass_profile_failure(
                target_label,
                bypass_profile_idx,
                bypass_profile_total,
                "invalid-addr-type",
            );
            return Err(EngineError::Internal(format!(
                "bypass invalid addr type: 0x{other:02x}"
            )));
        }
    }
    Ok(bypass)
}

async fn connect_route_candidate(
    conn_id: u64,
    outbound: DynOutbound,
    target: TargetEndpoint,
    destination: String,
    candidate: RouteCandidate,
) -> Result<BoxStream> {
    match candidate.kind {
        RouteKind::Direct => outbound.connect(target).await,
        RouteKind::Bypass => {
            let bypass_addr = candidate.bypass_addr.ok_or_else(|| {
                EngineError::Internal("bypass candidate is missing address".to_owned())
            })?;
            let stream = connect_bypass_upstream(
                conn_id,
                &target,
                &destination,
                bypass_addr,
                candidate.bypass_profile_idx,
                candidate.bypass_profile_total,
            )
            .await?;
            Ok(Box::new(stream))
        }
    }
}

fn engine_error_is_network_unreachable(err: &EngineError) -> bool {
    match err {
        EngineError::Io(io) => {
            matches!(
                io.kind(),
                ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable
            ) || matches!(io.raw_os_error(), Some(10051 | 10065 | 113))
        }
        _ => false,
    }
}

fn engine_error_bypass_rep_code(err: &EngineError) -> Option<u8> {
    let EngineError::Internal(msg) = err else {
        return None;
    };
    let marker = "REP=0x";
    let idx = msg.find(marker)?;
    let hex = msg.get(idx + marker.len()..idx + marker.len() + 2)?;
    u8::from_str_radix(hex, 16).ok()
}

fn engine_error_is_dns_sinkhole(err: &EngineError) -> bool {
    let msg = match err {
        EngineError::InvalidInput(msg) => msg.as_str(),
        EngineError::Internal(msg) => msg.as_str(),
        _ => return false,
    };
    msg.contains("unspecified/sinkhole IPs")
}

fn should_ignore_route_failure(candidate: &RouteCandidate, err: &EngineError) -> bool {
    candidate.kind == RouteKind::Direct && engine_error_is_dns_sinkhole(err)
}

fn maybe_mark_route_capability_failure(candidate: &RouteCandidate, err: &EngineError) {
    if candidate.family == RouteIpFamily::Any {
        return;
    }

    if engine_error_is_network_unreachable(err) {
        mark_route_capability_weak(
            candidate.kind,
            candidate.family,
            "network-unreachable",
            ROUTE_CAPABILITY_NET_UNREACHABLE_SECS,
        );
        return;
    }

    if candidate.kind == RouteKind::Bypass {
        if let Some(rep) = engine_error_bypass_rep_code(err) {
            let penalty = if rep == 0x03 {
                ROUTE_CAPABILITY_BYPASS_REP03_SECS
            } else {
                ROUTE_CAPABILITY_BYPASS_REP_OTHER_SECS
            };
            mark_route_capability_weak(
                RouteKind::Bypass,
                candidate.family,
                "bypass-rep-nonzero",
                penalty,
            );
        }
    }
}

