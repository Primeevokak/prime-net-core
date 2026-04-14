//! Per-ISP route profiling.
//!
//! Tracks which DPI evasion routes work best for the user's current ISP.
//! The ISP is identified by a configurable label (e.g. from a GeoIP lookup
//! or user configuration).  Route performance is aggregated per-ISP so
//! that users on different networks get different routing strategies
//! without polluting each other's bandit state.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::pt::socks5_server::now_unix_secs;

/// Global per-ISP route statistics, keyed by `"<isp_label>|<bucket>|<arm>"`.
static ISP_ROUTE_STATS: OnceLock<DashMap<String, IspArmStats>> = OnceLock::new();

/// Cached ISP label for the current session, detected at startup or set via config.
static CURRENT_ISP: OnceLock<parking_lot::RwLock<String>> = OnceLock::new();

/// Per-ISP performance statistics for a single route arm.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IspArmStats {
    /// Number of successful connections through this arm.
    pub successes: u64,
    /// Number of failed connections through this arm.
    pub failures: u64,
    /// Sum of connection latencies in milliseconds.
    pub total_latency_ms: u64,
    /// Sum of bytes transferred upstream-to-client.
    pub total_bytes_u2c: u64,
    /// Unix timestamp of last observation.
    pub last_seen_unix: u64,
}

impl IspArmStats {
    /// Mean latency in milliseconds, or 0 if no successful connections.
    pub fn mean_latency_ms(&self) -> u64 {
        if self.successes > 0 {
            self.total_latency_ms / self.successes
        } else {
            0
        }
    }

    /// Success rate as a fraction in `[0.0, 1.0]`.
    pub fn success_rate(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            0.0
        } else {
            self.successes as f64 / total as f64
        }
    }
}

/// Access the global ISP stats map.
fn stats_map() -> &'static DashMap<String, IspArmStats> {
    ISP_ROUTE_STATS.get_or_init(DashMap::new)
}

/// Get the current ISP label.
fn current_isp_lock() -> &'static parking_lot::RwLock<String> {
    CURRENT_ISP.get_or_init(|| parking_lot::RwLock::new("unknown".to_owned()))
}

/// Set the current ISP label.
///
/// Call this at engine startup with the detected or configured ISP name.
pub fn set_current_isp(isp: &str) {
    let mut guard = current_isp_lock().write();
    *guard = isp.to_owned();
}

/// Get a copy of the current ISP label.
pub fn get_current_isp() -> String {
    current_isp_lock().read().clone()
}

/// Build the composite key for ISP-specific arm stats.
fn isp_arm_key(isp: &str, bucket: &str, arm: &str) -> String {
    format!("{isp}|{bucket}|{arm}")
}

/// Record a successful connection for the current ISP.
pub fn record_isp_success(bucket: &str, arm: &str, latency_ms: u64, bytes_u2c: u64) {
    let isp = get_current_isp();
    let key = isp_arm_key(&isp, bucket, arm);
    let map = stats_map();
    let mut entry = map.entry(key).or_default();
    entry.successes += 1;
    entry.total_latency_ms += latency_ms;
    entry.total_bytes_u2c += bytes_u2c;
    entry.last_seen_unix = now_unix_secs();
}

/// Record a failed connection for the current ISP.
pub fn record_isp_failure(bucket: &str, arm: &str) {
    let isp = get_current_isp();
    let key = isp_arm_key(&isp, bucket, arm);
    let map = stats_map();
    let mut entry = map.entry(key).or_default();
    entry.failures += 1;
    entry.last_seen_unix = now_unix_secs();
}

/// Get the ISP-specific stats for a route arm, if any.
pub fn get_isp_arm_stats(bucket: &str, arm: &str) -> Option<IspArmStats> {
    let isp = get_current_isp();
    let key = isp_arm_key(&isp, bucket, arm);
    stats_map().get(&key).map(|e| e.clone())
}

/// Compute an ISP-specific score adjustment for a route arm.
///
/// Returns a bonus/penalty in `[-50, +50]` based on ISP-specific success rate
/// and latency.  Returns 0 if no ISP data is available.
pub fn isp_score_adjustment(bucket: &str, arm: &str) -> i64 {
    let stats = match get_isp_arm_stats(bucket, arm) {
        Some(s) => s,
        None => return 0,
    };

    let total = stats.successes + stats.failures;
    if total < 3 {
        return 0; // Not enough data.
    }

    let rate = stats.success_rate();

    // Base adjustment from success rate: range [-30, +30].
    let rate_adj = ((rate - 0.5) * 60.0) as i64;

    // Latency bonus: fast connections (<300ms mean) get up to +20.
    let latency_adj = if stats.successes > 0 {
        let mean_ms = stats.mean_latency_ms();
        if mean_ms < 150 {
            20
        } else if mean_ms < 300 {
            10
        } else if mean_ms > 2000 {
            -10
        } else {
            0
        }
    } else {
        0
    };

    (rate_adj + latency_adj).clamp(-50, 50)
}

/// Get the best-performing arm for a bucket based on ISP-specific data.
///
/// Returns `None` if there is insufficient ISP-specific data.
pub fn isp_best_arm(bucket: &str, arms: &[String]) -> Option<String> {
    let isp = get_current_isp();
    let map = stats_map();

    let mut best_arm = None;
    let mut best_score = f64::NEG_INFINITY;

    for arm in arms {
        let key = isp_arm_key(&isp, bucket, arm);
        if let Some(stats) = map.get(&key) {
            let total = stats.successes + stats.failures;
            if total < 5 {
                continue;
            }
            // Score: success rate weighted by log of total observations.
            let score = stats.success_rate() * (total as f64).ln();
            if score > best_score {
                best_score = score;
                best_arm = Some(arm.clone());
            }
        }
    }

    best_arm
}

/// Prune ISP stats not seen within `max_age_secs`.
pub fn prune_isp_state(now: u64, max_age_secs: u64) {
    stats_map().retain(|_, stats| now.saturating_sub(stats.last_seen_unix) <= max_age_secs);
}

/// Point-in-time snapshot of ISP profiling data for diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct IspProfileSnapshot {
    /// Current ISP label.
    pub isp: String,
    /// Number of ISP-specific arm entries.
    pub entries: usize,
    /// Top 10 arms by total observations for the current ISP.
    pub top_arms: Vec<IspArmEntry>,
}

/// Single arm entry in an ISP profile snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct IspArmEntry {
    /// The bucket and arm id.
    pub key: String,
    /// Success rate in `[0.0, 1.0]`.
    pub success_rate: f64,
    /// Mean latency in ms.
    pub mean_latency_ms: u64,
    /// Total observations.
    pub total: u64,
}

/// Collect a snapshot of ISP profiling state.
pub fn isp_profile_snapshot() -> IspProfileSnapshot {
    let isp = get_current_isp();
    let map = stats_map();
    let prefix = format!("{isp}|");

    let mut entries: Vec<IspArmEntry> = map
        .iter()
        .filter(|e| e.key().starts_with(&prefix))
        .map(|e| {
            let stats = e.value();
            IspArmEntry {
                key: e.key().strip_prefix(&prefix).unwrap_or(e.key()).to_owned(),
                success_rate: stats.success_rate(),
                mean_latency_ms: stats.mean_latency_ms(),
                total: stats.successes + stats.failures,
            }
        })
        .collect();

    entries.sort_unstable_by(|a, b| b.total.cmp(&a.total));
    entries.truncate(10);

    IspProfileSnapshot {
        isp,
        entries: map.iter().filter(|e| e.key().starts_with(&prefix)).count(),
        top_arms: entries,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod isp_profiler_tests {
    use super::*;

    fn cleanup_keys(keys: &[&str]) {
        let map = stats_map();
        for k in keys {
            map.remove(*k);
        }
    }

    #[test]
    fn record_and_retrieve_isp_stats() {
        set_current_isp("test-isp");
        record_isp_success("youtube", "native:1", 200, 5000);
        record_isp_success("youtube", "native:1", 150, 3000);
        record_isp_failure("youtube", "native:1");

        let stats = get_isp_arm_stats("youtube", "native:1").unwrap();
        assert_eq!(stats.successes, 2);
        assert_eq!(stats.failures, 1);
        assert_eq!(stats.mean_latency_ms(), 175); // (200+150)/2
        assert!((stats.success_rate() - 2.0 / 3.0).abs() < 0.01);

        cleanup_keys(&["test-isp|youtube|native:1"]);
    }

    #[test]
    fn isp_score_adjustment_positive_for_high_success() {
        set_current_isp("adj-test-isp");
        for _ in 0..10 {
            record_isp_success("discord", "native:2", 100, 1000);
        }
        record_isp_failure("discord", "native:2");

        let adj = isp_score_adjustment("discord", "native:2");
        assert!(
            adj > 0,
            "high success rate should give positive adjustment: {adj}"
        );

        cleanup_keys(&["adj-test-isp|discord|native:2"]);
    }

    #[test]
    fn isp_score_adjustment_negative_for_low_success() {
        set_current_isp("adj-neg-isp");
        record_isp_success("default", "native:3", 500, 100);
        for _ in 0..10 {
            record_isp_failure("default", "native:3");
        }

        let adj = isp_score_adjustment("default", "native:3");
        assert!(
            adj < 0,
            "low success rate should give negative adjustment: {adj}"
        );

        cleanup_keys(&["adj-neg-isp|default|native:3"]);
    }

    #[test]
    fn isp_score_adjustment_zero_insufficient_data() {
        set_current_isp("insuf-isp");
        record_isp_success("test", "arm-x", 100, 100);

        let adj = isp_score_adjustment("test", "arm-x");
        assert_eq!(adj, 0, "1 observation is insufficient");

        cleanup_keys(&["insuf-isp|test|arm-x"]);
    }

    #[test]
    fn isp_best_arm_selects_highest_scorer() {
        set_current_isp("best-arm-isp");
        // arm-a: 8/10 success
        for _ in 0..8 {
            record_isp_success("bucket", "arm-a", 100, 1000);
        }
        for _ in 0..2 {
            record_isp_failure("bucket", "arm-a");
        }
        // arm-b: 3/10 success
        for _ in 0..3 {
            record_isp_success("bucket", "arm-b", 100, 1000);
        }
        for _ in 0..7 {
            record_isp_failure("bucket", "arm-b");
        }

        let arms = vec!["arm-a".to_owned(), "arm-b".to_owned()];
        let best = isp_best_arm("bucket", &arms);
        assert_eq!(best, Some("arm-a".to_owned()));

        cleanup_keys(&["best-arm-isp|bucket|arm-a", "best-arm-isp|bucket|arm-b"]);
    }

    #[test]
    fn prune_removes_stale_isp_entries() {
        let map = stats_map();
        let now = now_unix_secs();

        let stale_key = "prune-isp|old|arm".to_owned();
        let fresh_key = "prune-isp|new|arm".to_owned();

        map.insert(
            stale_key.clone(),
            IspArmStats {
                successes: 5,
                failures: 0,
                total_latency_ms: 500,
                total_bytes_u2c: 1000,
                last_seen_unix: now.saturating_sub(8 * 24 * 3600),
            },
        );
        map.insert(
            fresh_key.clone(),
            IspArmStats {
                successes: 3,
                failures: 1,
                total_latency_ms: 300,
                total_bytes_u2c: 500,
                last_seen_unix: now.saturating_sub(3600),
            },
        );

        prune_isp_state(now, 7 * 24 * 3600);

        assert!(!map.contains_key(&stale_key));
        assert!(map.contains_key(&fresh_key));

        map.remove(&fresh_key);
    }

    #[test]
    fn snapshot_returns_current_isp_data() {
        set_current_isp("snap-isp");
        record_isp_success("youtube", "native:1", 100, 1000);

        let snap = isp_profile_snapshot();
        assert_eq!(snap.isp, "snap-isp");
        assert!(snap.entries > 0);

        cleanup_keys(&["snap-isp|youtube|native:1"]);
    }
}
