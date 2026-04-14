//! Telemetry aggregation with percentile latency statistics.
//!
//! Collects per-bucket connection metrics (latency, throughput, error rates)
//! and computes aggregate statistics including P50/P95/P99 latencies using
//! a fixed-size ring buffer to bound memory usage.

use dashmap::DashMap;
use serde::Serialize;
use std::sync::OnceLock;

use crate::pt::socks5_server::now_unix_secs;

/// Global telemetry aggregation state, keyed by bucket name.
static AGGREGATOR: OnceLock<DashMap<String, BucketTelemetry>> = OnceLock::new();

/// Maximum number of latency samples kept per bucket.
const MAX_LATENCY_SAMPLES: usize = 1000;

/// Per-bucket telemetry accumulator.
#[derive(Debug, Clone, Default)]
pub struct BucketTelemetry {
    /// Total connections attempted.
    pub total_connections: u64,
    /// Successful connections (connect + TLS handshake OK).
    pub successful_connections: u64,
    /// Failed connections.
    pub failed_connections: u64,
    /// Total bytes transferred (upstream to client).
    pub total_bytes_u2c: u64,
    /// Ring buffer of recent latency samples (in milliseconds).
    latency_samples: Vec<u64>,
    /// Write cursor into the ring buffer.
    latency_cursor: usize,
    /// Whether the ring buffer has wrapped around.
    latency_full: bool,
    /// Last update timestamp (unix seconds).
    pub last_updated_unix: u64,
}

impl BucketTelemetry {
    /// Record a latency sample into the ring buffer.
    fn push_latency(&mut self, ms: u64) {
        if self.latency_samples.len() < MAX_LATENCY_SAMPLES {
            self.latency_samples.push(ms);
        } else {
            self.latency_samples[self.latency_cursor] = ms;
            self.latency_full = true;
        }
        self.latency_cursor = (self.latency_cursor + 1) % MAX_LATENCY_SAMPLES;
    }

    /// Return a sorted copy of all active latency samples.
    fn sorted_latencies(&self) -> Vec<u64> {
        let mut v = if self.latency_full {
            self.latency_samples.clone()
        } else {
            self.latency_samples[..self.latency_samples.len()].to_vec()
        };
        v.sort_unstable();
        v
    }
}

/// Access the global aggregator map.
fn aggregator_map() -> &'static DashMap<String, BucketTelemetry> {
    AGGREGATOR.get_or_init(DashMap::new)
}

/// Record a successful connection in the telemetry aggregator.
pub fn record_connection_success(bucket: &str, latency_ms: u64, bytes_u2c: u64) {
    let map = aggregator_map();
    let mut entry = map.entry(bucket.to_owned()).or_default();
    entry.total_connections += 1;
    entry.successful_connections += 1;
    entry.total_bytes_u2c += bytes_u2c;
    entry.push_latency(latency_ms);
    entry.last_updated_unix = now_unix_secs();
}

/// Record a failed connection in the telemetry aggregator.
pub fn record_connection_failure(bucket: &str) {
    let map = aggregator_map();
    let mut entry = map.entry(bucket.to_owned()).or_default();
    entry.total_connections += 1;
    entry.failed_connections += 1;
    entry.last_updated_unix = now_unix_secs();
}

/// Compute the P-th percentile from a sorted slice.
///
/// Uses linear interpolation between adjacent ranks.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }

    let rank = (p / 100.0) * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;

    if lower == upper {
        sorted[lower]
    } else {
        let frac = rank - lower as f64;
        let a = sorted[lower] as f64;
        let b = sorted[upper] as f64;
        (a + frac * (b - a)).round() as u64
    }
}

/// Aggregated latency statistics for a bucket.
#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    /// Number of samples used.
    pub sample_count: usize,
    /// Minimum latency (ms).
    pub min_ms: u64,
    /// Maximum latency (ms).
    pub max_ms: u64,
    /// Mean latency (ms).
    pub mean_ms: u64,
    /// Median latency (ms).
    pub p50_ms: u64,
    /// 95th percentile latency (ms).
    pub p95_ms: u64,
    /// 99th percentile latency (ms).
    pub p99_ms: u64,
}

/// Compute latency statistics for a bucket.
///
/// Returns `None` if no latency samples have been recorded.
pub fn latency_stats(bucket: &str) -> Option<LatencyStats> {
    let map = aggregator_map();
    let entry = map.get(bucket)?;
    let sorted = entry.sorted_latencies();
    if sorted.is_empty() {
        return None;
    }

    let sum: u64 = sorted.iter().sum();
    Some(LatencyStats {
        sample_count: sorted.len(),
        min_ms: sorted[0],
        max_ms: *sorted.last().unwrap_or(&0),
        mean_ms: sum / sorted.len() as u64,
        p50_ms: percentile(&sorted, 50.0),
        p95_ms: percentile(&sorted, 95.0),
        p99_ms: percentile(&sorted, 99.0),
    })
}

/// Full telemetry snapshot for a single bucket.
#[derive(Debug, Clone, Serialize)]
pub struct BucketSnapshot {
    /// Bucket name.
    pub bucket: String,
    /// Total connections attempted.
    pub total_connections: u64,
    /// Success rate as fraction `[0.0, 1.0]`.
    pub success_rate: f64,
    /// Total bytes transferred upstream-to-client.
    pub total_bytes_u2c: u64,
    /// Latency statistics (if samples exist).
    pub latency: Option<LatencyStats>,
    /// Unix timestamp of last update.
    pub last_updated_unix: u64,
}

/// Collect snapshots of all tracked buckets, sorted by total connections descending.
pub fn all_bucket_snapshots() -> Vec<BucketSnapshot> {
    let map = aggregator_map();
    let mut snapshots: Vec<BucketSnapshot> = map
        .iter()
        .map(|e| {
            let bucket = e.key().clone();
            let t = e.value();
            let sorted = t.sorted_latencies();
            let latency = if sorted.is_empty() {
                None
            } else {
                let sum: u64 = sorted.iter().sum();
                Some(LatencyStats {
                    sample_count: sorted.len(),
                    min_ms: sorted[0],
                    max_ms: *sorted.last().unwrap_or(&0),
                    mean_ms: sum / sorted.len() as u64,
                    p50_ms: percentile(&sorted, 50.0),
                    p95_ms: percentile(&sorted, 95.0),
                    p99_ms: percentile(&sorted, 99.0),
                })
            };
            let success_rate = if t.total_connections > 0 {
                t.successful_connections as f64 / t.total_connections as f64
            } else {
                0.0
            };
            BucketSnapshot {
                bucket,
                total_connections: t.total_connections,
                success_rate,
                total_bytes_u2c: t.total_bytes_u2c,
                latency,
                last_updated_unix: t.last_updated_unix,
            }
        })
        .collect();

    snapshots.sort_unstable_by(|a, b| b.total_connections.cmp(&a.total_connections));
    snapshots
}

/// Prune buckets not updated within `max_age_secs`.
pub fn prune_aggregator(now: u64, max_age_secs: u64) {
    aggregator_map().retain(|_, t| now.saturating_sub(t.last_updated_unix) <= max_age_secs);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod telemetry_aggregator_tests {
    use super::*;

    fn cleanup_bucket(bucket: &str) {
        aggregator_map().remove(bucket);
    }

    #[test]
    fn percentile_basic() {
        let data: Vec<u64> = (1..=100).collect();
        // P50 of [1..100]: rank=49.5 → interp(50,51)=50.5 → 51
        assert_eq!(percentile(&data, 50.0), 51);
        assert_eq!(percentile(&data, 95.0), 95);
        assert_eq!(percentile(&data, 99.0), 99);
        assert_eq!(percentile(&data, 0.0), 1);
        assert_eq!(percentile(&data, 100.0), 100);
    }

    #[test]
    fn percentile_single_element() {
        assert_eq!(percentile(&[42], 50.0), 42);
        assert_eq!(percentile(&[42], 95.0), 42);
    }

    #[test]
    fn percentile_empty() {
        assert_eq!(percentile(&[], 50.0), 0);
    }

    #[test]
    fn record_and_query_success() {
        let bucket = "agg-test-success";
        cleanup_bucket(bucket);

        record_connection_success(bucket, 100, 5000);
        record_connection_success(bucket, 200, 3000);
        record_connection_success(bucket, 150, 4000);

        let stats = latency_stats(bucket).unwrap();
        assert_eq!(stats.sample_count, 3);
        assert_eq!(stats.min_ms, 100);
        assert_eq!(stats.max_ms, 200);
        assert_eq!(stats.mean_ms, 150);

        cleanup_bucket(bucket);
    }

    #[test]
    fn record_failure_increments_count() {
        let bucket = "agg-test-failure";
        cleanup_bucket(bucket);

        record_connection_failure(bucket);
        record_connection_failure(bucket);
        record_connection_success(bucket, 100, 1000);

        let map = aggregator_map();
        {
            let entry = map.get(bucket).unwrap();
            assert_eq!(entry.total_connections, 3);
            assert_eq!(entry.failed_connections, 2);
            assert_eq!(entry.successful_connections, 1);
        }

        cleanup_bucket(bucket);
    }

    #[test]
    fn p95_calculation_with_many_samples() {
        let bucket = "agg-test-p95";
        cleanup_bucket(bucket);

        // Record 100 samples: 1ms, 2ms, ..., 100ms
        for i in 1..=100 {
            record_connection_success(bucket, i, 100);
        }

        let stats = latency_stats(bucket).unwrap();
        assert_eq!(stats.sample_count, 100);
        assert_eq!(stats.min_ms, 1);
        assert_eq!(stats.max_ms, 100);
        assert_eq!(stats.p50_ms, 51);
        assert!(
            (stats.p95_ms as i64 - 95).abs() <= 1,
            "p95 should be ~95: {}",
            stats.p95_ms
        );
        assert!(
            (stats.p99_ms as i64 - 99).abs() <= 1,
            "p99 should be ~99: {}",
            stats.p99_ms
        );

        cleanup_bucket(bucket);
    }

    #[test]
    fn ring_buffer_wraps_at_max() {
        let bucket = "agg-test-ring";
        cleanup_bucket(bucket);

        // Fill beyond MAX_LATENCY_SAMPLES
        for i in 0..(MAX_LATENCY_SAMPLES + 100) {
            record_connection_success(bucket, (i % 500) as u64, 100);
        }

        let stats = latency_stats(bucket).unwrap();
        assert_eq!(
            stats.sample_count, MAX_LATENCY_SAMPLES,
            "should be capped at MAX_LATENCY_SAMPLES"
        );

        cleanup_bucket(bucket);
    }

    #[test]
    fn all_bucket_snapshots_sorted_by_total() {
        let b1 = "agg-snap-a";
        let b2 = "agg-snap-b";
        cleanup_bucket(b1);
        cleanup_bucket(b2);

        record_connection_success(b1, 100, 1000);
        for _ in 0..5 {
            record_connection_success(b2, 200, 2000);
        }

        let snaps = all_bucket_snapshots();
        let b2_idx = snaps.iter().position(|s| s.bucket == b2);
        let b1_idx = snaps.iter().position(|s| s.bucket == b1);

        if let (Some(i2), Some(i1)) = (b2_idx, b1_idx) {
            assert!(i2 < i1, "b2 (5 conns) should come before b1 (1 conn)");
        }

        cleanup_bucket(b1);
        cleanup_bucket(b2);
    }

    #[test]
    fn prune_removes_stale_buckets() {
        let stale = "agg-prune-stale";
        let fresh = "agg-prune-fresh";
        let map = aggregator_map();

        map.insert(
            stale.to_owned(),
            BucketTelemetry {
                total_connections: 5,
                last_updated_unix: now_unix_secs().saturating_sub(8 * 24 * 3600),
                ..Default::default()
            },
        );
        map.insert(
            fresh.to_owned(),
            BucketTelemetry {
                total_connections: 3,
                last_updated_unix: now_unix_secs().saturating_sub(3600),
                ..Default::default()
            },
        );

        prune_aggregator(now_unix_secs(), 7 * 24 * 3600);

        assert!(!map.contains_key(stale));
        assert!(map.contains_key(fresh));

        map.remove(fresh);
    }

    #[test]
    fn latency_stats_none_for_unknown_bucket() {
        assert!(latency_stats("agg-nonexistent").is_none());
    }
}
