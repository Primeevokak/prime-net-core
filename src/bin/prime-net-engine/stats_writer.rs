//! Background task that writes a JSON stats snapshot to a file every 5 seconds.
//!
//! The GUI polls this file instead of an IPC socket so there is no coupling
//! between the engine process and the GUI process lifecycle.  Writes are
//! atomic (write to `.tmp`, rename) so the reader never sees a partial file.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prime_net_engine_core::pt::socks5_server::ml_shadow::{ml_state_snapshot, MlStateSnapshot};
use prime_net_engine_core::pt::socks5_server::routing_state;
use serde::Serialize;
use tracing::warn;

/// Aggregate route counters snapshot.
#[derive(Debug, Serialize)]
pub struct RouteMetricsSnapshot {
    /// Total route races started (multiple candidates tried in parallel).
    pub race_started: u64,
    /// Races skipped because a cached winner was available.
    pub race_skipped: u64,
    /// Successful connections via the direct (unmodified) route.
    pub success_direct: u64,
    /// Successful connections via an external bypass proxy.
    pub success_bypass: u64,
    /// Successful connections via native TCP desync.
    pub success_native: u64,
    /// Failed connections via the direct route.
    pub failure_direct: u64,
    /// Failed connections via bypass proxy.
    pub failure_bypass: u64,
    /// Failed connections via native desync.
    pub failure_native: u64,
}

/// Full stats snapshot written to disk every 5 seconds.
#[derive(Debug, Serialize)]
pub struct StatsSnapshot {
    /// Unix timestamp (seconds) when this snapshot was taken.
    pub timestamp_unix: u64,
    /// How long the engine has been running, in seconds.
    pub uptime_secs: u64,
    /// SOCKS5 listen address (e.g. `"127.0.0.1:1080"`).
    pub listen_addr: String,
    /// Number of loaded native desync profiles (0 = native bypass disabled).
    pub native_profiles_count: usize,
    /// Aggregate route success/failure counters.
    pub metrics: RouteMetricsSnapshot,
    /// ML bandit arm state.
    pub ml: MlStateSnapshot,
    /// Number of distinct destinations being tracked by the classifier.
    pub destinations_tracked: usize,
}

/// Spawn a background task that writes a [`StatsSnapshot`] to `path` every 5 s.
///
/// Returns a [`tokio::task::JoinHandle`] — dropping it cancels the writer.
pub fn spawn_stats_writer(
    path: PathBuf,
    listen_addr: String,
    native_profiles_count: usize,
    start_time: Instant,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(write_loop(
        path,
        listen_addr,
        native_profiles_count,
        start_time,
    ))
}

async fn write_loop(
    path: PathBuf,
    listen_addr: String,
    native_profiles_count: usize,
    start_time: Instant,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await; // consume the first immediate tick

    loop {
        interval.tick().await;

        let snapshot = collect_snapshot(&listen_addr, native_profiles_count, &start_time);
        let json = match serde_json::to_string_pretty(&snapshot) {
            Ok(j) => j,
            Err(e) => {
                warn!(target: "stats_writer", error = %e, "failed to serialize stats snapshot");
                continue;
            }
        };

        // Atomic write: write to .tmp then rename so the reader never sees a partial file.
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = tokio::fs::write(&tmp, json.as_bytes()).await {
            warn!(
                target: "stats_writer",
                error = %e,
                path = %tmp.display(),
                "failed to write stats snapshot"
            );
            continue;
        }
        if let Err(e) = tokio::fs::rename(&tmp, &path).await {
            warn!(
                target: "stats_writer",
                error = %e,
                "failed to rename stats snapshot into place"
            );
        }
    }
}

fn collect_snapshot(
    listen_addr: &str,
    native_profiles_count: usize,
    start_time: &Instant,
) -> StatsSnapshot {
    let rs = routing_state();
    let m = &rs.route_metrics;

    let metrics = RouteMetricsSnapshot {
        race_started: m.race_started.load(Ordering::Relaxed),
        race_skipped: m.race_skipped.load(Ordering::Relaxed),
        success_direct: m.route_success_direct.load(Ordering::Relaxed),
        success_bypass: m.route_success_bypass.load(Ordering::Relaxed),
        success_native: m.route_success_native.load(Ordering::Relaxed),
        failure_direct: m.route_failure_direct.load(Ordering::Relaxed),
        failure_bypass: m.route_failure_bypass.load(Ordering::Relaxed),
        failure_native: m.route_failure_native.load(Ordering::Relaxed),
    };

    StatsSnapshot {
        timestamp_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        uptime_secs: start_time.elapsed().as_secs(),
        listen_addr: listen_addr.to_owned(),
        native_profiles_count,
        metrics,
        ml: ml_state_snapshot(),
        destinations_tracked: rs.dest_classifier.len(),
    }
}
