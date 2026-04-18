//! Background task that writes a JSON stats snapshot to a file every 5 seconds.
//!
//! The GUI polls this file instead of an IPC socket so there is no coupling
//! between the engine process and the GUI process lifecycle.  Writes are
//! atomic (write to `.tmp`, rename) so the reader never sees a partial file.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prime_net_engine_core::evasion::startup_report::{DegradedReason, DesyncEngineReport};
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

/// Per-profile status entry for the GUI.
///
/// Describes a single native desync profile's name, technique, and whether
/// it is running in degraded mode (e.g. missing WinDivert).
#[derive(Debug, Clone, Serialize)]
pub struct ProfileSnapshotEntry {
    /// Short identifier (e.g. `"tcp-disorder-15ms"`).
    pub name: String,
    /// Desync technique label (e.g. `"TcpSegmentSplit"`, `"TcpDisorder"`).
    pub technique: String,
    /// `"operational"` or `"degraded"`.
    pub status: String,
    /// Human-readable reason when `status == "degraded"`.
    pub degraded_reason: Option<String>,
}

/// Packet interceptor / raw injector capability snapshot.
///
/// Derived once at startup from [`DesyncEngineReport`] and included
/// verbatim in every [`StatsSnapshot`] so the GUI can display the
/// WinDivert status and any degraded profiles.
#[derive(Debug, Clone, Serialize)]
pub struct EngineCapabilitySnapshot {
    /// Whether a packet interceptor (WinDivert/NFQueue) is available.
    pub has_packet_interceptor: bool,
    /// Name of the interceptor backend (e.g. `"WinDivert"`), if loaded.
    pub interceptor_backend: Option<String>,
    /// Whether the raw packet injector (WinDivert send-only handle) is available.
    pub has_raw_injector: bool,
    /// Number of profiles operating in degraded mode.
    pub degraded_profiles_count: usize,
    /// Names of profiles operating in degraded mode.
    pub degraded_profile_names: Vec<String>,
    /// Per-profile operational status for the GUI profile list.
    pub profiles: Vec<ProfileSnapshotEntry>,
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
    /// Packet interceptor status, raw injector availability, and per-profile
    /// degradation info.  `None` when native bypass is not active.
    pub capabilities: Option<EngineCapabilitySnapshot>,
}

/// Build an [`EngineCapabilitySnapshot`] from a [`DesyncEngineReport`] and the
/// engine's profile list.
///
/// Called once at startup; the returned value is cloned into every stats tick.
pub fn build_capability_snapshot(
    report: &DesyncEngineReport,
    engine: &prime_net_engine_core::evasion::TcpDesyncEngine,
) -> EngineCapabilitySnapshot {
    let degraded_profile_names: Vec<String> =
        report.degraded.iter().map(|d| d.name.clone()).collect();

    let mut profiles = Vec::with_capacity(report.total_profiles);
    for idx in 0..engine.profile_count() {
        let p = engine.profile_at(idx);
        let technique_label = technique_short_label(&p.technique);

        // Find whether this profile appears in the degraded list.
        let degraded_entry = report.degraded.iter().find(|d| d.name == p.name);
        let (status, reason) = match degraded_entry {
            Some(d) => (
                "degraded".to_owned(),
                Some(degraded_reason_label(&d.reason)),
            ),
            None => ("operational".to_owned(), None),
        };

        profiles.push(ProfileSnapshotEntry {
            name: p.name.clone(),
            technique: technique_label,
            status,
            degraded_reason: reason,
        });
    }

    EngineCapabilitySnapshot {
        has_packet_interceptor: report.has_packet_interceptor,
        interceptor_backend: report.interceptor_backend.clone(),
        has_raw_injector: report.has_raw_injector,
        degraded_profiles_count: report.degraded.len(),
        degraded_profile_names,
        profiles,
    }
}

/// Short human-readable label for a [`DesyncTechnique`] variant.
fn technique_short_label(
    t: &prime_net_engine_core::evasion::tcp_desync::DesyncTechnique,
) -> String {
    use prime_net_engine_core::evasion::tcp_desync::DesyncTechnique;
    match t {
        DesyncTechnique::TcpSegmentSplit { .. } => "TcpSegmentSplit".to_owned(),
        DesyncTechnique::TlsRecordSplit { .. } => "TlsRecordSplit".to_owned(),
        DesyncTechnique::TlsRecordSplitOob { .. } => "TlsRecordSplitOob".to_owned(),
        DesyncTechnique::TcpSegmentSplitOob { .. } => "TcpSegmentSplitOob".to_owned(),
        DesyncTechnique::HttpSplit { .. } => "HttpSplit".to_owned(),
        DesyncTechnique::MultiSplit { .. } => "MultiSplit".to_owned(),
        DesyncTechnique::TlsRecordPadding { .. } => "TlsRecordPadding".to_owned(),
        DesyncTechnique::TcpDisorder { .. } => "TcpDisorder".to_owned(),
        DesyncTechnique::SeqOverlap { .. } => "SeqOverlap".to_owned(),
        DesyncTechnique::Chain { .. } => "Chain".to_owned(),
    }
}

/// Human-readable description of why a profile is degraded.
fn degraded_reason_label(reason: &DegradedReason) -> String {
    match reason {
        DegradedReason::TcpDisorderNoInterceptor => {
            "packet interceptor unavailable (WinDivert/NFQueue) — falls back to plain TCP split"
                .to_owned()
        }
        DegradedReason::SeqOverlapNoInjector => {
            "raw packet injector unavailable — falls back to plain TLS record split".to_owned()
        }
        DegradedReason::FakeProbeNoInjector => {
            "raw packet injector unavailable — fake probe skipped, split technique still runs"
                .to_owned()
        }
    }
}

/// Spawn a background task that writes a [`StatsSnapshot`] to `path` every 5 s.
///
/// `capabilities` should be `Some(...)` when the native desync engine is active,
/// providing WinDivert/interceptor status and per-profile degradation info for
/// the GUI.
///
/// Returns a [`tokio::task::JoinHandle`] — dropping it cancels the writer.
pub fn spawn_stats_writer(
    path: PathBuf,
    listen_addr: String,
    native_profiles_count: usize,
    start_time: Instant,
    capabilities: Option<EngineCapabilitySnapshot>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(write_loop(
        path,
        listen_addr,
        native_profiles_count,
        start_time,
        capabilities,
    ))
}

async fn write_loop(
    path: PathBuf,
    listen_addr: String,
    native_profiles_count: usize,
    start_time: Instant,
    capabilities: Option<EngineCapabilitySnapshot>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await; // consume the first immediate tick

    loop {
        interval.tick().await;

        let snapshot = collect_snapshot(
            &listen_addr,
            native_profiles_count,
            &start_time,
            capabilities.clone(),
        );
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
    capabilities: Option<EngineCapabilitySnapshot>,
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
        capabilities,
    }
}
