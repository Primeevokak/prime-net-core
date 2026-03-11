use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::info;

use crate::config::EngineConfig;
use crate::pt::socks5_server::*;

pub enum TelemetryEvent {
    RouteSuccess {
        route_key: String,
        candidate: RouteCandidate,
    },
    RouteFailure {
        route_key: String,
        candidate: RouteCandidate,
        reason: &'static str,
    },
    GlobalBypassSuccess {
        candidate: RouteCandidate,
    },
    GlobalBypassFailure {
        candidate: RouteCandidate,
        reason: &'static str,
    },
    DestinationSuccess {
        destination: String,
        stage: u8,
    },
    DestinationFailure {
        destination: String,
        signal: BlockingSignal,
        stage: u8,
    },
    MlDecision {
        route_key: String,
        candidates: Vec<RouteCandidate>,
        raced: bool,
        canary: Option<ml_shadow::ShadowCanaryDecision>,
        decision_id: u64,
    },
    MlOutcome {
        decision_id: u64,
        candidate: Option<RouteCandidate>,
        connect_ok: bool,
        tls_ok_proxy: bool,
        bytes_u2c: u64,
        lifetime_ms: u64,
        error_class: String,
    },
}

static TELEMETRY_TX: OnceLock<mpsc::UnboundedSender<TelemetryEvent>> = OnceLock::new();

pub fn init_telemetry_bus(cfg: Arc<EngineConfig>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<TelemetryEvent>();
    let _ = TELEMETRY_TX.set(tx);

    tokio::spawn(async move {
        info!(target: "socks5.telemetry", "Stats Actor started");
        let mut last_prune = Instant::now();

        while let Some(event) = rx.recv().await {
            match event {
                TelemetryEvent::RouteSuccess {
                    route_key,
                    candidate,
                } => {
                    route_scoring::record_route_success_sync(&route_key, &candidate, &cfg);
                }
                TelemetryEvent::RouteFailure {
                    route_key,
                    candidate,
                    reason,
                } => {
                    route_scoring::record_route_failure_sync(&route_key, &candidate, reason, &cfg);
                }
                TelemetryEvent::GlobalBypassSuccess { candidate } => {
                    route_scoring::record_global_bypass_profile_success_sync(&candidate, &cfg);
                }
                TelemetryEvent::GlobalBypassFailure { candidate, reason } => {
                    route_scoring::record_global_bypass_profile_failure_sync(
                        &candidate,
                        reason,
                        now_unix_secs(),
                        &cfg,
                    );
                }
                TelemetryEvent::DestinationSuccess { destination, stage } => {
                    classifier_and_persistence::record_destination_success_sync(
                        &destination,
                        stage,
                        &cfg,
                    );
                }
                TelemetryEvent::DestinationFailure {
                    destination,
                    signal,
                    stage,
                } => {
                    classifier_and_persistence::record_destination_failure_sync(
                        &destination,
                        signal,
                        stage,
                        &cfg,
                    );
                }
                TelemetryEvent::MlDecision {
                    route_key,
                    candidates,
                    raced,
                    canary,
                    decision_id,
                } => {
                    ml_shadow::begin_route_decision_event_sync(
                        &route_key,
                        &candidates,
                        raced,
                        canary,
                        decision_id,
                        &cfg,
                    );
                }
                TelemetryEvent::MlOutcome {
                    decision_id,
                    candidate,
                    connect_ok,
                    tls_ok_proxy,
                    bytes_u2c,
                    lifetime_ms,
                    error_class,
                } => {
                    ml_shadow::complete_route_outcome_event_sync(
                        decision_id,
                        candidate.as_ref(),
                        connect_ok,
                        tls_ok_proxy,
                        bytes_u2c,
                        lifetime_ms,
                        &error_class,
                        &cfg,
                    );
                }
            }

            if last_prune.elapsed() > Duration::from_secs(30) {
                classifier_and_persistence::maybe_prune_runtime_classifier_state(
                    now_unix_secs(),
                    cfg.clone(),
                );
                classifier_and_persistence::maybe_flush_classifier_store(false, cfg.clone());
                last_prune = Instant::now();
            }
        }
    });
}

pub fn send_telemetry(event: TelemetryEvent) {
    if let Some(tx) = TELEMETRY_TX.get() {
        let _ = tx.send(event);
    }
}
