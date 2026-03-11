use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

use crate::config::EngineConfig;
use crate::pt::socks5_server::telemetry_bus::*;
use crate::pt::socks5_server::*;

pub(super) static NEXT_ROUTE_DECISION_ID: AtomicU64 = AtomicU64::new(1);
pub(super) static ROUTE_DECISION_EVENTS_PENDING: OnceLock<DashMap<u64, RouteDecisionEvent>> =
    OnceLock::new();
pub(super) static ROUTE_OUTCOME_EVENTS: OnceLock<DashMap<u64, RouteOutcomeEvent>> = OnceLock::new();
pub(super) static SHADOW_BANDIT_ARMS: OnceLock<DashMap<String, ShadowBanditArmStats>> =
    OnceLock::new();
#[allow(dead_code)]
pub(super) static SHADOW_CANARY_DECISIONS: OnceLock<DashMap<u64, ShadowCanaryDecision>> =
    OnceLock::new();
#[allow(dead_code)]
pub(super) static SHADOW_CANARY_SWITCH_GUARD: OnceLock<DashMap<String, ShadowCanarySwitchGuard>> =
    OnceLock::new();
#[allow(dead_code)]
pub(super) static SHADOW_CANARY_BUCKET_COOLDOWN_UNTIL: OnceLock<DashMap<String, u64>> =
    OnceLock::new();
#[allow(dead_code)]
pub(super) static SHADOW_CANARY_SLO_STATE: OnceLock<RwLock<ShadowCanarySloState>> = OnceLock::new();
#[allow(dead_code)]
pub(super) static SHADOW_CANARY_ROLLBACK_UNTIL_UNIX: AtomicU64 = AtomicU64::new(0);

const SHADOW_PRIOR_PSEUDO_PULLS: u64 = 10;
#[allow(dead_code)]
const SHADOW_UCB_EXPLORATION_SCALE: f64 = 18.0;
#[allow(dead_code)]
const SHADOW_EXPLORATION_BUDGET_PCT: u64 = 5;
#[allow(dead_code)]
const PHASE2_CANARY_ENABLED: bool = true;
#[allow(dead_code)]
const PHASE2_CANARY_SWITCH_WINDOW_SECS: u64 = 30;
#[allow(dead_code)]
const PHASE2_CANARY_MAX_SWITCHES_PER_WINDOW: u8 = 1;
#[allow(dead_code)]
const PHASE2_CANARY_PROFILE_ROTATION_COOLDOWN_SECS: u64 = 45;
const SHADOW_DECAY_HALFLIFE_SECS: u64 = 1800;
const SHADOW_DECAY_MIN_ELAPSED_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShadowArmPrior {
    pseudo_pulls: u64,
    pseudo_reward_sum: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShadowCanaryDecision {
    pub applied: bool,
    pub route_arm: String,
    pub confidence_milli: i64,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct ShadowCanarySwitchGuard {
    pub window_started_unix: u64,
    pub switches_in_window: u8,
    pub last_arm: String,
}

#[derive(Debug, Clone, Default)]
pub struct ShadowCanarySloState {
    pub window_started_unix: u64,
    pub samples: u64,
    pub failures: u64,
}

impl ShadowArmPrior {
    fn with_mean(mean_reward: i64) -> Self {
        Self {
            pseudo_pulls: SHADOW_PRIOR_PSEUDO_PULLS,
            pseudo_reward_sum: mean_reward.saturating_mul(SHADOW_PRIOR_PSEUDO_PULLS as i64),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteDecisionEvent {
    pub decision_id: u64,
    pub timestamp_unix: u64,
    pub bucket: String,
    pub host: String,
    pub route_arm: String,
    pub profile: Option<u8>,
    pub raced: bool,
    pub winner: bool,
    pub shadow_route_arm: String,
}

impl RouteDecisionEvent {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.decision_id == 0 {
            return Err("decision_id must be non-zero");
        }
        if self.bucket.trim().is_empty() {
            return Err("bucket must not be empty");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteOutcomeEvent {
    pub decision_id: u64,
    pub timestamp_unix: u64,
    pub bucket: String,
    pub host: String,
    pub route_arm: String,
    pub profile: Option<u8>,
    pub raced: bool,
    pub winner: bool,
    pub connect_ok: bool,
    pub tls_ok_proxy: bool,
    pub bytes_u2c: u64,
    pub lifetime_ms: u64,
    pub error_class: String,
    pub shadow_route_arm: String,
    pub shadow_reward: i64,
}

impl RouteOutcomeEvent {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.decision_id == 0 {
            return Err("decision_id must be non-zero");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowBanditArmStats {
    pub pulls: u64,
    pub reward_sum: i64,
    pub last_reward: i64,
    pub last_seen_unix: u64,
    pub ema_reward_milli: i64,
    pub ema_abs_dev_milli: u64,
    pub drift_alert_streak: u32,
}

pub fn next_route_decision_id() -> u64 {
    NEXT_ROUTE_DECISION_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn apply_phase3_ml_override(
    route_key: &str,
    candidates: Vec<RouteCandidate>,
    cfg: &EngineConfig,
) -> (Vec<RouteCandidate>, ShadowCanaryDecision) {
    if candidates.is_empty() {
        return (candidates, ShadowCanaryDecision::default());
    }
    let host = route_destination_host(route_key);

    // Explicit domain_profiles override: skip ML entirely and force the configured arm.
    // Keys are matched as exact host or suffix (e.g. "discord.com" matches "gateway.discord.com").
    if !cfg.routing.domain_profiles.is_empty() {
        for (domain, forced_arm) in &cfg.routing.domain_profiles {
            let domain = domain.trim();
            if host == domain || host.ends_with(&format!(".{domain}")) {
                let pos = candidates
                    .iter()
                    .position(|c: &RouteCandidate| c.route_id() == forced_arm.trim());
                if let Some(position) = pos {
                    if position != 0 {
                        let mut reordered = candidates;
                        let selected = reordered.remove(position);
                        reordered.insert(0, selected);
                        return (
                            reordered,
                            ShadowCanaryDecision {
                                applied: true,
                                route_arm: forced_arm.trim().to_owned(),
                                confidence_milli: 10000,
                                reason: "domain-profile-override",
                            },
                        );
                    }
                    return (
                        candidates,
                        ShadowCanaryDecision {
                            applied: false,
                            route_arm: forced_arm.trim().to_owned(),
                            confidence_milli: 10000,
                            reason: "domain-profile-override-already-first",
                        },
                    );
                }
                break;
            }
        }
    }

    let bucket = shadow_bucket_name(route_key, &host, cfg);
    let selected_arm = shadow_choose_route_arm(&bucket, route_key, &candidates);
    let pos = candidates
        .iter()
        .position(|c: &RouteCandidate| c.route_id() == selected_arm);
    if let Some(position) = pos {
        if position != 0 {
            let mut reordered = candidates;
            let selected = reordered.remove(position);
            reordered.insert(0, selected);
            return (
                reordered,
                ShadowCanaryDecision {
                    applied: true,
                    route_arm: selected_arm,
                    confidence_milli: 10000,
                    reason: "ml-override",
                },
            );
        }
    }
    (
        candidates,
        ShadowCanaryDecision {
            applied: false,
            route_arm: "direct".to_owned(),
            confidence_milli: 0,
            reason: "no-override",
        },
    )
}

pub fn begin_route_decision_event(
    route_key: &str,
    candidates: &[RouteCandidate],
    raced: bool,
    cfg: &EngineConfig,
) -> u64 {
    begin_route_decision_event_with_canary(route_key, candidates, raced, None, cfg)
}

pub fn begin_route_decision_event_with_canary(
    route_key: &str,
    candidates: &[RouteCandidate],
    raced: bool,
    canary: Option<ShadowCanaryDecision>,
    _cfg: &EngineConfig,
) -> u64 {
    let decision_id = next_route_decision_id();
    send_telemetry(TelemetryEvent::MlDecision {
        route_key: route_key.to_owned(),
        candidates: candidates.to_vec(),
        raced,
        canary,
        decision_id,
    });
    decision_id
}

pub fn begin_route_decision_event_sync(
    route_key: &str,
    candidates: &[RouteCandidate],
    raced: bool,
    _canary: Option<ShadowCanaryDecision>,
    decision_id: u64,
    cfg: &EngineConfig,
) {
    let now = now_unix_secs();
    let host = route_destination_host(route_key);
    let bucket = shadow_bucket_name(route_key, &host, cfg);
    let planned = candidates
        .first()
        .map(|c: &RouteCandidate| c.route_id())
        .unwrap_or_else(|| "none".to_owned());
    let shadow_route_arm = shadow_choose_route_arm(&bucket, route_key, candidates);
    let event = RouteDecisionEvent {
        decision_id,
        timestamp_unix: now,
        bucket,
        host,
        route_arm: planned.clone(),
        profile: None,
        raced,
        winner: false,
        shadow_route_arm: shadow_route_arm.clone(),
    };
    if event.validate().is_ok() {
        ROUTE_DECISION_EVENTS_PENDING
            .get_or_init(DashMap::new)
            .insert(decision_id, event);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn complete_route_outcome_event(
    decision_id: u64,
    _rk: &str,
    candidate: Option<&RouteCandidate>,
    connect_ok: bool,
    tls_ok_proxy: bool,
    bytes_u2c: u64,
    lifetime_ms: u64,
    error_class: &str,
    _cfg: &EngineConfig,
) {
    send_telemetry(TelemetryEvent::MlOutcome {
        decision_id,
        candidate: candidate.cloned(),
        connect_ok,
        tls_ok_proxy,
        bytes_u2c,
        lifetime_ms,
        error_class: error_class.to_owned(),
    });
}

#[allow(clippy::too_many_arguments)]
pub fn complete_route_outcome_event_sync(
    decision_id: u64,
    candidate: Option<&RouteCandidate>,
    connect_ok: bool,
    tls_ok_proxy: bool,
    bytes_u2c: u64,
    lifetime_ms: u64,
    error_class: &str,
    _cfg: &EngineConfig,
) {
    let now = now_unix_secs();
    if let Some((_, event)) = ROUTE_DECISION_EVENTS_PENDING
        .get_or_init(DashMap::new)
        .remove(&decision_id)
    {
        let reward = shadow_reward_from_outcome(
            connect_ok,
            tls_ok_proxy,
            bytes_u2c,
            lifetime_ms,
            error_class,
        );
        let outcome = RouteOutcomeEvent {
            decision_id,
            timestamp_unix: now,
            bucket: event.bucket.clone(),
            host: event.host.clone(),
            route_arm: candidate
                .map(|c: &RouteCandidate| c.route_id())
                .unwrap_or(event.route_arm),
            profile: None,
            raced: event.raced,
            winner: connect_ok,
            connect_ok,
            tls_ok_proxy,
            bytes_u2c,
            lifetime_ms,
            error_class: error_class.to_owned(),
            shadow_route_arm: event.shadow_route_arm.clone(),
            shadow_reward: reward,
        };
        if outcome.validate().is_ok() {
            ROUTE_OUTCOME_EVENTS
                .get_or_init(DashMap::new)
                .insert(decision_id, outcome.clone());
            update_shadow_bandit_sync(
                &outcome.bucket,
                &outcome.route_arm,
                outcome.shadow_reward,
                now,
            );
        }
    }
}

pub fn shadow_reward_from_outcome(
    connect_ok: bool,
    tls_ok_proxy: bool,
    _b: u64,
    _l: u64,
    _e: &str,
) -> i64 {
    if connect_ok && tls_ok_proxy {
        60
    } else if connect_ok {
        20
    } else {
        -100
    }
}

pub fn shadow_choose_route_arm(
    bucket: &str,
    route_key: &str,
    candidates: &[RouteCandidate],
) -> String {
    if candidates.is_empty() {
        return "none".to_owned();
    }
    let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
    let mut best_arm = candidates[0].route_id();
    let mut best_score = f64::NEG_INFINITY;
    for c in candidates {
        let (pulls, reward_sum) = shadow_effective_stats(bucket, &c.route_id(), map);
        let score = reward_sum as f64 / pulls.max(1) as f64;
        if score > best_score {
            best_score = score;
            best_arm = c.route_id();
        }
    }
    let _ = route_key;
    best_arm
}

fn route_destination_host(route_key: &str) -> String {
    let dest = crate::pt::socks5_server::route_scoring::route_destination_key(route_key);
    split_host_port_for_connect(dest)
        .map(|(h, _)| h)
        .unwrap_or_else(|| dest.to_owned())
}

fn update_shadow_bandit_sync(bucket: &str, arm: &str, reward: i64, now: u64) {
    let key = format!("{bucket}|{arm}");
    let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
    let mut entry = map.entry(key).or_default();
    entry.pulls += 1;
    entry.reward_sum += reward;
    entry.last_seen_unix = now;
}

fn shadow_effective_stats(
    bucket: &str,
    arm: &str,
    map: &DashMap<String, ShadowBanditArmStats>,
) -> (u64, i64) {
    let prior = shadow_arm_prior(bucket, arm);
    let key = format!("{bucket}|{arm}");
    if let Some(stats) = map.get(&key) {
        // Apply exponential time-decay so stale observations lose weight over time.
        // If an ISP updates its DPI, the bandit adapts faster instead of waiting for
        // enough failures to overcome a large accumulated reward_sum.
        let decay = if stats.last_seen_unix > 0 {
            let elapsed = now_unix_secs().saturating_sub(stats.last_seen_unix);
            if elapsed >= SHADOW_DECAY_MIN_ELAPSED_SECS {
                let factor = 2.0_f64.powf(-(elapsed as f64 / SHADOW_DECAY_HALFLIFE_SECS as f64));
                factor.clamp(0.0, 1.0)
            } else {
                1.0
            }
        } else {
            1.0
        };
        let effective_pulls = (stats.pulls as f64 * decay).round() as u64;
        let effective_reward = (stats.reward_sum as f64 * decay).round() as i64;
        (
            prior.pseudo_pulls + effective_pulls,
            prior.pseudo_reward_sum + effective_reward,
        )
    } else {
        (prior.pseudo_pulls, prior.pseudo_reward_sum)
    }
}

fn shadow_arm_prior(bucket: &str, arm: &str) -> ShadowArmPrior {
    match bucket {
        "youtube" => {
            if arm == "bypass:1" {
                ShadowArmPrior::with_mean(60)
            } else {
                ShadowArmPrior::with_mean(0)
            }
        }
        _ => ShadowArmPrior::with_mean(0),
    }
}

fn shadow_bucket_name(_rk: &str, host: &str, cfg: &EngineConfig) -> String {
    let bucket = crate::pt::socks5_server::route_scoring::host_service_bucket(host, cfg);
    if bucket.contains("youtube") {
        "youtube".to_owned()
    } else {
        "default".to_owned()
    }
}

pub fn prune_ml_state(_now: u64) {}
pub fn note_phase2_profile_rotation(_d: &str, _cfg: &EngineConfig) {}
