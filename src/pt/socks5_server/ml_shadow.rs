use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use crate::config::EngineConfig;
use crate::pt::socks5_server::isp_profiler;
use crate::pt::socks5_server::telemetry_aggregator;
use crate::pt::socks5_server::telemetry_bus::*;
use crate::pt::socks5_server::thompson_sampling;
use crate::pt::socks5_server::*;

pub(super) static NEXT_ROUTE_DECISION_ID: AtomicU64 = AtomicU64::new(1);
pub(super) static ROUTE_DECISION_EVENTS_PENDING: OnceLock<DashMap<u64, RouteDecisionEvent>> =
    OnceLock::new();
pub(super) static ROUTE_OUTCOME_EVENTS: OnceLock<DashMap<u64, RouteOutcomeEvent>> = OnceLock::new();
pub(super) static SHADOW_BANDIT_ARMS: OnceLock<DashMap<String, ShadowBanditArmStats>> =
    OnceLock::new();

const SHADOW_PRIOR_PSEUDO_PULLS: u64 = 10;
const SHADOW_UCB_EXPLORATION_SCALE: f64 = 18.0;
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowBanditArmStats {
    pub pulls: u64,
    pub reward_sum: i64,
    pub last_reward: i64,
    pub last_seen_unix: u64,
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

            // Feed Thompson Sampling posterior with the same reward.
            thompson_sampling::thompson_update(
                &outcome.bucket,
                &outcome.route_arm,
                outcome.shadow_reward,
            );

            // Feed ISP profiler with per-connection metrics.
            if connect_ok {
                isp_profiler::record_isp_success(
                    &outcome.bucket,
                    &outcome.route_arm,
                    lifetime_ms,
                    bytes_u2c,
                );
            } else {
                isp_profiler::record_isp_failure(&outcome.bucket, &outcome.route_arm);
            }

            // Feed telemetry aggregator.
            if connect_ok {
                telemetry_aggregator::record_connection_success(
                    &outcome.bucket,
                    lifetime_ms,
                    bytes_u2c,
                );
            } else {
                telemetry_aggregator::record_connection_failure(&outcome.bucket);
            }
        }
    }
}

/// Compute a reward signal from connection outcome.
///
/// Returns a value in `[-100, 70]`. Positive values reinforce the arm; negative
/// values penalise it. The reward is fed into the UCB bandit via
/// `update_shadow_bandit_sync`.
pub fn shadow_reward_from_outcome(
    connect_ok: bool,
    tls_ok_proxy: bool,
    bytes_u2c: u64,
    lifetime_ms: u64,
    _error_class: &str,
) -> i64 {
    if !connect_ok {
        return -100;
    }
    if !tls_ok_proxy {
        return 20;
    }

    let mut reward: i64 = 60;

    // Fast connection bonus (<200ms).
    if lifetime_ms > 0 && lifetime_ms < 200 {
        reward += 10;
    }

    // Slow connection penalty: -5 per 250ms above 500ms, capped at -20.
    if lifetime_ms > 500 {
        let penalty = ((lifetime_ms.saturating_sub(500)) / 250).min(4) as i64 * 5;
        reward -= penalty;
    }

    // Silent block: connected + TLS ok but got 0 bytes over 5+ seconds.
    if bytes_u2c == 0 && lifetime_ms > 5000 {
        reward = -50;
    }

    reward
}

/// Choose the best route arm using a hybrid UCB1 + Thompson Sampling strategy.
///
/// Primary: UCB1 scores `mean_reward + C * sqrt(ln(total_pulls) / pulls)`.
/// Secondary: Thompson Sampling provides a probabilistic tiebreaker.
/// ISP-specific adjustments modify the final score when per-ISP data is available.
///
/// Arms with no prior observations get infinite exploration bonus and are
/// always tried before exploiting known-good arms.
pub fn shadow_choose_route_arm(
    bucket: &str,
    route_key: &str,
    candidates: &[RouteCandidate],
) -> String {
    if candidates.is_empty() {
        return "none".to_owned();
    }
    let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);

    // Total pulls across all candidates — used for the UCB exploration term.
    let total_pulls: u64 = candidates
        .iter()
        .map(|c| shadow_effective_stats(bucket, &c.route_id(), map).0)
        .sum();

    let ln_total = if total_pulls > 1 {
        (total_pulls as f64).ln()
    } else {
        1.0
    };

    // Get Thompson Sampling's pick as a tiebreaker signal.
    let thompson_pick = thompson_sampling::thompson_choose_route_arm(bucket, candidates);

    let mut best_arm = candidates[0].route_id();
    let mut best_score = f64::NEG_INFINITY;

    for c in candidates {
        let arm_id = c.route_id();
        // Arms with no real observations always get infinite priority (UCB1 guarantee).
        let has_real_data = map.contains_key(&format!("{bucket}|{arm_id}"));
        let mut score = if !has_real_data {
            f64::INFINITY
        } else {
            let (pulls, reward_sum) = shadow_effective_stats(bucket, &arm_id, map);
            let pulls_f = pulls.max(1) as f64;
            let mean_reward = reward_sum as f64 / pulls_f;
            let exploration = SHADOW_UCB_EXPLORATION_SCALE * (ln_total / pulls_f).sqrt();
            mean_reward + exploration
        };

        // Blend in ISP-specific adjustment (range [-50, +50]).
        if score.is_finite() {
            score += isp_profiler::isp_score_adjustment(bucket, &arm_id) as f64;
        }

        // Thompson tiebreaker: small bonus if Thompson agrees with this arm.
        if score.is_finite() && arm_id == thompson_pick {
            score += 5.0;
        }

        if score > best_score {
            best_score = score;
            best_arm = arm_id;
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
        // Apply exponential time-decay so stale observations lose weight.
        // If an ISP updates its DPI, the bandit adapts faster instead of waiting
        // for failures to overcome accumulated reward_sum.
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
    // Services almost always blocked in RU → prior favours bypass/native.
    match bucket {
        "youtube" | "discord" | "instagram" | "facebook" | "twitter" => {
            if arm.starts_with("bypass:") || arm.starts_with("native:") {
                ShadowArmPrior::with_mean(40)
            } else {
                ShadowArmPrior::with_mean(-20)
            }
        }
        "rutracker" => {
            if arm.starts_with("bypass:") || arm.starts_with("native:") {
                ShadowArmPrior::with_mean(60)
            } else {
                ShadowArmPrior::with_mean(-40)
            }
        }
        _ => ShadowArmPrior::with_mean(0),
    }
}

fn shadow_bucket_name(_rk: &str, host: &str, cfg: &EngineConfig) -> String {
    let bucket = crate::pt::socks5_server::route_scoring::host_service_bucket(host, cfg);
    let bucket_lower = bucket.to_ascii_lowercase();

    if bucket_lower.contains("youtube") || bucket_lower.contains("googlevideo") {
        "youtube".to_owned()
    } else if bucket_lower.contains("discord") {
        "discord".to_owned()
    } else if bucket_lower.contains("instagram")
        || bucket_lower.contains("fbcdn")
        || bucket_lower.contains("cdninstagram")
    {
        "instagram".to_owned()
    } else if bucket_lower.contains("facebook")
        || bucket_lower.contains("fb.com")
        || bucket_lower.contains("messenger.com")
    {
        "facebook".to_owned()
    } else if bucket_lower.contains("rutracker") {
        "rutracker".to_owned()
    } else if bucket_lower.contains("twitter")
        || bucket_lower.contains("x.com")
        || bucket_lower.contains("twimg")
    {
        "twitter".to_owned()
    } else if bucket_lower.contains("tiktok") || bucket_lower.contains("tiktokcdn") {
        "tiktok".to_owned()
    } else if bucket_lower.contains("soundcloud") || bucket_lower.contains("sndcdn") {
        "soundcloud".to_owned()
    } else {
        "default".to_owned()
    }
}

/// Remove stale ML state entries to prevent unbounded memory growth.
///
/// Should be called periodically (e.g. every minute) with the current Unix timestamp.
/// Prunes:
/// - Pending decision events older than 5 minutes (orphaned — no outcome was received).
/// - Completed outcome events older than 30 minutes (no longer needed for scoring).
/// - Bandit arms not seen in 7 days (forgotten so the engine re-explores with fresh data).
pub fn prune_ml_state(now: u64) {
    // Orphaned decision events (no outcome received) older than 5 minutes are stale.
    // They accumulate when connections are cancelled or the client disconnects.
    const PENDING_MAX_AGE_SECS: u64 = 300;
    if let Some(pending) = ROUTE_DECISION_EVENTS_PENDING.get() {
        pending.retain(|_, event| now.saturating_sub(event.timestamp_unix) <= PENDING_MAX_AGE_SECS);
    }

    // Completed outcome events older than 30 minutes are no longer needed for scoring.
    const OUTCOME_MAX_AGE_SECS: u64 = 1800;
    if let Some(outcomes) = ROUTE_OUTCOME_EVENTS.get() {
        outcomes
            .retain(|_, event| now.saturating_sub(event.timestamp_unix) <= OUTCOME_MAX_AGE_SECS);
    }

    // Bandit arms not seen in 7 days are forgotten so the engine re-explores with fresh data.
    const ARM_MAX_AGE_SECS: u64 = 7 * 24 * 3600;
    if let Some(arms) = SHADOW_BANDIT_ARMS.get() {
        arms.retain(|_, stats| now.saturating_sub(stats.last_seen_unix) <= ARM_MAX_AGE_SECS);
    }

    // Prune Thompson Sampling state on the same 7-day cadence.
    thompson_sampling::prune_thompson_state(now, ARM_MAX_AGE_SECS);

    // Prune ISP profiling state on 14-day cadence (ISPs change slowly).
    const ISP_MAX_AGE_SECS: u64 = 14 * 24 * 3600;
    isp_profiler::prune_isp_state(now, ISP_MAX_AGE_SECS);

    // Prune telemetry aggregator on 7-day cadence.
    telemetry_aggregator::prune_aggregator(now, ARM_MAX_AGE_SECS);
}

pub fn note_phase2_profile_rotation(_d: &str, _cfg: &EngineConfig) {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod prune_tests {
    use super::*;

    #[test]
    fn prune_removes_stale_arms() {
        let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);

        // Insert a fresh arm and a stale arm.
        let fresh_key = "prune-test-bucket|fresh-arm".to_owned();
        let stale_key = "prune-test-bucket|stale-arm".to_owned();

        let now = now_unix_secs();
        // Fresh arm: last seen 1 hour ago — within 7-day window.
        map.insert(
            fresh_key.clone(),
            ShadowBanditArmStats {
                pulls: 5,
                reward_sum: 100,
                last_reward: 20,
                last_seen_unix: now.saturating_sub(3600),
            },
        );
        // Stale arm: last seen 8 days ago — outside 7-day window.
        map.insert(
            stale_key.clone(),
            ShadowBanditArmStats {
                pulls: 3,
                reward_sum: 60,
                last_reward: 20,
                last_seen_unix: now.saturating_sub(8 * 24 * 3600),
            },
        );

        prune_ml_state(now);

        assert!(
            map.contains_key(&fresh_key),
            "fresh arm should survive pruning"
        );
        assert!(!map.contains_key(&stale_key), "stale arm should be pruned");

        // Cleanup.
        map.remove(&fresh_key);
    }

    #[test]
    fn prune_keeps_all_arms_when_none_stale() {
        let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
        let now = now_unix_secs();

        let key1 = "prune-keep-test|arm-a".to_owned();
        let key2 = "prune-keep-test|arm-b".to_owned();

        map.insert(
            key1.clone(),
            ShadowBanditArmStats {
                pulls: 1,
                reward_sum: 10,
                last_reward: 10,
                last_seen_unix: now,
            },
        );
        map.insert(
            key2.clone(),
            ShadowBanditArmStats {
                pulls: 2,
                reward_sum: 40,
                last_reward: 20,
                last_seen_unix: now.saturating_sub(60),
            },
        );

        prune_ml_state(now);

        assert!(map.contains_key(&key1), "recent arm should survive");
        assert!(map.contains_key(&key2), "recent arm should survive");

        // Cleanup.
        map.remove(&key1);
        map.remove(&key2);
    }
}

#[cfg(test)]
mod reward_tests {
    use super::shadow_reward_from_outcome;

    #[test]
    fn reward_fast_successful() {
        let r = shadow_reward_from_outcome(true, true, 1000, 150, "");
        assert!(r > 60, "fast connection should get bonus: got {r}");
    }

    #[test]
    fn reward_slow_successful() {
        let r = shadow_reward_from_outcome(true, true, 1000, 1500, "");
        assert!(r < 60, "slow connection should get penalty: got {r}");
    }

    #[test]
    fn reward_silent_block() {
        let r = shadow_reward_from_outcome(true, true, 0, 6000, "");
        assert!(r < 0, "silent block should be negative: got {r}");
    }

    #[test]
    fn reward_connection_failed() {
        assert_eq!(
            shadow_reward_from_outcome(false, false, 0, 0, "reset"),
            -100
        );
    }

    #[test]
    fn reward_connect_ok_tls_fail() {
        assert_eq!(shadow_reward_from_outcome(true, false, 0, 300, ""), 20);
    }
}

#[cfg(test)]
mod shadow_bandit_tests {
    use super::*;

    fn init_bandit_arm(bucket: &str, arm: &str, pulls: u64, reward_sum: i64) {
        let key = format!("{bucket}|{arm}");
        let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
        let mut entry = map.entry(key).or_default();
        entry.pulls = pulls;
        entry.reward_sum = reward_sum;
        entry.last_seen_unix = now_unix_secs();
    }

    fn make_native_candidates(count: usize) -> Vec<RouteCandidate> {
        (0..count)
            .map(|i| {
                RouteCandidate::native_with_family("test", i as u8, count as u8, RouteIpFamily::Any)
            })
            .collect()
    }

    #[test]
    fn ucb_prefers_untried_arm_over_known_good() {
        let bucket = "test-ucb-untried";
        // arm native:1 has many successful pulls
        init_bandit_arm(bucket, "native:1", 100, 6000);
        // native:2 and native:3 have 0 pulls — UCB exploration bonus should dominate

        let candidates = make_native_candidates(3);
        let chosen = shadow_choose_route_arm(bucket, "test:443", &candidates);

        // UCB should choose an untried arm, not the known-good native:1
        assert_ne!(chosen, "native:1", "UCB should explore untried arms");

        // Cleanup
        let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
        map.remove(&format!("{bucket}|native:1"));
    }

    #[test]
    fn ucb_converges_to_best_arm_with_equal_pulls() {
        let bucket = "test-ucb-converge";
        init_bandit_arm(bucket, "native:1", 50, 1000); // mean = 20
        init_bandit_arm(bucket, "native:2", 50, 3000); // mean = 60
        init_bandit_arm(bucket, "native:3", 50, 500); //  mean = 10

        let candidates = make_native_candidates(3);
        let chosen = shadow_choose_route_arm(bucket, "test:443", &candidates);

        // With equal pulls, exploration bonus is equal → best mean wins
        assert_eq!(chosen, "native:2");

        // Cleanup
        let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
        for arm in ["native:1", "native:2", "native:3"] {
            map.remove(&format!("{bucket}|{arm}"));
        }
    }
}

// ── Stats snapshot ────────────────────────────────────────────────────────────

/// Point-in-time snapshot of a single ML bandit arm for the stats file.
#[derive(Debug, Clone, Serialize)]
pub struct BucketArmSnapshot {
    /// Composite key: `"<bucket>|<route_arm>"`.
    pub key: String,
    /// Total number of times this arm was selected.
    pub pulls: u64,
    /// Sum of all rewards received (range: pulls × [−100, +70]).
    pub reward_sum: i64,
    /// Mean reward per pull; 0.0 when pulls == 0.
    pub mean_reward: f64,
}

/// Point-in-time snapshot of ML state for the stats writer.
#[derive(Debug, Clone, Serialize)]
pub struct MlStateSnapshot {
    /// Number of pending (unresolved) route decisions.
    pub pending_decisions: usize,
    /// Number of completed outcome events kept in memory.
    pub outcome_events: usize,
    /// Total number of active bandit arms across all buckets.
    pub bandit_arms: usize,
    /// Top-10 arms by pull count (most-used routes first).
    pub top_arms: Vec<BucketArmSnapshot>,
}

/// Collect a point-in-time snapshot of ML state.
///
/// Reads the three process-global DashMaps under shared locks; does not block
/// the writer.
pub fn ml_state_snapshot() -> MlStateSnapshot {
    let pending_decisions = ROUTE_DECISION_EVENTS_PENDING
        .get()
        .map(|m| m.len())
        .unwrap_or(0);
    let outcome_events = ROUTE_OUTCOME_EVENTS.get().map(|m| m.len()).unwrap_or(0);

    let (bandit_arms, top_arms) = if let Some(arms) = SHADOW_BANDIT_ARMS.get() {
        let count = arms.len();
        let mut entries: Vec<BucketArmSnapshot> = arms
            .iter()
            .map(|e| {
                let s = e.value();
                let mean = if s.pulls > 0 {
                    s.reward_sum as f64 / s.pulls as f64
                } else {
                    0.0
                };
                BucketArmSnapshot {
                    key: e.key().clone(),
                    pulls: s.pulls,
                    reward_sum: s.reward_sum,
                    mean_reward: mean,
                }
            })
            .collect();
        entries.sort_unstable_by(|a, b| b.pulls.cmp(&a.pulls));
        entries.truncate(10);
        (count, entries)
    } else {
        (0, Vec::new())
    };

    MlStateSnapshot {
        pending_decisions,
        outcome_events,
        bandit_arms,
        top_arms,
    }
}
