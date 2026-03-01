use super::*;
use crate::config::EngineConfig;

pub(super) static NEXT_ROUTE_DECISION_ID: AtomicU64 = AtomicU64::new(1);
pub(super) static ROUTE_DECISION_EVENTS_PENDING: OnceLock<DashMap<u64, RouteDecisionEvent>> =
    OnceLock::new();
pub(super) static ROUTE_OUTCOME_EVENTS: OnceLock<DashMap<u64, RouteOutcomeEvent>> = OnceLock::new();
pub(super) static SHADOW_BANDIT_ARMS: OnceLock<DashMap<String, ShadowBanditArmStats>> =
    OnceLock::new();
pub(super) static SHADOW_CANARY_DECISIONS: OnceLock<DashMap<u64, ShadowCanaryDecision>> =
    OnceLock::new();
pub(super) static SHADOW_CANARY_SWITCH_GUARD: OnceLock<DashMap<String, ShadowCanarySwitchGuard>> =
    OnceLock::new();
pub(super) static SHADOW_CANARY_BUCKET_COOLDOWN_UNTIL: OnceLock<DashMap<String, u64>> =
    OnceLock::new();
pub(super) static SHADOW_CANARY_SLO_STATE: OnceLock<RwLock<ShadowCanarySloState>> = OnceLock::new();
pub(super) static SHADOW_CANARY_ROLLBACK_UNTIL_UNIX: AtomicU64 = AtomicU64::new(0);

const SHADOW_PRIOR_PSEUDO_PULLS: u64 = 10;
const SHADOW_UCB_EXPLORATION_SCALE: f64 = 18.0;
const SHADOW_EXPLORATION_BUDGET_PCT: u64 = 5;
const PHASE2_CANARY_ENABLED: bool = true;
const PHASE2_CANARY_MIN_PULLS: u64 = 24;
const PHASE2_CANARY_CONFIDENCE_MILLI: i64 = 12_000;
const PHASE2_CANARY_SWITCH_WINDOW_SECS: u64 = 30;
const PHASE2_CANARY_MAX_SWITCHES_PER_WINDOW: u8 = 1;
const PHASE2_CANARY_PROFILE_ROTATION_COOLDOWN_SECS: u64 = 45;
const PHASE2_CANARY_SLO_WINDOW_SECS: u64 = 90;
const PHASE2_CANARY_SLO_MIN_SAMPLES: u64 = 12;
const PHASE2_CANARY_SLO_MAX_FAILURE_PPM: u64 = 420_000;
const PHASE2_CANARY_ROLLBACK_SECS: u64 = 180;
const PHASE3_ML_CONTROL_ENABLED: bool = true;
const PHASE3_ML_MIN_PULLS: u64 = 24;
const PHASE3_ML_CONFIDENCE_MILLI: i64 = 8_000;
const SHADOW_DECAY_HALFLIFE_SECS: u64 = 30 * 60;
const SHADOW_DECAY_MIN_ELAPSED_SECS: u64 = 10;
const SHADOW_DRIFT_EMA_ALPHA_DEN: i64 = 16;
const SHADOW_DRIFT_MIN_DEV_MILLI: u64 = 8_000;
const SHADOW_DRIFT_STREAK_TRIGGER: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShadowArmPrior {
    pseudo_pulls: u64,
    pseudo_reward_sum: i64,
}

#[derive(Debug, Clone, Default)]
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
        if self.host.trim().is_empty() {
            return Err("host must not be empty");
        }
        if self.route_arm.trim().is_empty() {
            return Err("route_arm must not be empty");
        }
        if self.shadow_route_arm.trim().is_empty() {
            return Err("shadow_route_arm must not be empty");
        }
        if matches!(self.profile, Some(0)) {
            return Err("profile index is 1-based");
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
        if self.bucket.trim().is_empty() {
            return Err("bucket must not be empty");
        }
        if self.host.trim().is_empty() {
            return Err("host must not be empty");
        }
        if self.route_arm.trim().is_empty() {
            return Err("route_arm must not be empty");
        }
        if self.error_class.trim().is_empty() {
            return Err("error_class must not be empty");
        }
        if self.shadow_route_arm.trim().is_empty() {
            return Err("shadow_route_arm must not be empty");
        }
        if matches!(self.profile, Some(0)) {
            return Err("profile index is 1-based");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ShadowBanditArmStats {
    pub pulls: u64,
    pub reward_sum: i64,
    pub last_reward: i64,
    pub last_seen_unix: u64,
    pub ema_reward_milli: i64,
    pub ema_abs_dev_milli: u64,
    pub drift_alert_streak: u32,
}

pub(super) fn next_route_decision_id() -> u64 {
    NEXT_ROUTE_DECISION_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn apply_phase3_ml_override(
    route_key: &str,
    candidates: Vec<RouteCandidate>,
    cfg: &EngineConfig,
) -> (Vec<RouteCandidate>, ShadowCanaryDecision) {
    if !PHASE3_ML_CONTROL_ENABLED {
        return apply_phase2_canary_override(route_key, candidates, cfg);
    }
    if candidates.is_empty() {
        return (
            candidates,
            ShadowCanaryDecision {
                applied: false,
                route_arm: "none".to_owned(),
                confidence_milli: 0,
                reason: "empty-candidates",
            },
        );
    }

    let host = route_destination_host(route_key);
    let bucket = shadow_bucket_name(route_key, &host, cfg);
    let mut decision = ShadowCanaryDecision {
        applied: false,
        route_arm: candidates[0].route_id(),
        confidence_milli: 0,
        reason: "phase3-disabled",
    };

    if !shadow_phase3_bucket_allowed(&bucket) {
        decision.reason = "bucket-not-allowed";
        return (candidates, decision);
    }

    let now = now_unix_secs();
    let rollback_until = SHADOW_CANARY_ROLLBACK_UNTIL_UNIX.load(Ordering::Relaxed);
    if rollback_until > now {
        decision.reason = "rollback-active";
        return (candidates, decision);
    }

    if shadow_bucket_in_cooldown(&bucket, now) {
        decision.reason = "bucket-cooldown";
        return (candidates, decision);
    }

    let selected_arm = shadow_choose_route_arm(&bucket, route_key, &candidates);
    let confidence = shadow_route_arm_confidence_milli(&bucket, &selected_arm, &candidates);
    decision.route_arm = selected_arm.clone();
    decision.confidence_milli = confidence;

    if confidence < PHASE3_ML_CONFIDENCE_MILLI {
        decision.reason = "low-confidence";
        return (candidates, decision);
    }

    if !shadow_arm_has_min_pulls(&bucket, &selected_arm, PHASE3_ML_MIN_PULLS) {
        decision.reason = "insufficient-history";
        return (candidates, decision);
    }

    if !shadow_switch_guard_allows(route_key, &selected_arm, now) {
        decision.reason = "switch-guard";
        return (candidates, decision);
    }

    if let Some(reason) =
        shadow_phase3_safety_override_reason(route_key, &bucket, &selected_arm, &candidates, now, cfg)
    {
        decision.reason = reason;
        return (candidates, decision);
    }

    let position = candidates
        .iter()
        .position(|candidate| candidate.route_id() == selected_arm);
    let Some(position) = position else {
        decision.reason = "arm-not-in-candidates";
        return (candidates, decision);
    };

    if position == 0 {
        decision.applied = true;
        decision.reason = "already-primary";
        return (candidates, decision);
    }

    let mut reordered = candidates;
    let selected = reordered.remove(position);
    reordered.insert(0, selected);
    decision.applied = true;
    decision.reason = "phase3-ml-override";
    (reordered, decision)
}

pub fn apply_phase2_canary_override(
    route_key: &str,
    candidates: Vec<RouteCandidate>,
    cfg: &EngineConfig,
) -> (Vec<RouteCandidate>, ShadowCanaryDecision) {
    if candidates.is_empty() {
        return (
            candidates,
            ShadowCanaryDecision {
                applied: false,
                route_arm: "none".to_owned(),
                confidence_milli: 0,
                reason: "empty-candidates",
            },
        );
    }

    let host = route_destination_host(route_key);
    let bucket = shadow_bucket_name(route_key, &host, cfg);
    let mut decision = ShadowCanaryDecision {
        applied: false,
        route_arm: candidates[0].route_id(),
        confidence_milli: 0,
        reason: "phase2-disabled",
    };
    if !PHASE2_CANARY_ENABLED {
        return (candidates, decision);
    }
    
    let is_censored = cfg.routing.censored_groups.keys().any(|g| bucket == *g || bucket == format!("meta-group:{}", g));
    if !is_censored {
        decision.reason = "bucket-not-allowed";
        return (candidates, decision);
    }

    let now = now_unix_secs();
    let rollback_until = SHADOW_CANARY_ROLLBACK_UNTIL_UNIX.load(Ordering::Relaxed);
    if rollback_until > now {
        decision.reason = "rollback-active";
        return (candidates, decision);
    }

    if shadow_bucket_in_cooldown(&bucket, now) {
        decision.reason = "bucket-cooldown";
        return (candidates, decision);
    }

    let selected_arm = shadow_choose_route_arm(&bucket, route_key, &candidates);
    let confidence = shadow_route_arm_confidence_milli(&bucket, &selected_arm, &candidates);
    decision.route_arm = selected_arm.clone();
    decision.confidence_milli = confidence;

    if confidence < PHASE2_CANARY_CONFIDENCE_MILLI {
        decision.reason = "low-confidence";
        return (candidates, decision);
    }

    if !shadow_arm_has_min_pulls(&bucket, &selected_arm, PHASE2_CANARY_MIN_PULLS) {
        decision.reason = "insufficient-history";
        return (candidates, decision);
    }

    if !shadow_switch_guard_allows(route_key, &selected_arm, now) {
        decision.reason = "switch-guard";
        return (candidates, decision);
    }

    let position = candidates
        .iter()
        .position(|candidate| candidate.route_id() == selected_arm);
    let Some(position) = position else {
        decision.reason = "arm-not-in-candidates";
        return (candidates, decision);
    };

    if position == 0 {
        decision.applied = true;
        decision.reason = "already-primary";
        return (candidates, decision);
    }

    let mut reordered = candidates;
    let selected = reordered.remove(position);
    reordered.insert(0, selected);
    decision.applied = true;
    decision.reason = "canary-override";
    (reordered, decision)
}

pub fn begin_route_decision_event(
    route_key: &str,
    candidates: &[RouteCandidate],
    _explore: bool,
    cfg: &EngineConfig,
) -> u64 {
    begin_route_decision_event_with_canary(route_key, candidates, false, None, cfg)
}

pub fn begin_route_decision_event_with_canary(
    route_key: &str,
    candidates: &[RouteCandidate],
    raced: bool,
    canary: Option<ShadowCanaryDecision>,
    cfg: &EngineConfig,
) -> u64 {
    let decision_id = next_route_decision_id();
    let now = now_unix_secs();
    let host = route_destination_host(route_key);
    let bucket = shadow_bucket_name(route_key, &host, cfg);
    let planned = candidates
        .first()
        .map(|candidate| candidate.route_id())
        .unwrap_or_else(|| "none".to_owned());
    let shadow_route_arm = shadow_choose_route_arm(&bucket, route_key, candidates);
    let shadow_explore = shadow_exploration_enabled(&bucket, decision_id, route_key);
    let event = RouteDecisionEvent {
        decision_id,
        timestamp_unix: now,
        bucket,
        host,
        route_arm: planned.clone(),
        profile: profile_from_route_arm(&planned),
        raced,
        winner: false,
        shadow_route_arm: shadow_route_arm.clone(),
    };

    if let Err(err) = event.validate() {
        warn!(
            target: "socks5.ml",
            decision_id,
            validation_error = err,
            "route decision event validation failed"
        );
        return decision_id;
    }

    let pending = ROUTE_DECISION_EVENTS_PENDING.get_or_init(DashMap::new);
    pending.insert(decision_id, event.clone());
    if let Some(canary) = canary {
        SHADOW_CANARY_DECISIONS
            .get_or_init(DashMap::new)
            .insert(decision_id, canary.clone());
        info!(
            target: "socks5.ml",
            event = "canary-decision",
            decision_id,
            route_key = %route_key,
            canary_applied = canary.applied,
            canary_arm = %canary.route_arm,
            canary_confidence_milli = canary.confidence_milli,
            canary_reason = canary.reason,
            "phase2 canary decision"
        );
    }
    info!(
        target: "socks5.ml",
        event = "decision",
        decision_id = event.decision_id,
        bucket = %event.bucket,
        host = %event.host,
        route_arm = %event.route_arm,
        profile = ?event.profile,
        raced = event.raced,
        winner = event.winner,
        shadow_route_arm = %event.shadow_route_arm,
        shadow_explore,
        "route decision event"
    );
    decision_id
}

pub fn complete_route_outcome_event(
    decision_id: u64,
    route_key: &str,
    candidate: Option<&RouteCandidate>,
    connect_ok: bool,
    tls_ok_proxy: bool,
    bytes_u2c: u64,
    lifetime_ms: u64,
    error_class: &str,
    cfg: &EngineConfig,
) {
    let now = now_unix_secs();
    let pending = ROUTE_DECISION_EVENTS_PENDING.get_or_init(DashMap::new);
    let decision = pending.remove(&decision_id).map(|(_, event)| event);

    let fallback_bucket = "default".to_owned();
    let fallback_host = "unknown".to_owned();

    let host = route_destination_host(route_key);
    let bucket = shadow_bucket_name(route_key, &host, cfg);
    let route_arm = candidate
        .map(|route| route.route_id())
        .or_else(|| decision.as_ref().map(|event| event.route_arm.clone()))
        .unwrap_or_else(|| "none".to_owned());
    let profile = candidate
        .and_then(profile_from_candidate)
        .or_else(|| decision.as_ref().and_then(|event| event.profile))
        .or_else(|| profile_from_route_arm(&route_arm));
    let shadow_route_arm = decision
        .as_ref()
        .map(|event| event.shadow_route_arm.clone())
        .unwrap_or_else(|| route_arm.clone());
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
        bucket: decision
            .as_ref()
            .map(|event| event.bucket.clone())
            .unwrap_or(fallback_bucket),
        host: decision
            .as_ref()
            .map(|event| event.host.clone())
            .unwrap_or(fallback_host),
        route_arm,
        profile,
        raced: decision.as_ref().map(|event| event.raced).unwrap_or(false),
        winner: connect_ok && candidate.is_some(),
        connect_ok,
        tls_ok_proxy,
        bytes_u2c,
        lifetime_ms,
        error_class: error_class.to_owned(),
        shadow_route_arm: shadow_route_arm.clone(),
        shadow_reward: reward,
    };
    if let Err(err) = outcome.validate() {
        warn!(
            target: "socks5.ml",
            decision_id,
            validation_error = err,
            "route outcome event validation failed"
        );
        return;
    }

    let outcomes = ROUTE_OUTCOME_EVENTS.get_or_init(DashMap::new);
    outcomes.insert(decision_id, outcome.clone());
    let canary = SHADOW_CANARY_DECISIONS
        .get_or_init(DashMap::new)
        .remove(&decision_id)
        .map(|(_, value)| value)
        .unwrap_or_default();
    let posterior_arm = outcome.route_arm.clone();
    update_shadow_bandit(&outcome.bucket, &posterior_arm, outcome.shadow_reward, now);
    let shadow_match = outcome.shadow_route_arm == outcome.route_arm;
    if canary.applied {
        shadow_update_canary_slo(
            &outcome.bucket,
            outcome.connect_ok,
            outcome.tls_ok_proxy,
            &outcome.error_class,
            now,
        );
    }

    info!(
        target: "socks5.ml",
        event = "outcome",
        decision_id = outcome.decision_id,
        bucket = %outcome.bucket,
        host = %outcome.host,
        route_arm = %outcome.route_arm,
        profile = ?outcome.profile,
        raced = outcome.raced,
        winner = outcome.winner,
        connect_ok = outcome.connect_ok,
        tls_ok_proxy = outcome.tls_ok_proxy,
        bytes_u2c = outcome.bytes_u2c,
        lifetime_ms = outcome.lifetime_ms,
        error_class = %outcome.error_class,
        shadow_route_arm = %outcome.shadow_route_arm,
        posterior_arm = %posterior_arm,
        shadow_match,
        canary_applied = canary.applied,
        canary_arm = %canary.route_arm,
        canary_confidence_milli = canary.confidence_milli,
        canary_reason = canary.reason,
        shadow_reward = outcome.shadow_reward,
        "route outcome event"
    );
}

pub(super) fn shadow_reward_from_outcome(
    connect_ok: bool,
    tls_ok_proxy: bool,
    bytes_u2c: u64,
    lifetime_ms: u64,
    error_class: &str,
) -> i64 {
    let mut reward = if connect_ok { 40 } else { -90 };
    if tls_ok_proxy {
        reward += 20;
    } else if connect_ok {
        reward -= 10;
    }

    // A plain TCP connect without any usable upstream bytes is not a real success.
    // Treat this as negative evidence so direct "phantom connects" don't dominate.
    if connect_ok && !tls_ok_proxy && bytes_u2c <= 7 {
        reward -= 45;
    }

    reward += (bytes_u2c.min(256 * 1024) / 16_384) as i64;

    if lifetime_ms > 0 && lifetime_ms < 250 && !tls_ok_proxy {
        reward -= 10;
    }

    if error_class.contains("client-disconnect") && !tls_ok_proxy && bytes_u2c <= 7 {
        reward -= 20;
    }

    if error_class.contains("timeout") {
        reward -= 20;
    } else if error_class.contains("connect-failed") {
        reward -= 30;
    } else if error_class.contains("suspicious-zero-reply")
        || error_class.contains("zero-reply-soft")
    {
        reward -= 25;
    }
    reward
}

pub(super) fn shadow_choose_route_arm(
    bucket: &str,
    route_key: &str,
    candidates: &[RouteCandidate],
) -> String {
    if candidates.is_empty() {
        return "none".to_owned();
    }

    let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
    let mut total_pulls = 0u64;
    let mut by_arm = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let arm = candidate.route_id();
        let (pulls, reward_sum) = shadow_effective_stats(bucket, &arm, &map);
        total_pulls = total_pulls.saturating_add(pulls.max(1));
        by_arm.push((arm, pulls.max(1), reward_sum));
    }

    let total_pulls_ln = (total_pulls as f64 + 1.0).ln();
    let mut best_arm: Option<String> = None;
    let mut best_score = f64::NEG_INFINITY;
    for (arm, pulls, reward_sum) in by_arm {
        let mean = reward_sum as f64 / pulls as f64;
        let bonus = (total_pulls_ln / pulls as f64).sqrt() * SHADOW_UCB_EXPLORATION_SCALE;
        let score = mean + bonus;
        let replace = if score > best_score {
            true
        } else if (score - best_score).abs() < f64::EPSILON {
            match best_arm.as_ref() {
                Some(current_best) => shadow_tie_break(route_key, &arm, current_best),
                None => true,
            }
        } else {
            false
        };
        if replace {
            best_score = score;
            best_arm = Some(arm);
        }
    }

    best_arm.unwrap_or_else(|| candidates[0].route_id())
}

fn shadow_route_arm_confidence_milli(
    bucket: &str,
    selected_arm: &str,
    candidates: &[RouteCandidate],
) -> i64 {
    if candidates.is_empty() {
        return 0;
    }
    let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
    let mut scores: Vec<(String, f64)> = candidates
        .iter()
        .map(|candidate| {
            let arm = candidate.route_id();
            let (pulls, reward_sum) = shadow_effective_stats(bucket, &arm, map);
            (arm, reward_sum as f64 / pulls.max(1) as f64)
        })
        .collect();
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let best = scores
        .iter()
        .find(|(arm, _)| arm == selected_arm)
        .map(|(_, mean)| *mean)
        .unwrap_or(0.0);
    let second = scores
        .iter()
        .filter(|(arm, _)| arm != selected_arm)
        .map(|(_, mean)| *mean)
        .next()
        .unwrap_or(best);
    ((best - second) * 1000.0) as i64
}

fn shadow_arm_has_min_pulls(bucket: &str, arm: &str, min_pulls: u64) -> bool {
    let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
    let key = format!("{bucket}|{arm}");
    map.get(&key)
        .map(|stats| {
            let (pulls, _) = shadow_decayed_stats_view(&stats, now_unix_secs());
            pulls >= min_pulls
        })
        .unwrap_or(false)
}

fn shadow_phase3_bucket_allowed(bucket: &str) -> bool {
    !matches!(bucket, "ads-noise")
}

fn shadow_phase3_safety_override_reason(
    route_key: &str,
    bucket: &str,
    selected_arm: &str,
    candidates: &[RouteCandidate],
    now: u64,
    cfg: &EngineConfig,
) -> Option<&'static str> {
    if !shadow_phase3_bucket_allowed(bucket) && selected_arm != "direct" {
        return Some("a-ads-noise-override");
    }
    if route_is_temporarily_weak(route_key, selected_arm, now) {
        return Some("a-weak-route-override");
    }

    let selected = candidates
        .iter()
        .find(|candidate| candidate.route_id() == selected_arm);
    if let Some(candidate) = selected {
        if candidate.kind == RouteKind::Bypass
            && global_bypass_profile_score(candidate, now, cfg) <= GLOBAL_BYPASS_HARD_WEAK_SCORE
        {
            return Some("a-global-weak-override");
        }
    }

    if shadow_arm_drift_detected(bucket, selected_arm) {
        return Some("a-drift-override");
    }

    None
}

fn shadow_bucket_in_cooldown(bucket: &str, now: u64) -> bool {
    SHADOW_CANARY_BUCKET_COOLDOWN_UNTIL
        .get_or_init(DashMap::new)
        .get(bucket)
        .map(|until| *until > now)
        .unwrap_or(false)
}

fn shadow_switch_guard_allows(route_key: &str, selected_arm: &str, now: u64) -> bool {
    let map = SHADOW_CANARY_SWITCH_GUARD.get_or_init(DashMap::new);
    let mut entry = map.entry(route_key.to_owned()).or_default();
    if entry.window_started_unix == 0 {
        entry.window_started_unix = now;
        entry.last_arm = selected_arm.to_owned();
        entry.switches_in_window = 0;
        return true;
    }
    if now.saturating_sub(entry.window_started_unix) > PHASE2_CANARY_SWITCH_WINDOW_SECS {
        entry.window_started_unix = now;
        entry.last_arm = selected_arm.to_owned();
        entry.switches_in_window = 0;
        return true;
    }
    if entry.last_arm == selected_arm {
        return true;
    }
    if entry.switches_in_window >= PHASE2_CANARY_MAX_SWITCHES_PER_WINDOW {
        return false;
    }
    entry.switches_in_window = entry.switches_in_window.saturating_add(1);
    entry.last_arm = selected_arm.to_owned();
    true
}

fn shadow_update_canary_slo(
    bucket: &str,
    connect_ok: bool,
    tls_ok_proxy: bool,
    error_class: &str,
    now: u64,
) {
    if !matches!(bucket, "youtube" | "discord") {
        return;
    }
    let state_lock =
        SHADOW_CANARY_SLO_STATE.get_or_init(|| RwLock::new(ShadowCanarySloState::default()));
    let Ok(mut state) = state_lock.write() else {
        return;
    };
    if state.window_started_unix == 0
        || now.saturating_sub(state.window_started_unix) > PHASE2_CANARY_SLO_WINDOW_SECS
    {
        state.window_started_unix = now;
        state.samples = 0;
        state.failures = 0;
    }
    state.samples = state.samples.saturating_add(1);
    let failed = !connect_ok
        || !tls_ok_proxy
        || error_class.contains("timeout")
        || error_class.contains("connect-failed")
        || error_class.contains("zero-reply")
        || error_class.contains("reset")
        || error_class.contains("broken-pipe");
    if failed {
        state.failures = state.failures.saturating_add(1);
    }
    if state.samples < PHASE2_CANARY_SLO_MIN_SAMPLES {
        return;
    }
    let failure_ppm = state.failures.saturating_mul(1_000_000) / state.samples.max(1);
    if failure_ppm > PHASE2_CANARY_SLO_MAX_FAILURE_PPM {
        let rollback_until = now.saturating_add(PHASE2_CANARY_ROLLBACK_SECS);
        SHADOW_CANARY_ROLLBACK_UNTIL_UNIX.store(rollback_until, Ordering::Relaxed);
        warn!(
            target: "socks5.ml",
            bucket,
            samples = state.samples,
            failures = state.failures,
            failure_ppm,
            rollback_until,
            "phase2 canary rollback activated"
        );
        state.window_started_unix = now;
        state.samples = 0;
        state.failures = 0;
    }
}

pub(super) fn note_phase2_profile_rotation(destination: &str, cfg: &EngineConfig) {
    let host = split_host_port_for_connect(crate::pt::socks5_server::route_connection::route_destination_key(destination))
        .map(|(host, _)| host)
        .unwrap_or_else(|| crate::pt::socks5_server::route_connection::route_destination_key(destination).to_owned());
    let bucket = shadow_bucket_name(destination, &host, cfg);
    
    let key = bypass_profile_key(destination, cfg);
    let service_key = bypass_profile_legacy_service_key(destination, cfg);
    let meta_key = bypass_profile_meta_service_key(destination, cfg);
    
    let mut keys = vec![key, service_key];
    if let Some(m) = meta_key {
        keys.push(m);
    }
    
    let map = SHADOW_CANARY_SWITCH_GUARD.get_or_init(DashMap::new);
    let now = now_unix_secs();
    for k in keys {
        let mut entry = map.entry(k).or_insert(ShadowCanarySwitchGuard {
            window_started_unix: now,
            switches_in_window: 0,
            last_arm: String::new(),
        });
        if now.saturating_sub(entry.window_started_unix) > 3600 {
            entry.window_started_unix = now;
            entry.switches_in_window = 0;
        }
        entry.switches_in_window = entry.switches_in_window.saturating_add(1);
    }

    if !matches!(bucket.as_str(), "youtube" | "discord") {
        return;
    }
    let until = now.saturating_add(PHASE2_CANARY_PROFILE_ROTATION_COOLDOWN_SECS);
    SHADOW_CANARY_BUCKET_COOLDOWN_UNTIL
        .get_or_init(DashMap::new)
        .insert(bucket.clone(), until);
    info!(
        target: "socks5.ml",
        bucket = %bucket,
        cooldown_until = until,
        "phase2 canary bucket cooldown armed after profile rotation"
    );
}

pub fn prune_ml_state(now: u64) {
    if let Some(map) = ROUTE_OUTCOME_EVENTS.get() {
        if map.len() > 1000 {
            let mut keys: Vec<u64> = map.iter().map(|entry| *entry.key()).collect();
            keys.sort_unstable();
            let to_remove = keys.len().saturating_sub(1000);
            for key in keys.iter().take(to_remove) {
                map.remove(key);
            }
        }
    }
    if let Some(map) = SHADOW_BANDIT_ARMS.get() {
        let mut stale_keys = Vec::new();
        for entry in map.iter() {
            if now.saturating_sub(entry.value().last_seen_unix) > 86400 {
                stale_keys.push(entry.key().clone());
            }
        }
        for key in stale_keys { map.remove(&key); }
    }
    if let Some(map) = ROUTE_DECISION_EVENTS_PENDING.get() {
        let mut stale_keys = Vec::new();
        for entry in map.iter() {
            if now.saturating_sub(entry.value().timestamp_unix) > 600 {
                stale_keys.push(*entry.key());
            }
        }
        for key in stale_keys { map.remove(&key); }
    }
}

fn update_shadow_bandit(bucket: &str, arm: &str, reward: i64, now: u64) {
    let key = format!("{bucket}|{arm}");
    let map = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
    let mut entry = map.entry(key).or_default();
    apply_shadow_decay(&mut entry, now);

    entry.pulls = entry.pulls.saturating_add(1);
    let reward = reward.clamp(-200, 200);
    entry.reward_sum = entry.reward_sum.saturating_add(reward);
    entry.last_reward = reward;
    update_shadow_drift_state(&mut entry, reward);
    entry.last_seen_unix = now;
}

fn apply_shadow_decay(entry: &mut ShadowBanditArmStats, now: u64) {
    let (decayed_pulls, decayed_reward_sum) = shadow_decayed_stats_view(entry, now);
    if decayed_pulls == entry.pulls && decayed_reward_sum == entry.reward_sum {
        return;
    }
    let elapsed = now.saturating_sub(entry.last_seen_unix);
    let decay_factor = 0.5f64.powf(elapsed as f64 / SHADOW_DECAY_HALFLIFE_SECS as f64);
    entry.pulls = decayed_pulls;
    entry.reward_sum = decayed_reward_sum;
    entry.ema_abs_dev_milli = ((entry.ema_abs_dev_milli as f64) * decay_factor)
        .round()
        .max(0.0) as u64;
    if decay_factor < 0.25 {
        entry.drift_alert_streak = 0;
    }
}

fn update_shadow_drift_state(entry: &mut ShadowBanditArmStats, reward: i64) {
    let reward_milli = reward.saturating_mul(1000);
    if entry.pulls <= 1 || entry.ema_reward_milli == 0 {
        entry.ema_reward_milli = reward_milli;
        entry.ema_abs_dev_milli = SHADOW_DRIFT_MIN_DEV_MILLI;
        entry.drift_alert_streak = 0;
        return;
    }

    let delta = reward_milli.saturating_sub(entry.ema_reward_milli);
    entry.ema_reward_milli = entry
        .ema_reward_milli
        .saturating_add(delta / SHADOW_DRIFT_EMA_ALPHA_DEN);
    let abs_delta = delta.unsigned_abs() as i64;
    let dev_delta = abs_delta.saturating_sub(entry.ema_abs_dev_milli as i64);
    let next_dev = (entry.ema_abs_dev_milli as i64)
        .saturating_add(dev_delta / SHADOW_DRIFT_EMA_ALPHA_DEN)
        .max(SHADOW_DRIFT_MIN_DEV_MILLI as i64);
    entry.ema_abs_dev_milli = next_dev as u64;

    let threshold = entry
        .ema_abs_dev_milli
        .saturating_mul(2)
        .max(SHADOW_DRIFT_MIN_DEV_MILLI);
    if (abs_delta as u64) > threshold {
        entry.drift_alert_streak = entry.drift_alert_streak.saturating_add(1);
    } else if entry.drift_alert_streak > 0 {
        entry.drift_alert_streak = entry.drift_alert_streak.saturating_sub(1);
    }
}

fn shadow_arm_drift_detected(bucket: &str, arm: &str) -> bool {
    let key = format!("{bucket}|{arm}");
    SHADOW_BANDIT_ARMS
        .get_or_init(DashMap::new)
        .get(&key)
        .map(|stats| stats.drift_alert_streak >= SHADOW_DRIFT_STREAK_TRIGGER)
        .unwrap_or(false)
}

fn shadow_effective_stats(
    bucket: &str,
    arm: &str,
    map: &DashMap<String, ShadowBanditArmStats>,
) -> (u64, i64) {
    let prior = shadow_arm_prior(bucket, arm);
    let key = format!("{bucket}|{arm}");
    if let Some(stats) = map.get(&key) {
        let (pulls, reward_sum) = shadow_decayed_stats_view(&stats, now_unix_secs());
        (
            prior.pseudo_pulls.saturating_add(pulls),
            prior.pseudo_reward_sum.saturating_add(reward_sum),
        )
    } else {
        (prior.pseudo_pulls, prior.pseudo_reward_sum)
    }
}

fn shadow_decayed_stats_view(stats: &ShadowBanditArmStats, now: u64) -> (u64, i64) {
    if stats.last_seen_unix == 0 {
        return (stats.pulls, stats.reward_sum);
    }
    let elapsed = now.saturating_sub(stats.last_seen_unix);
    if elapsed < SHADOW_DECAY_MIN_ELAPSED_SECS {
        return (stats.pulls, stats.reward_sum);
    }
    let decay_factor = 0.5f64.powf(elapsed as f64 / SHADOW_DECAY_HALFLIFE_SECS as f64);
    if !(0.0..1.0).contains(&decay_factor) {
        return (stats.pulls, stats.reward_sum);
    }
    (
        ((stats.pulls as f64) * decay_factor).round().max(0.0) as u64,
        ((stats.reward_sum as f64) * decay_factor).round() as i64,
    )
}

fn shadow_tie_break(route_key: &str, candidate_arm: &str, current_best_arm: &str) -> bool {
    if candidate_arm == current_best_arm {
        return false;
    }
    let a = stable_hash(&format!("{route_key}|{candidate_arm}"));
    let b = stable_hash(&format!("{route_key}|{current_best_arm}"));
    if a == b {
        candidate_arm < current_best_arm
    } else {
        a < b
    }
}

fn shadow_arm_prior(bucket: &str, arm: &str) -> ShadowArmPrior {
    let bypass_idx = arm
        .strip_prefix("bypass:")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);
    match bucket {
        "youtube" => match arm {
            "direct" => ShadowArmPrior::with_mean(-20),
            "bypass:1" => ShadowArmPrior::with_mean(60),
            "bypass:2" => ShadowArmPrior::with_mean(35),
            _ if bypass_idx > 0 => ShadowArmPrior::with_mean(15),
            _ => ShadowArmPrior::with_mean(0),
        },
        "discord" => match arm {
            "direct" => ShadowArmPrior::with_mean(-25),
            "bypass:2" => ShadowArmPrior::with_mean(62),
            "bypass:1" => ShadowArmPrior::with_mean(50),
            _ if bypass_idx > 0 => ShadowArmPrior::with_mean(18),
            _ => ShadowArmPrior::with_mean(0),
        },
        "google-common" => match arm {
            // In blocked regions, direct often "connects" but dies before usable TLS traffic.
            // Biasing a bit towards bypass reduces long cold-start degradation.
            "direct" => ShadowArmPrior::with_mean(18),
            "bypass:1" => ShadowArmPrior::with_mean(32),
            "bypass:2" => ShadowArmPrior::with_mean(22),
            _ if bypass_idx > 0 => ShadowArmPrior::with_mean(12),
            _ => ShadowArmPrior::with_mean(0),
        },
        "ads-noise" => match arm {
            "direct" => ShadowArmPrior::with_mean(70),
            _ if bypass_idx > 0 => ShadowArmPrior::with_mean(-35),
            _ => ShadowArmPrior::with_mean(0),
        },
        _ => match arm {
            "direct" => ShadowArmPrior::with_mean(28),
            "bypass:1" => ShadowArmPrior::with_mean(18),
            "bypass:2" => ShadowArmPrior::with_mean(8),
            _ if bypass_idx > 0 => ShadowArmPrior::with_mean(2),
            _ => ShadowArmPrior::with_mean(0),
        },
    }
}

fn shadow_bucket_name(route_key: &str, host: &str, cfg: &EngineConfig) -> String {
    if crate::pt::socks5_server::is_noise_probe_https_destination(crate::pt::socks5_server::route_connection::route_destination_key(route_key)) {
        return "ads-noise".to_owned();
    }
    match host_service_bucket(host, cfg).as_str() {
        "meta-group:youtube" => "youtube".to_owned(),
        "meta-group:discord" => "discord".to_owned(),
        "meta-group:google" => "google-common".to_owned(),
        _ => "default".to_owned(),
    }
}

pub(super) fn shadow_exploration_enabled(bucket: &str, decision_id: u64, route_key: &str) -> bool {
    if bucket == "ads-noise" {
        return false;
    }
    let token = stable_hash(&format!("{bucket}|{decision_id}|{route_key}")) % 100;
    token < SHADOW_EXPLORATION_BUDGET_PCT
}

fn route_destination_host(route_key: &str) -> String {
    let destination = crate::pt::socks5_server::route_connection::route_destination_key(route_key);
    split_host_port_for_connect(destination)
        .map(|(host, _)| host)
        .unwrap_or_else(|| destination.to_owned())
}

fn profile_from_candidate(candidate: &RouteCandidate) -> Option<u8> {
    if candidate.kind == RouteKind::Bypass {
        Some(candidate.bypass_profile_idx.saturating_add(1))
    } else {
        None
    }
}

fn profile_from_route_arm(route_arm: &str) -> Option<u8> {
    route_arm
        .strip_prefix("bypass:")
        .and_then(|value| value.parse::<u8>().ok())
}

#[cfg(test)]
pub(super) fn clear_route_ml_state_for_test() {
    ROUTE_DECISION_EVENTS_PENDING
        .get_or_init(DashMap::new)
        .clear();
    ROUTE_OUTCOME_EVENTS.get_or_init(DashMap::new).clear();
    SHADOW_BANDIT_ARMS.get_or_init(DashMap::new).clear();
    SHADOW_CANARY_DECISIONS.get_or_init(DashMap::new).clear();
    SHADOW_CANARY_SWITCH_GUARD.get_or_init(DashMap::new).clear();
    SHADOW_CANARY_BUCKET_COOLDOWN_UNTIL
        .get_or_init(DashMap::new)
        .clear();
    if let Ok(mut state) = SHADOW_CANARY_SLO_STATE
        .get_or_init(|| RwLock::new(ShadowCanarySloState::default()))
        .write()
    {
        *state = ShadowCanarySloState::default();
    }
    SHADOW_CANARY_ROLLBACK_UNTIL_UNIX.store(0, Ordering::Relaxed);
    NEXT_ROUTE_DECISION_ID.store(1, Ordering::Relaxed);
}

#[cfg(test)]
pub(super) fn route_ml_pending_len_for_test() -> usize {
    ROUTE_DECISION_EVENTS_PENDING
        .get_or_init(DashMap::new)
        .len()
}

#[cfg(test)]
pub(super) fn route_ml_outcomes_for_test() -> Vec<RouteOutcomeEvent> {
    let map = ROUTE_OUTCOME_EVENTS.get_or_init(DashMap::new);
    let mut out: Vec<RouteOutcomeEvent> = map.iter().map(|entry| entry.value().clone()).collect();
    out.sort_by_key(|event| event.decision_id);
    out
}

#[cfg(test)]
pub(super) fn shadow_bandit_stats_for_test(
    bucket: &str,
    arm: &str,
) -> Option<ShadowBanditArmStats> {
    SHADOW_BANDIT_ARMS
        .get_or_init(DashMap::new)
        .get(&format!("{bucket}|{arm}"))
        .map(|entry| entry.clone())
}

#[cfg(test)]
pub(super) fn shadow_bucket_name_for_test(route_key: &str, host: &str) -> String {
    shadow_bucket_name(route_key, host, &EngineConfig::default())
}

#[cfg(test)]
pub(super) fn shadow_arm_prior_for_test(bucket: &str, arm: &str) -> (u64, i64) {
    let prior = shadow_arm_prior(bucket, arm);
    (prior.pseudo_pulls, prior.pseudo_reward_sum)
}

#[cfg(test)]
pub(super) fn canary_rollback_until_for_test() -> u64 {
    SHADOW_CANARY_ROLLBACK_UNTIL_UNIX.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(super) fn canary_bucket_cooldown_until_for_test(bucket: &str) -> Option<u64> {
    SHADOW_CANARY_BUCKET_COOLDOWN_UNTIL
        .get_or_init(DashMap::new)
        .get(bucket)
        .map(|value| *value)
}

#[cfg(test)]
pub(super) fn replay_route_outcomes_for_test(outcomes: &[RouteOutcomeEvent]) -> usize {
    let mut replay = outcomes.to_vec();
    replay.sort_by_key(|event| (event.timestamp_unix, event.decision_id));
    let mut applied = 0usize;
    for event in replay {
        if event.validate().is_err() {
            continue;
        }
        update_shadow_bandit(
            &event.bucket,
            &event.route_arm,
            event.shadow_reward,
            event.timestamp_unix,
        );
        applied = applied.saturating_add(1);
    }
    applied
}

#[cfg(test)]
pub(super) fn shadow_arm_drift_detected_for_test(bucket: &str, arm: &str) -> bool {
    shadow_arm_drift_detected(bucket, arm)
}
