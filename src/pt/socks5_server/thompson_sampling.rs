//! Thompson Sampling route selection strategy.
//!
//! Alternative to UCB1 for the ML shadow bandit.  Thompson Sampling draws
//! from a Beta posterior for each arm and picks the arm with the highest
//! sample.  This naturally balances exploration/exploitation without a
//! tunable exploration constant.
//!
//! The Beta distribution is parameterised as `Beta(alpha, beta)` where:
//! - `alpha` = prior_alpha + successes
//! - `beta`  = prior_beta + failures
//!
//! Rewards from `shadow_reward_from_outcome` (range `[-100, +70]`) are
//! mapped to the `[0, 1]` range before updating alpha/beta.

use dashmap::DashMap;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::pt::socks5_server::now_unix_secs;

/// Global Thompson Sampling arm state, keyed by `"<bucket>|<arm_id>"`.
static THOMPSON_ARMS: OnceLock<DashMap<String, ThompsonArmStats>> = OnceLock::new();

/// Per-arm Beta posterior parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThompsonArmStats {
    /// Accumulated pseudo-successes (`alpha` component).
    pub alpha: f64,
    /// Accumulated pseudo-failures (`beta` component).
    pub beta: f64,
    /// Total number of reward updates.
    pub updates: u64,
    /// Unix timestamp of last update (for decay).
    pub last_seen_unix: u64,
}

/// Default prior: weakly informative `Beta(1, 1)` = uniform on `[0, 1]`.
const PRIOR_ALPHA: f64 = 1.0;
const PRIOR_BETA: f64 = 1.0;

/// Minimum reward value from the reward function.
const REWARD_MIN: f64 = -100.0;
/// Maximum reward value from the reward function.
const REWARD_MAX: f64 = 70.0;

/// Half-life for exponential decay of Thompson posterior (30 minutes).
const THOMPSON_DECAY_HALFLIFE_SECS: u64 = 1800;

/// Map a raw reward in `[-100, +70]` to `[0, 1]`.
fn normalise_reward(reward: i64) -> f64 {
    let r = reward as f64;
    ((r - REWARD_MIN) / (REWARD_MAX - REWARD_MIN)).clamp(0.0, 1.0)
}

/// Sample from `Beta(alpha, beta)` using the Gamma decomposition.
///
/// `Beta(a, b)` is equivalent to `X/(X+Y)` where `X ~ Gamma(a, 1)`, `Y ~ Gamma(b, 1)`.
/// We use rejection sampling for the Gamma distribution (Marsaglia & Tsang method
/// is built into `rand_distr`, but we avoid the extra dependency by using a simpler
/// approximation that is good enough for bandit arms with moderate alpha/beta).
fn sample_beta(alpha: f64, beta: f64) -> f64 {
    let mut rng = rand::thread_rng();

    // Edge cases: when alpha or beta are very small, clamp to avoid NaN.
    let a = alpha.max(0.01);
    let b = beta.max(0.01);

    // Sample via Gamma ratio: Beta(a,b) = Ga/(Ga+Gb).
    let x = sample_gamma(&mut rng, a);
    let y = sample_gamma(&mut rng, b);

    if x + y == 0.0 {
        0.5
    } else {
        x / (x + y)
    }
}

/// Simple Gamma(shape, 1) sampler using Marsaglia-Tsang's method.
fn sample_gamma(rng: &mut impl Rng, shape: f64) -> f64 {
    if shape < 1.0 {
        // Boost: Gamma(a) = Gamma(a+1) * U^(1/a)
        let u: f64 = rng.gen::<f64>();
        return sample_gamma(rng, shape + 1.0) * u.powf(1.0 / shape);
    }

    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();

    loop {
        let x: f64 = loop {
            let n = sample_standard_normal(rng);
            if 1.0 + c * n > 0.0 {
                break n;
            }
        };
        let v = (1.0 + c * x).powi(3);
        let u: f64 = rng.gen::<f64>();

        if u < 1.0 - 0.0331 * x.powi(4) {
            return d * v;
        }
        if u.ln() < 0.5 * x * x + d * (1.0 - v + v.ln()) {
            return d * v;
        }
    }
}

/// Box-Muller standard normal sample.
fn sample_standard_normal(rng: &mut impl Rng) -> f64 {
    let u1: f64 = rng.gen::<f64>();
    let u2: f64 = rng.gen::<f64>();
    let r: f64 = (-2.0 * u1.max(1e-300).ln()).sqrt();
    r * (2.0 * std::f64::consts::PI * u2).cos()
}

/// Access the global Thompson arms map.
fn arms_map() -> &'static DashMap<String, ThompsonArmStats> {
    THOMPSON_ARMS.get_or_init(DashMap::new)
}

/// Choose a route arm using Thompson Sampling.
///
/// Draws a sample from each arm's Beta posterior and returns the arm with
/// the highest sample.  Arms with no observations draw from the prior
/// `Beta(1, 1)`, giving them a 50% expected sample — enough exploration
/// to try them early.
pub fn thompson_choose_route_arm(
    bucket: &str,
    candidates: &[crate::pt::socks5_server::RouteCandidate],
) -> String {
    if candidates.is_empty() {
        return "none".to_owned();
    }

    let map = arms_map();
    let now = now_unix_secs();

    let mut best_arm = candidates[0].route_id();
    let mut best_sample = f64::NEG_INFINITY;

    for c in candidates {
        let arm_id = c.route_id();
        let key = format!("{bucket}|{arm_id}");

        let (alpha, beta) = if let Some(stats) = map.get(&key) {
            let decay = compute_decay(stats.last_seen_unix, now);
            (
                PRIOR_ALPHA + stats.alpha * decay,
                PRIOR_BETA + stats.beta * decay,
            )
        } else {
            (PRIOR_ALPHA, PRIOR_BETA)
        };

        let sample = sample_beta(alpha, beta);
        if sample > best_sample {
            best_sample = sample;
            best_arm = arm_id;
        }
    }

    best_arm
}

/// Update the Thompson posterior for an arm after observing an outcome.
pub fn thompson_update(bucket: &str, arm: &str, reward: i64) {
    let p = normalise_reward(reward);
    let key = format!("{bucket}|{arm}");
    let map = arms_map();
    let mut entry = map.entry(key).or_default();
    entry.alpha += p;
    entry.beta += 1.0 - p;
    entry.updates += 1;
    entry.last_seen_unix = now_unix_secs();
}

/// Prune Thompson arms not seen in the given TTL.
pub fn prune_thompson_state(now: u64, max_age_secs: u64) {
    let map = arms_map();
    map.retain(|_, stats| now.saturating_sub(stats.last_seen_unix) <= max_age_secs);
}

/// Compute exponential decay factor based on elapsed time.
fn compute_decay(last_seen_unix: u64, now: u64) -> f64 {
    if last_seen_unix == 0 {
        return 1.0;
    }
    let elapsed = now.saturating_sub(last_seen_unix);
    if elapsed < 10 {
        1.0
    } else {
        2.0_f64
            .powf(-(elapsed as f64 / THOMPSON_DECAY_HALFLIFE_SECS as f64))
            .clamp(0.0, 1.0)
    }
}

/// Collect a snapshot of all Thompson arm states.
pub fn thompson_snapshot() -> Vec<(String, ThompsonArmStats)> {
    arms_map()
        .iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod thompson_sampling_tests {
    use super::*;
    use crate::pt::socks5_server::{RouteCandidate, RouteIpFamily};

    #[test]
    fn normalise_reward_range() {
        assert!((normalise_reward(-100) - 0.0).abs() < f64::EPSILON);
        assert!((normalise_reward(70) - 1.0).abs() < f64::EPSILON);
        let mid = normalise_reward(0);
        assert!(mid > 0.0 && mid < 1.0);
    }

    #[test]
    fn sample_beta_within_unit_interval() {
        for _ in 0..100 {
            let s = sample_beta(2.0, 3.0);
            assert!((0.0..=1.0).contains(&s), "sample={s}");
        }
    }

    #[test]
    fn thompson_update_increases_alpha_on_positive_reward() {
        let map = arms_map();
        let key = "ts-test-update|arm-a".to_owned();
        map.remove(&key);

        thompson_update("ts-test-update", "arm-a", 70); // max reward
        {
            let stats = map.get(&key).unwrap();
            assert!(stats.alpha > 0.9, "alpha should increase: {}", stats.alpha);
            assert!(stats.beta < 0.1, "beta should be near 0: {}", stats.beta);
        }

        map.remove(&key);
    }

    #[test]
    fn thompson_update_increases_beta_on_negative_reward() {
        let map = arms_map();
        let key = "ts-test-neg|arm-b".to_owned();
        map.remove(&key);

        thompson_update("ts-test-neg", "arm-b", -100); // min reward
        {
            let stats = map.get(&key).unwrap();
            assert!(stats.alpha < 0.1, "alpha near 0: {}", stats.alpha);
            assert!(stats.beta > 0.9, "beta should increase: {}", stats.beta);
        }

        map.remove(&key);
    }

    #[test]
    fn thompson_choose_returns_valid_arm() {
        let candidates = vec![
            RouteCandidate::native_with_family("test", 0, 3, RouteIpFamily::Any),
            RouteCandidate::native_with_family("test", 1, 3, RouteIpFamily::Any),
            RouteCandidate::native_with_family("test", 2, 3, RouteIpFamily::Any),
        ];

        let chosen = thompson_choose_route_arm("ts-test-choose", &candidates);
        let valid_arms: Vec<String> = candidates.iter().map(|c| c.route_id()).collect();
        assert!(
            valid_arms.contains(&chosen),
            "chosen arm '{chosen}' not in candidates"
        );
    }

    #[test]
    fn thompson_choose_empty_returns_none() {
        assert_eq!(thompson_choose_route_arm("ts-empty", &[]), "none");
    }

    #[test]
    fn prune_removes_old_thompson_state() {
        let map = arms_map();
        let stale_key = "ts-prune|stale".to_owned();
        let fresh_key = "ts-prune|fresh".to_owned();

        let now = now_unix_secs();
        map.insert(
            stale_key.clone(),
            ThompsonArmStats {
                alpha: 5.0,
                beta: 3.0,
                updates: 8,
                last_seen_unix: now.saturating_sub(8 * 24 * 3600),
            },
        );
        map.insert(
            fresh_key.clone(),
            ThompsonArmStats {
                alpha: 2.0,
                beta: 1.0,
                updates: 3,
                last_seen_unix: now.saturating_sub(3600),
            },
        );

        prune_thompson_state(now, 7 * 24 * 3600);

        assert!(!map.contains_key(&stale_key));
        assert!(map.contains_key(&fresh_key));

        map.remove(&fresh_key);
    }

    #[test]
    fn thompson_converges_to_best_arm() {
        let map = arms_map();
        let bucket = "ts-converge";

        // Simulate: native:1 gets many positive rewards, native:2 gets negative.
        // Use actual route IDs that match RouteCandidate::route_id().
        for _ in 0..50 {
            thompson_update(bucket, "native:1", 60);
            thompson_update(bucket, "native:2", -80);
        }

        let candidates = vec![
            RouteCandidate::native_with_family("test", 0, 2, RouteIpFamily::Any),
            RouteCandidate::native_with_family("test", 1, 2, RouteIpFamily::Any),
        ];

        let mut a_wins = 0;
        for _ in 0..100 {
            let chosen = thompson_choose_route_arm(bucket, &candidates);
            if chosen == "native:1" {
                a_wins += 1;
            }
        }

        assert!(
            a_wins > 70,
            "native:1 (high reward) should win most of the time: {a_wins}/100"
        );

        // Cleanup
        map.remove(&format!("{bucket}|native:1"));
        map.remove(&format!("{bucket}|native:2"));
    }
}
