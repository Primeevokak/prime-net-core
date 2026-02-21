pub mod dnt;
pub mod referer_policy;
pub mod tracker_blocker;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use once_cell::sync::Lazy;
use parking_lot::RwLock;

use crate::config::{PrivacyConfig, RefererMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct BlockedRecord {
    pub at: SystemTime,
    pub domain: String,
}

#[derive(Debug, Clone)]
pub struct PrivacyStatsSnapshot {
    pub session_blocked: u64,
    pub total_blocked: u64,
    pub recent_blocked: Vec<BlockedRecord>,
}

#[derive(Debug, Default)]
struct PrivacyStatsState {
    recent_blocked: RwLock<VecDeque<BlockedRecord>>,
    session_blocked: AtomicU64,
    total_blocked: AtomicU64,
}

static PRIVACY_STATS: Lazy<PrivacyStatsState> = Lazy::new(PrivacyStatsState::default);

pub fn record_blocked_domain(domain: &str) {
    PRIVACY_STATS
        .session_blocked
        .fetch_add(1, Ordering::Relaxed);
    PRIVACY_STATS.total_blocked.fetch_add(1, Ordering::Relaxed);

    let mut recent = PRIVACY_STATS.recent_blocked.write();
    recent.push_front(BlockedRecord {
        at: SystemTime::now(),
        domain: domain.to_owned(),
    });
    while recent.len() > 100 {
        recent.pop_back();
    }
}

pub fn privacy_stats_snapshot(limit: usize) -> PrivacyStatsSnapshot {
    let recent = PRIVACY_STATS
        .recent_blocked
        .read()
        .iter()
        .take(limit)
        .cloned()
        .collect();

    PrivacyStatsSnapshot {
        session_blocked: PRIVACY_STATS.session_blocked.load(Ordering::Relaxed),
        total_blocked: PRIVACY_STATS.total_blocked.load(Ordering::Relaxed),
        recent_blocked: recent,
    }
}

pub fn privacy_level(cfg: &PrivacyConfig) -> PrivacyLevel {
    if cfg.tracker_blocker.enabled
        && cfg.referer.enabled
        && cfg.signals.send_dnt
        && cfg.signals.send_gpc
        && matches!(cfg.referer.mode, RefererMode::Strip)
    {
        return PrivacyLevel::High;
    }
    if cfg.signals.send_gpc || cfg.referer.enabled || cfg.tracker_blocker.enabled {
        return PrivacyLevel::Medium;
    }
    PrivacyLevel::Low
}
