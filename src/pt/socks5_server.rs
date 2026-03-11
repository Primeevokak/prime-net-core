use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;

use crate::pt::{BoxStream, OutboundConnector};

// --- GLOBAL CONSTANTS ---
pub const ROUTE_WINNER_TTL_SECS: u64 = 900;
pub const ROUTE_FAILS_BEFORE_WEAK: u8 = 2;
pub const ROUTE_WEAK_BASE_SECS: u64 = 45;
pub const ROUTE_WEAK_MAX_SECS: u64 = 300;
pub const GLOBAL_BYPASS_HARD_WEAK_SCORE: i64 = -80;
pub const LEARNED_BYPASS_MIN_FAILURES_DOMAIN: u8 = 1;
pub const LEARNED_BYPASS_MIN_FAILURES_IP: u8 = 3;
pub const ROUTE_CAPABILITY_BYPASS_REP03_SECS: u64 = 120;
pub const ROUTE_RACE_MAX_CANDIDATES: usize = 4;
pub const ROUTE_RACE_BASE_DELAY_MS: u64 = 50;
pub const ROUTE_RACE_DIRECT_HEADSTART_MS: u64 = 300;
pub const ROUTE_RACE_BYPASS_EXTRA_DELAY_MS: u64 = 50;

// --- GLOBAL ENUMS ---
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockingSignal {
    Reset,
    Timeout,
    EarlyClose,
    BrokenPipe,
    SuspiciousZeroReply,
    SilentDrop,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteKind {
    Direct,
    Bypass,
    /// In-process TLS/TCP desync via `TcpDesyncEngine` — no external binary needed.
    Native,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteIpFamily {
    V4,
    V6,
    Any,
}
impl RouteIpFamily {
    pub fn label(&self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
            Self::Any => "any",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRaceReason {
    NonTlsPort,
    SingleCandidate,
    NoWinner,
    EmptyWinner,
    WinnerStale,
    WinnerMissingFromCandidates,
    WinnerWeak,
    WinnerHealthy,
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub enum StageSelectionSource {
    #[default]
    Default,
    Classifier,
    DomainMatch,
}

// --- GLOBAL STRUCTS ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCandidate {
    pub kind: RouteKind,
    pub source: &'static str,
    pub bypass_addr: Option<SocketAddr>,
    pub bypass_profile_idx: u8,
    pub bypass_profile_total: u8,
    pub family: RouteIpFamily,
    pub score: i32,
}
impl RouteCandidate {
    pub fn direct_with_family(source: &'static str, family: RouteIpFamily) -> Self {
        Self {
            kind: RouteKind::Direct,
            source,
            bypass_addr: None,
            bypass_profile_idx: 0,
            bypass_profile_total: 0,
            family,
            score: 0,
        }
    }
    pub fn bypass_with_family(
        source: &'static str,
        addr: SocketAddr,
        idx: u8,
        total: u8,
        family: RouteIpFamily,
    ) -> Self {
        Self {
            kind: RouteKind::Bypass,
            source,
            bypass_addr: Some(addr),
            bypass_profile_idx: idx,
            bypass_profile_total: total,
            family,
            score: 0,
        }
    }
    pub fn native_with_family(
        source: &'static str,
        idx: u8,
        total: u8,
        family: RouteIpFamily,
    ) -> Self {
        Self {
            kind: RouteKind::Native,
            source,
            bypass_addr: None,
            bypass_profile_idx: idx,
            bypass_profile_total: total,
            family,
            score: 0,
        }
    }
    pub fn route_id(&self) -> String {
        match self.kind {
            RouteKind::Direct => "direct".to_owned(),
            RouteKind::Bypass => format!("bypass:{}", self.bypass_profile_idx + 1),
            RouteKind::Native => format!("native:{}", self.bypass_profile_idx + 1),
        }
    }
    pub fn route_label(&self) -> String {
        match self.kind {
            RouteKind::Direct => format!("direct:{}", self.source),
            RouteKind::Bypass => format!("bypass:{}:{}", self.bypass_profile_idx + 1, self.source),
            RouteKind::Native => format!("native:{}:{}", self.bypass_profile_idx + 1, self.source),
        }
    }
    pub fn kind_rank(&self) -> u8 {
        match self.kind {
            RouteKind::Direct => 0,
            RouteKind::Bypass => 1,
            RouteKind::Native => 1,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteWinner {
    pub route_id: String,
    pub updated_at_unix: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteHealth {
    pub successes: u64,
    pub failures: u64,
    pub consecutive_failures: u8,
    pub weak_until_unix: u64,
    pub last_success_unix: u64,
    pub last_failure_unix: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BypassProfileHealth {
    pub successes: u64,
    pub failures: u64,
    pub connect_failures: u64,
    pub soft_zero_replies: u64,
    pub io_errors: u64,
    pub last_success_unix: u64,
    pub last_failure_unix: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DestinationClassifier {
    pub successes: u64,
    pub failures: u64,
    pub resets: u8,
    pub timeouts: u64,
    pub early_closes: u64,
    pub broken_pipes: u64,
    pub suspicious_zero_replies: u64,
    pub silent_drops: u64,
    pub last_seen_unix: u64,
    pub winner: Option<RouteWinner>,
    pub preferred_stage: Option<u8>,
}
#[derive(Debug, Clone, Default)]
pub struct RouteCapabilities {
    pub direct_v4_weak_until: u64,
    pub direct_v6_weak_until: u64,
    pub bypass_v4_weak_until: u64,
    pub bypass_v6_weak_until: u64,
}
#[derive(Debug, Default)]
pub struct RouteMetrics {
    pub race_started: AtomicU64,
    pub race_skipped: AtomicU64,
    pub route_success_direct: AtomicU64,
    pub route_success_bypass: AtomicU64,
    pub route_failure_direct: AtomicU64,
    pub route_failure_bypass: AtomicU64,
}
#[derive(Debug, Clone, Default)]
pub struct TunedRelay {
    pub options: RelayOptions,
    pub stage: u8,
    pub source: StageSelectionSource,
}

// --- STATICS ---
pub static DEST_FAILURES: OnceLock<DashMap<String, u8>> = OnceLock::new();
pub static DEST_CLASSIFIER: OnceLock<DashMap<String, DestinationClassifier>> = OnceLock::new();
pub static DEST_PREFERRED_STAGE: OnceLock<DashMap<String, u8>> = OnceLock::new();
pub static DEST_BYPASS_PROFILE_IDX: OnceLock<DashMap<String, u8>> = OnceLock::new();
pub static DEST_BYPASS_PROFILE_FAILURES: OnceLock<DashMap<String, u8>> = OnceLock::new();
pub static DEST_ROUTE_WINNER: OnceLock<DashMap<String, RouteWinner>> = OnceLock::new();
pub static DEST_ROUTE_HEALTH: OnceLock<DashMap<String, DashMap<String, RouteHealth>>> =
    OnceLock::new();
pub static GLOBAL_BYPASS_PROFILE_HEALTH: OnceLock<DashMap<String, BypassProfileHealth>> =
    OnceLock::new();
pub static ROUTE_CAPABILITIES: OnceLock<RwLock<RouteCapabilities>> = OnceLock::new();
pub static ROUTE_METRICS: OnceLock<RouteMetrics> = OnceLock::new();
pub static BLOCKLIST_DOMAINS: OnceLock<crate::blocklist::DomainBloom> = OnceLock::new();

// --- MODULES ---
#[path = "socks5_server_parts/classifier_and_persistence.rs"]
pub mod classifier_and_persistence;
#[path = "socks5_server_parts/ml_shadow.rs"]
pub mod ml_shadow;
#[path = "socks5_server_parts/protocol_handlers.rs"]
pub mod protocol_handlers;
#[path = "socks5_server_parts/protocol_socks4.rs"]
pub mod protocol_socks4;
#[path = "socks5_server_parts/protocol_udp.rs"]
pub mod protocol_udp;
#[path = "socks5_server_parts/relay_and_io_helpers.rs"]
pub mod relay_and_io_helpers;
#[path = "socks5_server_parts/route_connection.rs"]
pub mod route_connection;
#[path = "socks5_server_parts/route_scoring.rs"]
pub mod route_scoring;
#[path = "socks5_server_parts/state_and_startup.rs"]
pub mod state_and_startup;
#[path = "socks5_server_parts/telemetry_bus.rs"]
pub mod telemetry_bus;

pub use state_and_startup::{
    start_socks5_server, RelayOptions, Socks5ServerGuard, WARNED_SOCKS4_LIMITATIONS,
};
pub use telemetry_bus::{init_telemetry_bus, send_telemetry, TelemetryEvent};

// --- UTILS ---
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn split_host_port_for_connect(target: &str) -> Option<(String, u16)> {
    let mut parts = target.rsplitn(2, ':');
    let port = parts.next()?.parse::<u16>().ok()?;
    let host = parts.next()?.to_owned();
    Some((host, port))
}
pub fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>().ok()
}
pub fn is_bypassable_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unicast_link_local()
                && !v6.is_unique_local()
                && !v6.is_multicast()
                && !v6.is_unspecified()
        }
    }
}
pub fn stable_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}
