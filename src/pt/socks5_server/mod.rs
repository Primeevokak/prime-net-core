use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;

use crate::pt::{BoxStream, OutboundConnector};

// ── Constants ─────────────────────────────────────────────────────────────────

/// How long (in seconds) a learned route winner is considered fresh before a re-race.
pub const ROUTE_WINNER_TTL_SECS: u64 = 900;
/// Consecutive failures before a route is marked "weak".
pub const ROUTE_FAILS_BEFORE_WEAK: u8 = 2;
/// Base weak-penalty duration in seconds.
pub const ROUTE_WEAK_BASE_SECS: u64 = 45;
/// Maximum weak-penalty duration in seconds.
pub const ROUTE_WEAK_MAX_SECS: u64 = 300;
/// Global bypass health score below which the profile is considered hard-weak.
pub const GLOBAL_BYPASS_HARD_WEAK_SCORE: i64 = -80;
/// Minimum per-domain failures before learned bypass kicks in for domain targets.
pub const LEARNED_BYPASS_MIN_FAILURES_DOMAIN: u8 = 1;
/// Minimum per-IP failures before learned bypass kicks in for IP targets.
pub const LEARNED_BYPASS_MIN_FAILURES_IP: u8 = 3;
/// Seconds to wait before re-probing a capability-weak bypass route.
pub const ROUTE_CAPABILITY_BYPASS_REP03_SECS: u64 = 120;
/// Maximum number of candidates evaluated in a single route race.
pub const ROUTE_RACE_MAX_CANDIDATES: usize = 4;
/// Base inter-candidate delay in milliseconds during a route race.
pub const ROUTE_RACE_BASE_DELAY_MS: u64 = 50;
/// Head-start given to Direct routes before Bypass/Native are tried.
pub const ROUTE_RACE_DIRECT_HEADSTART_MS: u64 = 300;
/// Extra delay added for each additional Bypass candidate.
pub const ROUTE_RACE_BYPASS_EXTRA_DELAY_MS: u64 = 50;

// ── Enums ─────────────────────────────────────────────────────────────────────

/// Observed TCP signal that indicates DPI-based blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockingSignal {
    /// TCP RST from the remote side.
    Reset,
    /// No data received within the connection timeout.
    Timeout,
    /// Connection closed before any data was exchanged.
    EarlyClose,
    /// Write failed with a broken-pipe error.
    BrokenPipe,
    /// Server replied with zero meaningful bytes (suspected block page).
    SuspiciousZeroReply,
    /// Connection silently dropped — no RST, no data.
    SilentDrop,
}

/// How a connection should be routed to reach the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteKind {
    /// Direct TCP — no evasion.
    Direct,
    /// External SOCKS5 bypass proxy (ciadpi / outline / etc.).
    Bypass,
    /// In-process TLS/TCP desync via [`TcpDesyncEngine`] — no external binary needed.
    Native,
}

/// IP address family preference for a route candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteIpFamily {
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
    /// No preference — use whatever resolves first.
    Any,
}

impl RouteIpFamily {
    /// Short label used as a suffix in health-map keys.
    pub fn label(&self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
            Self::Any => "any",
        }
    }
}

/// Why a route race was initiated for a given connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRaceReason {
    /// Port is not TLS/HTTP — Direct is the only viable option.
    NonTlsPort,
    /// Only one candidate exists, no race needed.
    SingleCandidate,
    /// No cached winner — full race required.
    NoWinner,
    /// Winner entry exists but `route_id` is empty.
    EmptyWinner,
    /// Winner entry exists but has expired (TTL exceeded).
    WinnerStale,
    /// Cached winner's `route_id` is no longer in the candidate list.
    WinnerMissingFromCandidates,
    /// Winner is health-weak — re-evaluate.
    WinnerWeak,
    /// Winner is healthy and will be used directly.
    WinnerHealthy,
}

/// How the relay stage was selected for a connection.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub enum StageSelectionSource {
    /// Default stage (no learning data).
    #[default]
    Default,
    /// Stage was chosen by the destination classifier.
    Classifier,
    /// Stage was matched by a domain pattern.
    DomainMatch,
}

// ── Structs ───────────────────────────────────────────────────────────────────

/// A single candidate considered during a route race.
///
/// Constructed by [`route_scoring::select_route_candidates`] and consumed by
/// [`route_connection::connect_via_best_route`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCandidate {
    /// Whether to route Direct, via external Bypass, or via in-process Native desync.
    pub kind: RouteKind,
    /// Human-readable label for where this candidate came from (e.g. `"pool"`, `"engine"`).
    pub source: &'static str,
    /// Address of the external SOCKS5 bypass proxy; `None` for Direct and Native routes.
    pub bypass_addr: Option<SocketAddr>,
    /// Zero-based profile index within the bypass pool or the [`TcpDesyncEngine`].
    pub bypass_profile_idx: u8,
    /// Total number of profiles in the pool/engine at the time of candidate creation.
    pub bypass_profile_total: u8,
    /// IP family preference for this candidate.
    pub family: RouteIpFamily,
    /// Initial score used to order candidates before per-domain health is applied.
    pub score: i32,
}

impl RouteCandidate {
    /// Create a Direct candidate for the given IP family.
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

    /// Create a Bypass candidate with a specific pool address and profile index.
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

    /// Create a Native in-process desync candidate with a specific profile index.
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

    /// Stable string identifier used as map key in health and winner tracking.
    pub fn route_id(&self) -> String {
        match self.kind {
            RouteKind::Direct => "direct".to_owned(),
            RouteKind::Bypass => format!("bypass:{}", self.bypass_profile_idx + 1),
            RouteKind::Native => format!("native:{}", self.bypass_profile_idx + 1),
        }
    }

    /// Human-readable label for logging.
    pub fn route_label(&self) -> String {
        match self.kind {
            RouteKind::Direct => format!("direct:{}", self.source),
            RouteKind::Bypass => {
                format!("bypass:{}:{}", self.bypass_profile_idx + 1, self.source)
            }
            RouteKind::Native => {
                format!("native:{}:{}", self.bypass_profile_idx + 1, self.source)
            }
        }
    }

    /// Sort rank — lower is preferred when health scores are equal.
    /// Direct = 0 (fastest when unblocked), Bypass = Native = 1.
    pub fn kind_rank(&self) -> u8 {
        match self.kind {
            RouteKind::Direct => 0,
            RouteKind::Bypass | RouteKind::Native => 1,
        }
    }
}

/// Cached winner for a destination — the route that succeeded most recently.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteWinner {
    /// The `route_id()` of the winning candidate.
    pub route_id: String,
    /// Unix timestamp of the last win.
    pub updated_at_unix: u64,
}

/// Per-route health counters for a specific destination.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteHealth {
    /// Total successful connections via this route for this destination.
    pub successes: u64,
    /// Total failed connections via this route for this destination.
    pub failures: u64,
    /// Failures since the last success — resets to 0 on any success.
    pub consecutive_failures: u8,
    /// Route is penalised until this Unix timestamp; 0 means not penalised.
    pub weak_until_unix: u64,
    /// Unix timestamp of the last success.
    pub last_success_unix: u64,
    /// Unix timestamp of the last failure.
    pub last_failure_unix: u64,
}

/// Global health counters for a bypass/native profile across all destinations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BypassProfileHealth {
    /// Total successful connections through this profile globally.
    pub successes: u64,
    /// Total failures through this profile globally.
    pub failures: u64,
    /// Failures specifically at the TCP connect stage.
    pub connect_failures: u64,
    /// Connections where the server replied with zero meaningful bytes.
    pub soft_zero_replies: u64,
    /// I/O errors during the relay phase.
    pub io_errors: u64,
    /// Unix timestamp of the last global success.
    pub last_success_unix: u64,
    /// Unix timestamp of the last global failure.
    pub last_failure_unix: u64,
}

/// Per-destination accumulated signal counters used by the adaptive classifier.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DestinationClassifier {
    /// Total successful connections to this destination.
    pub successes: u64,
    /// Total failed connections to this destination.
    pub failures: u64,
    /// Number of TCP RST signals received.
    pub resets: u8,
    /// Number of connection timeouts observed.
    pub timeouts: u64,
    /// Number of early-close events (connection closed before any data).
    pub early_closes: u64,
    /// Number of broken-pipe errors.
    pub broken_pipes: u64,
    /// Number of suspicious zero-byte replies.
    pub suspicious_zero_replies: u64,
    /// Number of silent-drop events.
    pub silent_drops: u64,
    /// Unix timestamp of the most recent access.
    pub last_seen_unix: u64,
    /// Best route for this destination, learned from past races.
    pub winner: Option<RouteWinner>,
    /// Preferred relay stage index, if learned.
    pub preferred_stage: Option<u8>,
}

/// Per-IP-family availability windows for each [`RouteKind`].
///
/// A route kind + family pair is "weak" until its `*_weak_until` timestamp passes.
/// This prevents the route race from wasting time on routes that are globally broken.
#[derive(Debug, Clone, Default)]
pub struct RouteCapabilities {
    /// Direct IPv4 is unavailable until this Unix timestamp; 0 = available.
    pub direct_v4_weak_until: u64,
    /// Direct IPv6 is unavailable until this Unix timestamp; 0 = available.
    pub direct_v6_weak_until: u64,
    /// Bypass IPv4 is unavailable until this Unix timestamp; 0 = available.
    pub bypass_v4_weak_until: u64,
    /// Bypass IPv6 is unavailable until this Unix timestamp; 0 = available.
    pub bypass_v6_weak_until: u64,
    /// Native IPv4 is unavailable until this Unix timestamp; 0 = available.
    pub native_v4_weak_until: u64,
    /// Native IPv6 is unavailable until this Unix timestamp; 0 = available.
    pub native_v6_weak_until: u64,
}

/// Aggregate counters for the SOCKS5 routing engine, suitable for metrics export.
#[derive(Debug, Default)]
pub struct RouteMetrics {
    /// Number of route races started.
    pub race_started: AtomicU64,
    /// Number of route races skipped (cached winner reused directly).
    pub race_skipped: AtomicU64,
    /// Successful connections via Direct routes.
    pub route_success_direct: AtomicU64,
    /// Successful connections via Bypass routes.
    pub route_success_bypass: AtomicU64,
    /// Successful connections via Native in-process desync routes.
    pub route_success_native: AtomicU64,
    /// Failed connections via Direct routes.
    pub route_failure_direct: AtomicU64,
    /// Failed connections via Bypass routes.
    pub route_failure_bypass: AtomicU64,
    /// Failed connections via Native in-process desync routes.
    pub route_failure_native: AtomicU64,
}

/// Consolidated process-wide routing state.
///
/// All per-destination and per-route maps live here.  Access via [`routing_state()`]
/// which initialises the singleton on first call.
pub struct RoutingState {
    /// Per-destination failure counters (capped at 8).
    pub dest_failures: DashMap<String, u8>,
    /// Per-destination classifier state (signals, winner, stage).
    pub dest_classifier: DashMap<String, DestinationClassifier>,
    /// Per-destination preferred relay stage index.
    pub dest_preferred_stage: DashMap<String, u8>,
    /// Per-destination active bypass profile index (rotates on failure).
    pub dest_bypass_profile_idx: DashMap<String, u8>,
    /// Per-destination bypass profile failure counters.
    pub dest_bypass_profile_failures: DashMap<String, u8>,
    /// Per-destination route winner cache.
    pub dest_route_winner: DashMap<String, RouteWinner>,
    /// Per-destination, per-route health counters.
    pub dest_route_health: DashMap<String, DashMap<String, RouteHealth>>,
    /// Global health counters for each bypass/native profile across all destinations.
    pub global_bypass_profile_health: DashMap<String, BypassProfileHealth>,
    /// Global route capability availability (per kind + family).
    pub route_capabilities: RwLock<RouteCapabilities>,
    /// Aggregate routing metrics for the lifetime of the process.
    pub route_metrics: RouteMetrics,
}

impl RoutingState {
    fn new() -> Self {
        Self {
            dest_failures: DashMap::new(),
            dest_classifier: DashMap::new(),
            dest_preferred_stage: DashMap::new(),
            dest_bypass_profile_idx: DashMap::new(),
            dest_bypass_profile_failures: DashMap::new(),
            dest_route_winner: DashMap::new(),
            dest_route_health: DashMap::new(),
            global_bypass_profile_health: DashMap::new(),
            route_capabilities: RwLock::new(RouteCapabilities::default()),
            route_metrics: RouteMetrics::default(),
        }
    }

    /// Clear all maps — call this in tests to prevent state leak between test cases.
    #[cfg(test)]
    pub fn reset(&self) {
        self.dest_failures.clear();
        self.dest_classifier.clear();
        self.dest_preferred_stage.clear();
        self.dest_bypass_profile_idx.clear();
        self.dest_bypass_profile_failures.clear();
        self.dest_route_winner.clear();
        self.dest_route_health.clear();
        self.global_bypass_profile_health.clear();
        if let Ok(mut g) = self.route_capabilities.write() {
            *g = RouteCapabilities::default();
        }
    }
}

/// A relay configuration together with the stage and how it was selected.
#[derive(Debug, Clone, Default)]
pub struct TunedRelay {
    /// Relay configuration for this connection.
    pub options: RelayOptions,
    /// Active relay stage index.
    pub stage: u8,
    /// How this stage was chosen.
    pub source: StageSelectionSource,
}

// ── Statics ───────────────────────────────────────────────────────────────────

static ROUTING_STATE: OnceLock<RoutingState> = OnceLock::new();

/// Returns the process-wide [`RoutingState`], initialising it on first call.
pub fn routing_state() -> &'static RoutingState {
    ROUTING_STATE.get_or_init(RoutingState::new)
}

/// Optional domain blocklist loaded from a filter file.
pub static BLOCKLIST_DOMAINS: OnceLock<crate::blocklist::DomainBloom> = OnceLock::new();

// ── Submodules ────────────────────────────────────────────────────────────────

pub mod classifier_and_persistence;
pub mod ml_shadow;
pub mod protocol_handlers;
pub mod protocol_socks4;
pub mod protocol_udp;
pub mod relay_and_io_helpers;
pub mod route_connection;
pub mod route_scoring;
pub mod state_and_startup;
pub mod telemetry_bus;

pub use state_and_startup::{
    start_socks5_server, RelayOptions, Socks5ServerGuard, WARNED_SOCKS4_LIMITATIONS,
};
pub use telemetry_bus::{init_telemetry_bus, send_telemetry, TelemetryEvent};

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Returns the current time as seconds since the Unix epoch.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Split `"host:port"` into `(host, port)`, handling IPv6 literals.
pub fn split_host_port_for_connect(target: &str) -> Option<(String, u16)> {
    let mut parts = target.rsplitn(2, ':');
    let port = parts.next()?.parse::<u16>().ok()?;
    let host = parts.next()?.to_owned();
    Some((host, port))
}

/// Parse an optional IPv6-bracketed IP literal like `[::1]` or a plain IPv4 address.
pub fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>().ok()
}

/// Returns `true` if `ip` is a public, routable address (not loopback/private/link-local/etc.).
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

/// Fast non-cryptographic hash of a string; used for sharding and deduplication.
pub fn stable_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}
