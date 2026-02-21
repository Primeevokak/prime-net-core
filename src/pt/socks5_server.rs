use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::Duration;
use tracing::{error, info, warn};

use crate::blocklist::expand_tilde;
use crate::error::{EngineError, Result};
use crate::evasion::{FragmentConfig, FragmentingIo};

use super::{BoxStream, DynOutbound, TargetAddr, TargetEndpoint};

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);
#[cfg(windows)]
static PID_NAME_CACHE: OnceLock<Mutex<HashMap<u32, String>>> = OnceLock::new();
static WARNED_SOCKS4_LIMITATIONS: AtomicBool = AtomicBool::new(false);
static WARNED_SOCKS4_AGGRESSIVE: AtomicBool = AtomicBool::new(false);
static DEST_FAILURES: OnceLock<Mutex<HashMap<String, u8>>> = OnceLock::new();
static DEST_PREFERRED_STAGE: OnceLock<Mutex<HashMap<String, u8>>> = OnceLock::new();
static DEST_CLASSIFIER: OnceLock<Mutex<HashMap<String, DestinationClassifier>>> = OnceLock::new();
static DEST_BYPASS_PROFILE_IDX: OnceLock<Mutex<HashMap<String, u8>>> = OnceLock::new();
static DEST_BYPASS_PROFILE_FAILURES: OnceLock<Mutex<HashMap<String, u8>>> = OnceLock::new();
static GLOBAL_BYPASS_PROFILE_HEALTH: OnceLock<Mutex<HashMap<String, BypassProfileHealth>>> =
    OnceLock::new();
static DEST_ROUTE_WINNER: OnceLock<Mutex<HashMap<String, RouteWinner>>> = OnceLock::new();
static DEST_ROUTE_HEALTH: OnceLock<Mutex<HashMap<String, HashMap<String, RouteHealth>>>> =
    OnceLock::new();
static STAGE_RACE_STATS: OnceLock<Mutex<HashMap<u8, StageRaceStats>>> = OnceLock::new();
static RACE_SOURCE_COUNTERS: OnceLock<Mutex<RaceSourceCounters>> = OnceLock::new();
static ROUTE_METRICS: OnceLock<Mutex<RouteMetrics>> = OnceLock::new();
static LAST_CLASSIFIER_EMIT_UNIX: AtomicU64 = AtomicU64::new(0);
static CLASSIFIER_STORE_CFG: OnceLock<Option<ClassifierStoreConfig>> = OnceLock::new();
static CLASSIFIER_STORE_LOADED: AtomicBool = AtomicBool::new(false);
static CLASSIFIER_STORE_DIRTY: AtomicBool = AtomicBool::new(false);
static CLASSIFIER_STORE_LAST_FLUSH_UNIX: AtomicU64 = AtomicU64::new(0);
const CLASSIFIER_PERSIST_DEBOUNCE_SECS: u64 = 30;
const UDP_POLICY_DISABLE_THRESHOLD: u64 = 6;
const UDP_POLICY_DISABLE_SECS: u64 = 120;
const LEARNED_BYPASS_MIN_FAILURES_DOMAIN: u8 = 2;
const LEARNED_BYPASS_MIN_FAILURES_IP: u8 = 1;
const ROUTE_WINNER_TTL_SECS: u64 = 15 * 60;
const ROUTE_WEAK_BASE_SECS: u64 = 45;
const ROUTE_WEAK_MAX_SECS: u64 = 5 * 60;
const ROUTE_FAILS_BEFORE_WEAK: u8 = 2;
const ROUTE_SOFT_ZERO_REPLY_MIN_C2U: u64 = 256;

#[derive(Debug, Clone)]
pub struct RelayOptions {
    pub fragment_client_hello: bool,
    pub split_at_sni: bool,
    pub client_hello_split_offsets: Vec<usize>,
    pub fragment_size: usize,
    pub fragment_sleep_ms: u64,
    pub fragment_budget_bytes: usize,
    pub stage1_failures: u8,
    pub stage2_failures: u8,
    pub stage3_failures: u8,
    pub stage4_failures: u8,
    pub suspicious_zero_reply_min_c2u: usize,
    pub classifier_emit_interval_secs: u64,
    pub classifier_persist_enabled: bool,
    pub classifier_cache_path: Option<String>,
    pub classifier_entry_ttl_secs: u64,
    pub strategy_race_enabled: bool,
    pub upstream_socks5: Option<SocketAddr>,
    pub bypass_socks5: Option<SocketAddr>,
    pub bypass_socks5_pool: Vec<SocketAddr>,
    pub bypass_domain_check: Option<fn(&str) -> bool>,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            fragment_client_hello: false,
            split_at_sni: true,
            client_hello_split_offsets: vec![1, 5, 40],
            fragment_size: 64,
            fragment_sleep_ms: 0,
            fragment_budget_bytes: 8192,
            stage1_failures: 1,
            stage2_failures: 2,
            stage3_failures: 3,
            stage4_failures: 5,
            suspicious_zero_reply_min_c2u: 700,
            classifier_emit_interval_secs: 15,
            classifier_persist_enabled: true,
            classifier_cache_path: None,
            classifier_entry_ttl_secs: 7 * 24 * 60 * 60,
            strategy_race_enabled: true,
            upstream_socks5: None,
            bypass_socks5: None,
            bypass_socks5_pool: Vec::new(),
            bypass_domain_check: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BlockingSignal {
    Reset,
    Timeout,
    EarlyClose,
    BrokenPipe,
    SuspiciousZeroReply,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct DestinationClassifier {
    failures: u64,
    resets: u64,
    timeouts: u64,
    early_closes: u64,
    broken_pipes: u64,
    suspicious_zero_replies: u64,
    successes: u64,
    #[serde(default)]
    last_seen_unix: u64,
}

#[derive(Debug, Clone)]
struct TunedRelay {
    options: RelayOptions,
    stage: u8,
    source: StageSelectionSource,
}

#[derive(Debug, Clone, Copy)]
enum StageSelectionSource {
    Cache,
    Probe,
    Adaptive,
}

#[derive(Debug, Clone)]
struct ClassifierStoreConfig {
    path: PathBuf,
    entry_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ClassifierSnapshot {
    #[serde(default)]
    version: u8,
    #[serde(default)]
    updated_at_unix: u64,
    #[serde(default)]
    entries: HashMap<String, ClassifierSnapshotEntry>,
    #[serde(default)]
    global_bypass_health: HashMap<String, BypassProfileHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ClassifierSnapshotEntry {
    #[serde(default)]
    failures: u8,
    #[serde(default)]
    preferred_stage: u8,
    #[serde(default)]
    stats: DestinationClassifier,
    #[serde(default)]
    bypass_profile_idx: Option<u8>,
    #[serde(default)]
    bypass_profile_failures: u8,
    #[serde(default)]
    route_winner: Option<RouteWinner>,
    #[serde(default)]
    route_health: HashMap<String, RouteHealth>,
}

#[derive(Debug, Clone, Default)]
struct StageRaceStats {
    successes: u64,
    failures: u64,
}

#[derive(Debug, Clone, Default)]
struct RaceSourceCounters {
    cache: u64,
    probe: u64,
    adaptive: u64,
}

#[derive(Debug, Clone, Default)]
struct RouteMetrics {
    race_started: u64,
    race_skipped: u64,
    race_reason_non_tls: u64,
    race_reason_single_candidate: u64,
    race_reason_no_winner: u64,
    race_reason_empty_winner: u64,
    race_reason_winner_stale: u64,
    race_reason_winner_missing: u64,
    race_reason_winner_weak: u64,
    race_reason_winner_healthy: u64,
    winner_cache_hits: u64,
    winner_cache_misses: u64,
    route_selected_direct: u64,
    route_selected_bypass: u64,
    race_winner_direct: u64,
    race_winner_bypass: u64,
    route_success_direct: u64,
    route_success_bypass: u64,
    route_failure_direct: u64,
    route_failure_bypass: u64,
    route_soft_zero_reply_direct: u64,
    route_soft_zero_reply_bypass: u64,
    connect_failure_direct: u64,
    connect_failure_bypass: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteRaceReason {
    NonTlsPort,
    SingleCandidate,
    NoWinner,
    EmptyWinner,
    WinnerStale,
    WinnerMissingFromCandidates,
    WinnerWeak,
    WinnerHealthy,
}

#[derive(Debug, Clone, Default)]
struct UdpDestinationPolicy {
    sent: u64,
    recv: u64,
    disabled_until_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteKind {
    Direct,
    Bypass,
}

#[derive(Debug, Clone)]
struct RouteCandidate {
    kind: RouteKind,
    source: &'static str,
    bypass_addr: Option<SocketAddr>,
    bypass_profile_idx: u8,
    bypass_profile_total: u8,
}

impl RouteCandidate {
    fn direct(source: &'static str) -> Self {
        Self {
            kind: RouteKind::Direct,
            source,
            bypass_addr: None,
            bypass_profile_idx: 0,
            bypass_profile_total: 1,
        }
    }

    fn bypass(source: &'static str, addr: SocketAddr, profile_idx: u8, profile_total: u8) -> Self {
        Self {
            kind: RouteKind::Bypass,
            source,
            bypass_addr: Some(addr),
            bypass_profile_idx: profile_idx,
            bypass_profile_total: profile_total,
        }
    }

    fn route_id(&self) -> String {
        match self.kind {
            RouteKind::Direct => "direct".to_owned(),
            RouteKind::Bypass => format!("bypass:{}", self.bypass_profile_idx + 1),
        }
    }

    fn route_label(&self) -> &'static str {
        match self.kind {
            RouteKind::Direct => "direct",
            RouteKind::Bypass => "bypass",
        }
    }

    fn kind_rank(&self) -> u8 {
        match self.kind {
            RouteKind::Direct => 0,
            RouteKind::Bypass => 1,
        }
    }
}

struct ConnectedRoute {
    candidate: RouteCandidate,
    stream: BoxStream,
    route_key: String,
    raced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RouteHealth {
    #[serde(default)]
    successes: u64,
    #[serde(default)]
    failures: u64,
    #[serde(default)]
    consecutive_failures: u8,
    #[serde(default)]
    weak_until_unix: u64,
    #[serde(default)]
    last_success_unix: u64,
    #[serde(default)]
    last_failure_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BypassProfileHealth {
    #[serde(default)]
    successes: u64,
    #[serde(default)]
    failures: u64,
    #[serde(default)]
    connect_failures: u64,
    #[serde(default)]
    soft_zero_replies: u64,
    #[serde(default)]
    io_errors: u64,
    #[serde(default)]
    last_success_unix: u64,
    #[serde(default)]
    last_failure_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RouteWinner {
    #[serde(default)]
    route_id: String,
    #[serde(default)]
    updated_at_unix: u64,
}

#[derive(Debug)]
pub struct Socks5ServerGuard {
    listen_addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Socks5ServerGuard {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

impl Drop for Socks5ServerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        maybe_flush_classifier_store(true);
        self.handle.abort();
    }
}

pub async fn start_socks5_server(
    bind: &str,
    outbound: DynOutbound,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<Socks5ServerGuard> {
    init_classifier_store(&relay_opts);
    load_classifier_store_if_needed();
    let listener = TcpListener::bind(bind).await?;
    let listen_addr = listener.local_addr()?;
    info!(target: "socks5", listen_addr = %listen_addr, silent_drop, "SOCKS5 server started");
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let Ok((tcp, peer)) = res else { continue; };
                    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                    let outbound = outbound.clone();
                    let relay_opts = relay_opts.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(conn_id, tcp, peer, listen_addr, outbound, silent_drop, relay_opts).await {
                            error!(target: "socks5", conn_id, peer = %peer, error = %e, "SOCKS5 session failed");
                        }
                    });
                }
            }
        }
    });

    Ok(Socks5ServerGuard {
        listen_addr,
        shutdown_tx: Some(shutdown_tx),
        handle,
    })
}

async fn connect_bypass_upstream(
    conn_id: u64,
    target: &TargetEndpoint,
    target_label: &str,
    bypass_addr: SocketAddr,
    bypass_profile_idx: u8,
    bypass_profile_total: u8,
) -> Result<TcpStream> {
    let connect =
        tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(bypass_addr)).await;
    let mut bypass = match connect {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(
                target: "socks5",
                conn_id,
                destination = %target_label,
                bypass = %bypass_addr,
                error = %e,
                "bypass connect failed"
            );
            record_bypass_profile_failure(
                target_label,
                bypass_profile_idx,
                bypass_profile_total,
                "connect-failed",
            );
            return Err(e.into());
        }
        Err(_) => {
            warn!(
                target: "socks5",
                conn_id,
                destination = %target_label,
                bypass = %bypass_addr,
                "bypass connect timeout"
            );
            record_bypass_profile_failure(
                target_label,
                bypass_profile_idx,
                bypass_profile_total,
                "connect-timeout",
            );
            return Err(EngineError::Internal("bypass connect timeout".to_owned()));
        }
    };
    let _ = bypass.set_nodelay(true);

    bypass.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    bypass.read_exact(&mut method).await?;
    if method[0] != 0x05 || method[1] != 0x00 {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "auth-rejected",
        );
        return Err(EngineError::Internal(format!(
            "bypass socks5 auth rejected: {:02x} {:02x}",
            method[0], method[1]
        )));
    }

    let mut req: Vec<u8> = vec![0x05, 0x01, 0x00];
    match &target.addr {
        TargetAddr::Domain(host) => {
            let b = host.as_bytes();
            if b.len() > 255 {
                return Err(EngineError::Internal("bypass domain too long".to_owned()));
            }
            req.push(0x03);
            req.push(b.len() as u8);
            req.extend_from_slice(b);
        }
        TargetAddr::Ip(std::net::IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port.to_be_bytes());
    bypass.write_all(&req).await?;

    let mut reply_hdr = [0u8; 4];
    bypass.read_exact(&mut reply_hdr).await?;
    if reply_hdr[0] != 0x05 {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "invalid-reply-version",
        );
        return Err(EngineError::Internal(format!(
            "bypass socks5 invalid reply version: 0x{:02x}",
            reply_hdr[0]
        )));
    }
    if reply_hdr[1] != 0x00 {
        record_bypass_profile_failure(
            target_label,
            bypass_profile_idx,
            bypass_profile_total,
            "rep-nonzero",
        );
        return Err(EngineError::Internal(format!(
            "ciadpi rejected connect: REP=0x{:02x}",
            reply_hdr[1]
        )));
    }
    match reply_hdr[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            bypass.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            bypass.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize + 2];
            bypass.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            bypass.read_exact(&mut b).await?;
        }
        other => {
            return Err(EngineError::Internal(format!(
                "bypass invalid addr type: 0x{other:02x}"
            )));
        }
    }
    Ok(bypass)
}

async fn connect_route_candidate(
    conn_id: u64,
    outbound: DynOutbound,
    target: TargetEndpoint,
    destination: String,
    candidate: RouteCandidate,
) -> Result<BoxStream> {
    match candidate.kind {
        RouteKind::Direct => outbound.connect(target).await,
        RouteKind::Bypass => {
            let bypass_addr = candidate.bypass_addr.ok_or_else(|| {
                EngineError::Internal("bypass candidate is missing address".to_owned())
            })?;
            let stream = connect_bypass_upstream(
                conn_id,
                &target,
                &destination,
                bypass_addr,
                candidate.bypass_profile_idx,
                candidate.bypass_profile_total,
            )
            .await?;
            Ok(Box::new(stream))
        }
    }
}

async fn connect_via_best_route(
    conn_id: u64,
    outbound: DynOutbound,
    relay_opts: &RelayOptions,
    target_endpoint: &TargetEndpoint,
    destination: &str,
) -> Result<ConnectedRoute> {
    let route_key = route_decision_key(destination);
    let candidates = select_route_candidates(
        relay_opts,
        &target_endpoint.addr,
        target_endpoint.port,
        destination,
    );
    let ordered = ordered_route_candidates(&route_key, candidates);
    let (race, race_reason) = route_race_decision(target_endpoint.port, &route_key, &ordered);
    record_route_race_decision(race, race_reason);

    if race {
        info!(
            target: "socks5.route",
            destination = %destination,
            route_key = %route_key,
            candidates = ordered.len(),
            reason = route_race_reason_label(race_reason),
            "adaptive route race started"
        );
        let mut set = JoinSet::new();
        for (idx, candidate) in ordered.iter().cloned().enumerate() {
            let outbound = outbound.clone();
            let target = target_endpoint.clone();
            let destination = destination.to_owned();
            set.spawn(async move {
                if idx > 0 {
                    tokio::time::sleep(Duration::from_millis((idx as u64) * 75)).await;
                }
                let started = Instant::now();
                let res = connect_route_candidate(conn_id, outbound, target, destination, candidate.clone()).await;
                (candidate, started.elapsed().as_millis(), res)
            });
        }
        let mut last_error: Option<EngineError> = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((candidate, elapsed_ms, Ok(stream))) => {
                    set.abort_all();
                    info!(
                        target: "socks5.route",
                        destination = %destination,
                        route_key = %route_key,
                        route = %candidate.route_id(),
                        source = candidate.source,
                        elapsed_ms,
                        "adaptive route race winner selected"
                    );
                    record_route_selected(&candidate, true);
                    return Ok(ConnectedRoute {
                        candidate,
                        stream,
                        route_key,
                        raced: true,
                    });
                }
                Ok((candidate, _, Err(e))) => {
                    record_route_failure(&route_key, &candidate, "connect-failed");
                    last_error = Some(e);
                }
                Err(e) => {
                    last_error = Some(EngineError::Internal(format!(
                        "route race task join error: {e}"
                    )));
                }
            }
        }
        return Err(last_error.unwrap_or_else(|| {
            EngineError::Internal("adaptive route race: no route candidates succeeded".to_owned())
        }));
    }

    let mut last_error: Option<EngineError> = None;
    for candidate in ordered {
        match connect_route_candidate(
            conn_id,
            outbound.clone(),
            target_endpoint.clone(),
            destination.to_owned(),
            candidate.clone(),
        )
        .await
        {
            Ok(stream) => {
                record_route_selected(&candidate, false);
                return Ok(ConnectedRoute {
                    candidate,
                    stream,
                    route_key,
                    raced: false,
                });
            }
            Err(e) => {
                record_route_failure(&route_key, &candidate, "connect-failed");
                last_error = Some(e);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        EngineError::Internal("failed to connect via all route candidates".to_owned())
    }))
}

async fn handle_client(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    listen_addr: SocketAddr,
    outbound: DynOutbound,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    let client = resolve_client_label(peer, listen_addr).await;
    info!(target: "socks5", conn_id, client = %client, peer = %peer, "SOCKS5 client accepted");
    let _ = tcp.set_nodelay(true);

    // Приветствие SOCKS5: VER, NMETHODS, METHODS...
    let mut hdr = [0u8; 2];
    if tcp.read_exact(&mut hdr).await.is_err() {
        info!(target: "socks5", conn_id, peer = %peer, client = %client, "client disconnected before protocol negotiation");
        return Ok(());
    }
    if hdr[0] != 0x05 {
        if hdr[0] == 0x04 {
            info!(target: "socks5", conn_id, peer = %peer, client = %client, "SOCKS4/4a protocol detected");
            return handle_socks4(
                conn_id,
                tcp,
                peer,
                client,
                outbound,
                hdr[1],
                silent_drop,
                relay_opts,
            )
            .await;
        }
        if hdr[0].is_ascii_alphabetic() {
            info!(target: "socks5", conn_id, peer = %peer, client = %client, "HTTP proxy protocol detected on SOCKS port");
            return handle_http_proxy(conn_id, tcp, peer, client, outbound, hdr, relay_opts).await;
        }
        warn!(target: "socks5", conn_id, peer = %peer, client = %client, version = hdr[0], "SOCKS5 invalid greeting version");
        return silent_or_err(&mut tcp, silent_drop, "SOCKS5 invalid version").await;
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if tcp.read_exact(&mut methods).await.is_err() {
        warn!(target: "socks5", conn_id, peer = %peer, client = %client, "SOCKS5 client disconnected during method negotiation");
        return Ok(());
    }
    if !methods.contains(&0x00) {
        warn!(target: "socks5", conn_id, peer = %peer, client = %client, "SOCKS5 auth method mismatch: no no-auth method");
        if !silent_drop {
            let _ = tcp.write_all(&[0x05, 0xff]).await;
            let _ = tcp.shutdown().await;
        }
        return Ok(());
    }
    tcp.write_all(&[0x05, 0x00]).await?;

    // Запрос SOCKS5: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
    let mut rh = [0u8; 4];
    tcp.read_exact(&mut rh).await?;
    if rh[0] != 0x05 {
        warn!(target: "socks5", conn_id, peer = %peer, client = %client, version = rh[0], "SOCKS5 invalid request version");
        return silent_or_err(&mut tcp, silent_drop, "SOCKS5 invalid request version").await;
    }
    if rh[1] != 0x01 && rh[1] != 0x03 {
        warn!(target: "socks5", conn_id, peer = %peer, client = %client, cmd = rh[1], "SOCKS5 unsupported command");
        if !silent_drop {
            let _ = tcp
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            let _ = tcp.shutdown().await;
        }
        return Ok(());
    }

    let atyp = rh[3];
    let dst = read_socks_target_addr(&mut tcp, atyp).await?;

    let mut pb = [0u8; 2];
    tcp.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);
    let target = format_target(&dst, port);

    if rh[1] == 0x03 {
        info!(target: "socks5", conn_id, peer = %peer, client = %client, bind_hint = %target, "SOCKS5 UDP ASSOCIATE requested");
        return handle_socks5_udp_associate(conn_id, tcp, peer, client, dst, port, silent_drop)
            .await;
    }
    info!(target: "socks5", conn_id, peer = %peer, client = %client, destination = %target, "SOCKS5 CONNECT requested");
    let target_endpoint = TargetEndpoint { addr: dst, port };
    let mut connected = match connect_via_best_route(
        conn_id,
        outbound.clone(),
        &relay_opts,
        &target_endpoint,
        &target,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            if !silent_drop {
                let _ = tcp
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let _ = tcp.shutdown().await;
            }
            return Err(e);
        }
    };
    if connected.candidate.kind == RouteKind::Bypass {
        info!(
            target: "socks5",
            conn_id,
            peer = %peer,
            client = %client,
            destination = %target,
            route = connected.candidate.route_label(),
            source = connected.candidate.source,
            bypass = ?connected.candidate.bypass_addr,
            bypass_profile = connected.candidate.bypass_profile_idx + 1,
            bypass_profiles = connected.candidate.bypass_profile_total,
            raced = connected.raced,
            "SOCKS5 CONNECT route selected"
        );
    } else {
        info!(
            target: "socks5",
            conn_id,
            peer = %peer,
            client = %client,
            destination = %target,
            route = connected.candidate.route_label(),
            source = connected.candidate.source,
            raced = connected.raced,
            "SOCKS5 CONNECT route selected"
        );
    }

    // Ответ SOCKS5: успех, BND=0.0.0.0:0
    tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    if connected.candidate.kind == RouteKind::Bypass {
        info!(
            target: "socks5",
            conn_id,
            destination = %target,
            bypass = ?connected.candidate.bypass_addr,
            bypass_profile = connected.candidate.bypass_profile_idx + 1,
            bypass_profiles = connected.candidate.bypass_profile_total,
            "bypass tunnel established"
        );
        match tokio::io::copy_bidirectional(&mut tcp, &mut connected.stream).await {
            Ok((c2u, u2c)) => {
                info!(
                    target: "socks5",
                    conn_id,
                    destination = %target,
                    bytes_client_to_bypass = c2u,
                    bytes_bypass_to_client = u2c,
                    bypass_profile = connected.candidate.bypass_profile_idx + 1,
                    bypass_profiles = connected.candidate.bypass_profile_total,
                    "bypass tunnel closed"
                );
                if should_mark_bypass_profile_failure(
                    port,
                    c2u,
                    u2c,
                    relay_opts.suspicious_zero_reply_min_c2u as u64,
                ) {
                    record_bypass_profile_failure(
                        &target,
                        connected.candidate.bypass_profile_idx,
                        connected.candidate.bypass_profile_total,
                        "suspicious-zero-reply",
                    );
                    record_route_failure(
                        &connected.route_key,
                        &connected.candidate,
                        "suspicious-zero-reply",
                    );
                    warn!(
                        target: "socks5",
                        conn_id,
                        destination = %target,
                        bytes_client_to_bypass = c2u,
                        bytes_bypass_to_client = u2c,
                        bypass_profile = connected.candidate.bypass_profile_idx + 1,
                        bypass_profiles = connected.candidate.bypass_profile_total,
                        "bypass profile marked as weak for destination"
                    );
                } else if should_mark_route_soft_zero_reply(port, c2u, u2c) {
                    record_route_failure(&connected.route_key, &connected.candidate, "zero-reply-soft");
                    warn!(
                        target: "socks5.route",
                        conn_id,
                        route_key = %connected.route_key,
                        route = connected.candidate.route_label(),
                        destination = %target,
                        bytes_client_to_bypass = c2u,
                        bytes_bypass_to_client = u2c,
                        "adaptive route observed soft zero-reply; winner confidence reduced"
                    );
                } else {
                    record_bypass_profile_success(&target, connected.candidate.bypass_profile_idx);
                    record_route_success(&connected.route_key, &connected.candidate);
                }
            }
            Err(e) if is_expected_disconnect(&e) => {
                let _ = e;
            }
            Err(e) => {
                warn!(
                    target: "socks5",
                    conn_id,
                    destination = %target,
                    error = %e,
                    "bypass tunnel error"
                );
                record_bypass_profile_failure(
                    &target,
                    connected.candidate.bypass_profile_idx,
                    connected.candidate.bypass_profile_total,
                    "io-error",
                );
                record_route_failure(&connected.route_key, &connected.candidate, "io-error");
            }
        }
        return Ok(());
    }

    let tuned = tune_relay_for_target(relay_opts, port, &target, false);
    match relay_bidirectional(&mut tcp, &mut connected.stream, tuned.options.clone()).await {
        Ok((bytes_client_to_upstream, bytes_upstream_to_client)) => {
            if should_mark_suspicious_zero_reply(
                port,
                bytes_client_to_upstream,
                bytes_upstream_to_client,
                tuned.options.suspicious_zero_reply_min_c2u,
            ) {
                record_destination_failure(
                    &target,
                    BlockingSignal::SuspiciousZeroReply,
                    tuned.options.classifier_emit_interval_secs,
                    tuned.stage,
                );
                warn!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %target,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                    "SOCKS5 suspicious early close (no upstream bytes) classified as potential blocking"
                );
                record_route_failure(
                    &connected.route_key,
                    &connected.candidate,
                    "suspicious-zero-reply",
                );
            } else if should_mark_route_soft_zero_reply(
                port,
                bytes_client_to_upstream,
                bytes_upstream_to_client,
            ) {
                record_route_failure(&connected.route_key, &connected.candidate, "zero-reply-soft");
                warn!(
                    target: "socks5.route",
                    conn_id,
                    route_key = %connected.route_key,
                    route = connected.candidate.route_label(),
                    destination = %target,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                    "adaptive route observed soft zero-reply; winner confidence reduced"
                );
            } else {
                record_destination_success(&target, tuned.stage, tuned.source);
                record_route_success(&connected.route_key, &connected.candidate);
            }
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %target,
                bytes_client_to_upstream,
                bytes_upstream_to_client,
                "SOCKS5 session closed"
            );
        }
        Err(e) => {
            let signal = classify_io_error(&e);
            record_destination_failure(
                &target,
                signal,
                tuned.options.classifier_emit_interval_secs,
                tuned.stage,
            );
            record_route_failure(
                &connected.route_key,
                &connected.candidate,
                blocking_signal_label(signal),
            );
            if is_expected_disconnect(&e) {
                info!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %target,
                    error = %e,
                    "SOCKS5 relay closed by peer"
                );
            } else {
                warn!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %target,
                    error = %e,
                    "SOCKS5 relay interrupted"
                );
            }
        }
    }
    Ok(())
}

async fn silent_or_err(tcp: &mut TcpStream, silent_drop: bool, msg: &str) -> Result<()> {
    if silent_drop {
        // Делаем тихий разрыв на невалидном handshake (снижение заметности для active probing).
        let _ = tcp.shutdown().await;
        return Ok(());
    }
    Err(EngineError::InvalidInput(msg.to_owned()))
}

async fn handle_http_proxy(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    client: String,
    outbound: DynOutbound,
    first_two: [u8; 2],
    relay_opts: RelayOptions,
) -> Result<()> {
    let mut buf = Vec::with_capacity(2048);
    buf.extend_from_slice(&first_two);
    let mut tmp = [0u8; 512];
    loop {
        if find_http_header_end(&buf).is_some() {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(EngineError::InvalidInput(
                "HTTP proxy request header too large".to_owned(),
            ));
        }
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let Some(header_end) = find_http_header_end(&buf) else {
        return Err(EngineError::InvalidInput(
            "HTTP proxy request header terminator is missing".to_owned(),
        ));
    };
    let header_bytes = &buf[..header_end];
    let buffered_body = &buf[header_end..];

    let request = String::from_utf8_lossy(header_bytes);
    let Some(first_line) = request.lines().next() else {
        return Err(EngineError::InvalidInput(
            "HTTP proxy request is empty".to_owned(),
        ));
    };
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method == "CONNECT" {
        let Some((host, port)) = split_host_port_for_connect(target) else {
            warn!(target: "socks5", conn_id, peer = %peer, client = %client, target = %target, "HTTP CONNECT target is invalid");
            let _ = tcp
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            let _ = tcp.shutdown().await;
            return Ok(());
        };

        let target_addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            TargetAddr::Ip(ip)
        } else {
            TargetAddr::Domain(host.clone())
        };
        let destination = format!("{host}:{port}");
        let target_endpoint = TargetEndpoint {
            addr: target_addr,
            port,
        };
        info!(target: "socks5", conn_id, peer = %peer, client = %client, destination = %destination, "HTTP CONNECT requested");

        let mut connected = match connect_via_best_route(
            conn_id,
            outbound.clone(),
            &relay_opts,
            &target_endpoint,
            &destination,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(target: "socks5", conn_id, peer = %peer, client = %client, destination = %destination, error = %e, "HTTP CONNECT upstream failed");
                let _ = tcp
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = tcp.shutdown().await;
                return Ok(());
            }
        };
        if connected.candidate.kind == RouteKind::Bypass {
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %destination,
                route = connected.candidate.route_label(),
                source = connected.candidate.source,
                bypass = ?connected.candidate.bypass_addr,
                bypass_profile = connected.candidate.bypass_profile_idx + 1,
                bypass_profiles = connected.candidate.bypass_profile_total,
                raced = connected.raced,
                "HTTP CONNECT route selected"
            );
        } else {
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %destination,
                route = connected.candidate.route_label(),
                source = connected.candidate.source,
                raced = connected.raced,
                "HTTP CONNECT route selected"
            );
        }

        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        if connected.candidate.kind == RouteKind::Bypass {
            info!(
                target: "socks5",
                conn_id,
                destination = %destination,
                bypass = ?connected.candidate.bypass_addr,
                bypass_profile = connected.candidate.bypass_profile_idx + 1,
                bypass_profiles = connected.candidate.bypass_profile_total,
                "bypass tunnel established"
            );
            match tokio::io::copy_bidirectional(&mut tcp, &mut connected.stream).await {
                Ok((c2u, u2c)) => {
                    info!(
                        target: "socks5",
                        conn_id,
                        destination = %destination,
                        bytes_client_to_bypass = c2u,
                        bytes_bypass_to_client = u2c,
                        bypass_profile = connected.candidate.bypass_profile_idx + 1,
                        bypass_profiles = connected.candidate.bypass_profile_total,
                        "bypass tunnel closed"
                    );
                    if should_mark_bypass_profile_failure(
                        port,
                        c2u,
                        u2c,
                        relay_opts.suspicious_zero_reply_min_c2u as u64,
                    ) {
                        record_bypass_profile_failure(
                            &destination,
                            connected.candidate.bypass_profile_idx,
                            connected.candidate.bypass_profile_total,
                            "suspicious-zero-reply",
                        );
                        record_route_failure(
                            &connected.route_key,
                            &connected.candidate,
                            "suspicious-zero-reply",
                        );
                        warn!(
                            target: "socks5",
                            conn_id,
                            destination = %destination,
                            bytes_client_to_bypass = c2u,
                            bytes_bypass_to_client = u2c,
                            bypass_profile = connected.candidate.bypass_profile_idx + 1,
                            bypass_profiles = connected.candidate.bypass_profile_total,
                            "bypass profile marked as weak for destination"
                        );
                    } else if should_mark_route_soft_zero_reply(port, c2u, u2c) {
                        record_route_failure(
                            &connected.route_key,
                            &connected.candidate,
                            "zero-reply-soft",
                        );
                        warn!(
                            target: "socks5.route",
                            conn_id,
                            route_key = %connected.route_key,
                            route = connected.candidate.route_label(),
                            destination = %destination,
                            bytes_client_to_bypass = c2u,
                            bytes_bypass_to_client = u2c,
                            "adaptive route observed soft zero-reply; winner confidence reduced"
                        );
                    } else {
                        record_bypass_profile_success(
                            &destination,
                            connected.candidate.bypass_profile_idx,
                        );
                        record_route_success(&connected.route_key, &connected.candidate);
                    }
                }
                Err(e) if is_expected_disconnect(&e) => {
                    let _ = e;
                }
                Err(e) => {
                    warn!(
                        target: "socks5",
                        conn_id,
                        destination = %destination,
                        error = %e,
                        "bypass tunnel error"
                    );
                    record_bypass_profile_failure(
                        &destination,
                        connected.candidate.bypass_profile_idx,
                        connected.candidate.bypass_profile_total,
                        "io-error",
                    );
                    record_route_failure(&connected.route_key, &connected.candidate, "io-error");
                }
            }
            return Ok(());
        }

        let tuned = tune_relay_for_target(relay_opts, port, &destination, false);
        match relay_bidirectional(&mut tcp, &mut connected.stream, tuned.options.clone()).await {
            Ok((bytes_client_to_upstream, bytes_upstream_to_client)) => {
                if should_mark_suspicious_zero_reply(
                    port,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                    tuned.options.suspicious_zero_reply_min_c2u,
                ) {
                    record_destination_failure(
                        &destination,
                        BlockingSignal::SuspiciousZeroReply,
                        tuned.options.classifier_emit_interval_secs,
                        tuned.stage,
                    );
                    warn!(
                        target: "socks5",
                        conn_id,
                        peer = %peer,
                        client = %client,
                        destination = %destination,
                        bytes_client_to_upstream,
                        bytes_upstream_to_client,
                        "HTTP CONNECT suspicious early close (no upstream bytes) classified as potential blocking"
                    );
                    record_route_failure(
                        &connected.route_key,
                        &connected.candidate,
                        "suspicious-zero-reply",
                    );
                } else if should_mark_route_soft_zero_reply(
                    port,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                ) {
                    record_route_failure(
                        &connected.route_key,
                        &connected.candidate,
                        "zero-reply-soft",
                    );
                    warn!(
                        target: "socks5.route",
                        conn_id,
                        route_key = %connected.route_key,
                        route = connected.candidate.route_label(),
                        destination = %destination,
                        bytes_client_to_upstream,
                        bytes_upstream_to_client,
                        "adaptive route observed soft zero-reply; winner confidence reduced"
                    );
                } else {
                    record_destination_success(&destination, tuned.stage, tuned.source);
                    record_route_success(&connected.route_key, &connected.candidate);
                }
                info!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                    "HTTP CONNECT session closed"
                );
            }
            Err(e) => {
                let signal = classify_io_error(&e);
                record_destination_failure(
                    &destination,
                    signal,
                    tuned.options.classifier_emit_interval_secs,
                    tuned.stage,
                );
                record_route_failure(
                    &connected.route_key,
                    &connected.candidate,
                    blocking_signal_label(signal),
                );
                if is_expected_disconnect(&e) {
                    info!(
                        target: "socks5",
                        conn_id,
                        peer = %peer,
                        client = %client,
                        destination = %destination,
                        error = %e,
                        "HTTP CONNECT relay closed by peer"
                    );
                } else {
                    warn!(
                        target: "socks5",
                        conn_id,
                        peer = %peer,
                        client = %client,
                        destination = %destination,
                        error = %e,
                        "HTTP CONNECT relay interrupted"
                    );
                }
            }
        }
        return Ok(());
    }

    let Some(parsed) = parse_http_forward_target(target, request.as_ref()) else {
        warn!(target: "socks5", conn_id, peer = %peer, client = %client, method = %method, target = %target, "HTTP proxy target is invalid");
        let _ = tcp
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        let _ = tcp.shutdown().await;
        return Ok(());
    };
    let destination = format!("{}:{}", parsed.host, parsed.port);
    info!(target: "socks5", conn_id, peer = %peer, client = %client, method = %method, destination = %destination, "HTTP proxy forward requested");
    info!(
        target: "socks5",
        conn_id,
        peer = %peer,
        client = %client,
        method = %method,
        destination = %destination,
        route = "direct",
        "HTTP proxy forward route selected"
    );

    let target_addr = if let Ok(ip) = parsed.host.parse::<std::net::IpAddr>() {
        TargetAddr::Ip(ip)
    } else {
        TargetAddr::Domain(parsed.host.clone())
    };
    let mut out = match outbound
        .connect(TargetEndpoint {
            addr: target_addr,
            port: parsed.port,
        })
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            warn!(target: "socks5", conn_id, peer = %peer, client = %client, method = %method, destination = %destination, error = %e, "HTTP proxy forward upstream failed");
            let _ = tcp
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            let _ = tcp.shutdown().await;
            return Ok(());
        }
    };

    let upstream_head = rewrite_http_forward_head(
        &method,
        version,
        &parsed.request_uri,
        request.as_ref(),
        &parsed.host,
        parsed.port,
    );
    out.write_all(upstream_head.as_bytes()).await?;
    if !buffered_body.is_empty() {
        out.write_all(buffered_body).await?;
    }

    let tuned = tune_relay_for_target(relay_opts, parsed.port, &destination, false);
    match relay_bidirectional(&mut tcp, &mut out, tuned.options.clone()).await {
        Ok((bytes_client_to_upstream, bytes_upstream_to_client)) => {
            if should_mark_suspicious_zero_reply(
                parsed.port,
                bytes_client_to_upstream,
                bytes_upstream_to_client,
                tuned.options.suspicious_zero_reply_min_c2u,
            ) {
                record_destination_failure(
                    &destination,
                    BlockingSignal::SuspiciousZeroReply,
                    tuned.options.classifier_emit_interval_secs,
                    tuned.stage,
                );
                warn!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                    "HTTP proxy forward suspicious early close (no upstream bytes) classified as potential blocking"
                );
            } else {
                record_destination_success(&destination, tuned.stage, tuned.source);
            }
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %destination,
                bytes_client_to_upstream,
                bytes_upstream_to_client,
                "HTTP proxy forward session closed"
            );
        }
        Err(e) => {
            let signal = classify_io_error(&e);
            record_destination_failure(
                &destination,
                signal,
                tuned.options.classifier_emit_interval_secs,
                tuned.stage,
            );
            if is_expected_disconnect(&e) {
                info!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    method = %method,
                    destination = %destination,
                    error = %e,
                    "HTTP proxy forward relay closed by peer"
                );
            } else {
                warn!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    method = %method,
                    destination = %destination,
                    error = %e,
                    "HTTP proxy forward relay interrupted"
                );
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_socks4(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    client: String,
    outbound: DynOutbound,
    cmd: u8,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    if !WARNED_SOCKS4_LIMITATIONS.swap(true, Ordering::Relaxed) {
        warn!(
            target: "socks5",
            "SOCKS4/4a clients detected: requests often use IP literals, reducing anti-censorship effectiveness (prefer SOCKS5/CONNECT clients when possible)"
        );
    }

    if cmd != 0x01 {
        warn!(target: "socks5", conn_id, peer = %peer, client = %client, cmd, "SOCKS4 unsupported command");
        if !silent_drop {
            let _ = tcp.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
        }
        let _ = tcp.shutdown().await;
        return Ok(());
    }

    let mut port_buf = [0u8; 2];
    tcp.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    let mut ip_buf = [0u8; 4];
    tcp.read_exact(&mut ip_buf).await?;

    let _user_id = read_cstring(&mut tcp, 512).await?;

    let target_addr = if ip_buf[0] == 0 && ip_buf[1] == 0 && ip_buf[2] == 0 && ip_buf[3] != 0 {
        let host = read_cstring(&mut tcp, 2048).await?;
        if host.trim().is_empty() {
            warn!(target: "socks5", conn_id, peer = %peer, client = %client, "SOCKS4a empty host");
            if !silent_drop {
                let _ = tcp.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
            }
            let _ = tcp.shutdown().await;
            return Ok(());
        }
        TargetAddr::Domain(host)
    } else {
        TargetAddr::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip_buf)))
    };

    let destination = format_target(&target_addr, port);
    info!(target: "socks5", conn_id, peer = %peer, client = %client, destination = %destination, "SOCKS4 CONNECT requested");
    let mut out = match outbound
        .connect(TargetEndpoint {
            addr: target_addr,
            port,
        })
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            warn!(target: "socks5", conn_id, peer = %peer, client = %client, destination = %destination, error = %e, "SOCKS4 upstream failed");
            if !silent_drop {
                let _ = tcp.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
            }
            let _ = tcp.shutdown().await;
            return Ok(());
        }
    };

    tcp.write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0]).await?;
    let tuned = tune_relay_for_target(relay_opts, port, &destination, true);
    match relay_bidirectional(&mut tcp, &mut out, tuned.options.clone()).await {
        Ok((bytes_client_to_upstream, bytes_upstream_to_client)) => {
            if should_mark_suspicious_zero_reply(
                port,
                bytes_client_to_upstream,
                bytes_upstream_to_client,
                tuned.options.suspicious_zero_reply_min_c2u,
            ) {
                record_destination_failure(
                    &destination,
                    BlockingSignal::SuspiciousZeroReply,
                    tuned.options.classifier_emit_interval_secs,
                    tuned.stage,
                );
                warn!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                    "SOCKS4 suspicious early close (no upstream bytes) classified as potential blocking"
                );
            } else {
                record_destination_success(&destination, tuned.stage, tuned.source);
            }
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %destination,
                bytes_client_to_upstream,
                bytes_upstream_to_client,
                "SOCKS4 session closed"
            );
        }
        Err(e) => {
            let signal = classify_io_error(&e);
            record_destination_failure(
                &destination,
                signal,
                tuned.options.classifier_emit_interval_secs,
                tuned.stage,
            );
            if is_expected_disconnect(&e) {
                info!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    error = %e,
                    "SOCKS4 relay closed by peer"
                );
            } else {
                warn!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    error = %e,
                    "SOCKS4 relay interrupted"
                );
            }
        }
    }
    Ok(())
}

fn tune_relay_for_target(
    base: RelayOptions,
    port: u16,
    destination: &str,
    socks4_flow: bool,
) -> TunedRelay {
    if !base.fragment_client_hello {
        return TunedRelay {
            options: base,
            stage: 0,
            source: StageSelectionSource::Adaptive,
        };
    }
    if port != 443 {
        return TunedRelay {
            options: base,
            stage: 0,
            source: StageSelectionSource::Adaptive,
        };
    }
    let mut stage = if socks4_flow { 1u8 } else { 0u8 };
    let preferred = destination_preferred_stage(destination);
    let mut source = StageSelectionSource::Adaptive;
    if preferred > 0 {
        stage = stage.max(preferred);
        source = StageSelectionSource::Cache;
    }
    let failures = destination_failures(destination);
    if preferred == 0 && failures == 0 && base.strategy_race_enabled && !socks4_flow {
        stage = select_race_probe_stage(destination);
        source = StageSelectionSource::Probe;
    }
    if failures >= base.stage1_failures {
        stage += 1;
    }
    if failures >= base.stage2_failures {
        stage += 1;
    }
    if failures >= base.stage3_failures {
        stage += 1;
    }
    if failures >= base.stage4_failures {
        stage += 1;
    }
    stage = stage.min(4);

    if socks4_flow && !WARNED_SOCKS4_AGGRESSIVE.swap(true, Ordering::Relaxed) {
        info!(
            target: "socks5",
            "SOCKS4 aggressive DPI profile enabled for :443 (adaptive stage escalation is active)"
        );
    }

    let tuned = match stage {
        0 => base,
        1 => RelayOptions {
            fragment_client_hello: true,
            // Более крупные фрагменты с минимальной паузой: безопасный базовый профиль без долгих задержек handshake.
            fragment_size: base.fragment_size.clamp(1, 24),
            fragment_sleep_ms: base.fragment_sleep_ms.min(2),
            fragment_budget_bytes: base.fragment_budget_bytes.clamp(2 * 1024, 6 * 1024),
            ..base
        },
        2 => RelayOptions {
            fragment_client_hello: true,
            fragment_size: base.fragment_size.clamp(1, 8),
            fragment_sleep_ms: base.fragment_sleep_ms.min(1),
            fragment_budget_bytes: base.fragment_budget_bytes.clamp(4 * 1024, 8 * 1024),
            client_hello_split_offsets: vec![1, 5, 40],
            ..base
        },
        3 => RelayOptions {
            fragment_client_hello: true,
            fragment_size: base.fragment_size.clamp(1, 4),
            fragment_sleep_ms: 0,
            fragment_budget_bytes: base.fragment_budget_bytes.clamp(6 * 1024, 12 * 1024),
            client_hello_split_offsets: vec![1, 5, 40, 64],
            ..base
        },
        _ => RelayOptions {
            fragment_client_hello: true,
            fragment_size: base.fragment_size.clamp(1, 2),
            fragment_sleep_ms: 0,
            fragment_budget_bytes: base.fragment_budget_bytes.clamp(8 * 1024, 16 * 1024),
            client_hello_split_offsets: vec![1, 5, 40, 64],
            ..base
        },
    };
    if stage > 0 {
        info!(
            target: "socks5",
            destination = %destination,
            stage,
            source = ?source,
            fragment_size = tuned.fragment_size,
            fragment_sleep_ms = tuned.fragment_sleep_ms,
            fragment_budget_bytes = tuned.fragment_budget_bytes,
            "adaptive DPI relay profile selected"
        );
    }
    record_stage_source_selected(source);
    TunedRelay {
        options: tuned,
        stage,
        source,
    }
}

fn route_decision_key(destination: &str) -> String {
    bypass_profile_key(destination)
}

fn should_enable_universal_bypass_domain(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host == "localhost" || host.ends_with(".local") {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    host.contains('.')
}

fn select_bypass_source(
    relay_opts: &RelayOptions,
    target: &TargetAddr,
    port: u16,
) -> Option<&'static str> {
    if port != 443 {
        return None;
    }
    match target {
        TargetAddr::Domain(host) => {
            if let Some(check_fn) = relay_opts.bypass_domain_check {
                if check_fn(host) {
                    return Some("builtin");
                }
            }
            if should_bypass_by_classifier_host(host, port) {
                return Some("learned-domain");
            }
            if should_enable_universal_bypass_domain(host) {
                return Some("adaptive-race");
            }
            None
        }
        TargetAddr::Ip(ip) => {
            if should_bypass_by_classifier_ip(*ip, port) {
                return Some("learned-ip");
            }
            if is_bypassable_public_ip(*ip) {
                return Some("adaptive-race");
            }
            None
        }
    }
}

fn select_bypass_candidates(relay_opts: &RelayOptions, destination: &str) -> Vec<(SocketAddr, u8, u8)> {
    if !relay_opts.bypass_socks5_pool.is_empty() {
        let total = relay_opts.bypass_socks5_pool.len().min(255) as u8;
        let preferred = destination_bypass_profile_idx(destination, total);
        let mut out = Vec::with_capacity(total as usize);
        for offset in 0..total {
            let idx = (preferred + offset) % total;
            out.push((relay_opts.bypass_socks5_pool[idx as usize], idx, total));
        }
        return out;
    }
    relay_opts
        .bypass_socks5
        .map(|addr| vec![(addr, 0, 1)])
        .unwrap_or_default()
}

fn select_route_candidates(
    relay_opts: &RelayOptions,
    target: &TargetAddr,
    port: u16,
    destination: &str,
) -> Vec<RouteCandidate> {
    let mut out = vec![RouteCandidate::direct("adaptive")];
    let Some(source) = select_bypass_source(relay_opts, target, port) else {
        return out;
    };
    for (addr, idx, total) in select_bypass_candidates(relay_opts, destination) {
        out.push(RouteCandidate::bypass(source, addr, idx, total));
    }
    out
}

fn route_health_score(route_key: &str, route_id: &str, now: u64) -> i64 {
    let local_score = {
        let map = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
        let Ok(guard) = map.lock() else {
            return global_bypass_profile_score(route_id, now);
        };
        let Some(per_route) = guard.get(route_key) else {
            return global_bypass_profile_score(route_id, now);
        };
        let Some(health) = per_route.get(route_id) else {
            return global_bypass_profile_score(route_id, now);
        };
        let mut score = (health.successes as i64 * 3) - (health.failures as i64 * 4);
        score -= i64::from(health.consecutive_failures) * 8;
        if health.weak_until_unix > now {
            score -= 10_000;
        }
        score
    };
    local_score + global_bypass_profile_score(route_id, now)
}

fn bypass_profile_health_last_seen_unix(health: &BypassProfileHealth) -> u64 {
    health.last_success_unix.max(health.last_failure_unix)
}

fn bypass_profile_health_is_empty(health: &BypassProfileHealth) -> bool {
    health.successes == 0
        && health.failures == 0
        && health.connect_failures == 0
        && health.soft_zero_replies == 0
        && health.io_errors == 0
        && health.last_success_unix == 0
        && health.last_failure_unix == 0
}

fn global_bypass_profile_score(route_id: &str, now: u64) -> i64 {
    if !route_id.starts_with("bypass:") {
        return 0;
    }
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return 0;
    };
    let Some(health) = guard.get(route_id) else {
        return 0;
    };
    bypass_profile_score_from_health(health, now)
}

fn bypass_profile_score_from_health(health: &BypassProfileHealth, now: u64) -> i64 {
    let mut score = (health.successes as i64 * 5) - (health.failures as i64 * 6);
    score -= health.connect_failures as i64 * 8;
    score -= health.soft_zero_replies as i64 * 10;
    score -= health.io_errors as i64 * 7;
    if health.last_success_unix > 0 && now.saturating_sub(health.last_success_unix) <= 5 * 60 {
        score += 3;
    }
    if health.last_failure_unix > 0 && now.saturating_sub(health.last_failure_unix) <= 90 {
        score -= 4;
    }
    score
}

fn route_is_temporarily_weak(route_key: &str, route_id: &str, now: u64) -> bool {
    let map = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return false;
    };
    guard
        .get(route_key)
        .and_then(|m| m.get(route_id))
        .map(|h| h.weak_until_unix > now)
        .unwrap_or(false)
}

fn route_winner_for_key(route_key: &str) -> Option<RouteWinner> {
    let map = DEST_ROUTE_WINNER.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return None;
    };
    guard.get(route_key).cloned()
}

fn ordered_route_candidates(route_key: &str, candidates: Vec<RouteCandidate>) -> Vec<RouteCandidate> {
    let now = now_unix_secs();
    let winner = route_winner_for_key(route_key);
    let mut filtered: Vec<RouteCandidate> = candidates
        .iter()
        .filter(|c| !route_is_temporarily_weak(route_key, &c.route_id(), now))
        .cloned()
        .collect();
    if filtered.is_empty() {
        filtered = candidates;
    }
    filtered.sort_by(|a, b| {
        let a_id = a.route_id();
        let b_id = b.route_id();
        let a_winner = winner
            .as_ref()
            .map(|w| w.route_id == a_id)
            .unwrap_or(false);
        let b_winner = winner
            .as_ref()
            .map(|w| w.route_id == b_id)
            .unwrap_or(false);
        if a_winner != b_winner {
            return if a_winner {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }
        let a_score = route_health_score(route_key, &a_id, now);
        let b_score = route_health_score(route_key, &b_id, now);
        b_score
            .cmp(&a_score)
            .then_with(|| a.kind_rank().cmp(&b.kind_rank()))
            .then_with(|| a.route_label().cmp(b.route_label()))
    });
    filtered
}

fn route_race_reason_label(reason: RouteRaceReason) -> &'static str {
    match reason {
        RouteRaceReason::NonTlsPort => "non-tls-port",
        RouteRaceReason::SingleCandidate => "single-candidate",
        RouteRaceReason::NoWinner => "no-winner",
        RouteRaceReason::EmptyWinner => "empty-winner",
        RouteRaceReason::WinnerStale => "winner-stale",
        RouteRaceReason::WinnerMissingFromCandidates => "winner-missing-from-candidates",
        RouteRaceReason::WinnerWeak => "winner-weak",
        RouteRaceReason::WinnerHealthy => "winner-healthy",
    }
}

fn route_race_decision(
    port: u16,
    route_key: &str,
    candidates: &[RouteCandidate],
) -> (bool, RouteRaceReason) {
    if port != 443 || candidates.len() < 2 {
        return if port != 443 {
            (false, RouteRaceReason::NonTlsPort)
        } else {
            (false, RouteRaceReason::SingleCandidate)
        };
    }
    let now = now_unix_secs();
    let Some(winner) = route_winner_for_key(route_key) else {
        return (true, RouteRaceReason::NoWinner);
    };
    if winner.route_id.is_empty() {
        return (true, RouteRaceReason::EmptyWinner);
    }
    if now.saturating_sub(winner.updated_at_unix) > ROUTE_WINNER_TTL_SECS {
        return (true, RouteRaceReason::WinnerStale);
    }
    if !candidates.iter().any(|c| c.route_id() == winner.route_id) {
        return (true, RouteRaceReason::WinnerMissingFromCandidates);
    }
    if route_is_temporarily_weak(route_key, &winner.route_id, now) {
        return (true, RouteRaceReason::WinnerWeak);
    }
    (false, RouteRaceReason::WinnerHealthy)
}

fn with_route_metrics<F>(f: F)
where
    F: FnOnce(&mut RouteMetrics),
{
    if let Ok(mut guard) = ROUTE_METRICS
        .get_or_init(|| Mutex::new(RouteMetrics::default()))
        .lock()
    {
        f(&mut guard);
    }
}

fn record_route_race_decision(race: bool, reason: RouteRaceReason) {
    with_route_metrics(|m| {
        if race {
            m.race_started = m.race_started.saturating_add(1);
        } else {
            m.race_skipped = m.race_skipped.saturating_add(1);
        }
        match reason {
            RouteRaceReason::NonTlsPort => m.race_reason_non_tls = m.race_reason_non_tls.saturating_add(1),
            RouteRaceReason::SingleCandidate => {
                m.race_reason_single_candidate = m.race_reason_single_candidate.saturating_add(1)
            }
            RouteRaceReason::NoWinner => {
                m.race_reason_no_winner = m.race_reason_no_winner.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::EmptyWinner => {
                m.race_reason_empty_winner = m.race_reason_empty_winner.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::WinnerStale => {
                m.race_reason_winner_stale = m.race_reason_winner_stale.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::WinnerMissingFromCandidates => {
                m.race_reason_winner_missing = m.race_reason_winner_missing.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::WinnerWeak => {
                m.race_reason_winner_weak = m.race_reason_winner_weak.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::WinnerHealthy => {
                m.race_reason_winner_healthy = m.race_reason_winner_healthy.saturating_add(1);
                m.winner_cache_hits = m.winner_cache_hits.saturating_add(1);
            }
        }
    });
}

fn record_route_selected(candidate: &RouteCandidate, raced: bool) {
    with_route_metrics(|m| match candidate.kind {
        RouteKind::Direct => {
            m.route_selected_direct = m.route_selected_direct.saturating_add(1);
            if raced {
                m.race_winner_direct = m.race_winner_direct.saturating_add(1);
            }
        }
        RouteKind::Bypass => {
            m.route_selected_bypass = m.route_selected_bypass.saturating_add(1);
            if raced {
                m.race_winner_bypass = m.race_winner_bypass.saturating_add(1);
            }
        }
    });
}

fn record_route_success(route_key: &str, candidate: &RouteCandidate) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    with_route_metrics(|m| match candidate.kind {
        RouteKind::Direct => m.route_success_direct = m.route_success_direct.saturating_add(1),
        RouteKind::Bypass => m.route_success_bypass = m.route_success_bypass.saturating_add(1),
    });
    let health_map = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = health_map.lock() {
        let per_route = guard.entry(route_key.to_owned()).or_default();
        let entry = per_route.entry(route_id.clone()).or_default();
        entry.successes = entry.successes.saturating_add(1);
        entry.consecutive_failures = 0;
        entry.weak_until_unix = 0;
        entry.last_success_unix = now;
    }
    let winner_map = DEST_ROUTE_WINNER.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = winner_map.lock() {
        guard.insert(
            route_key.to_owned(),
            RouteWinner {
                route_id: route_id.clone(),
                updated_at_unix: now,
            },
        );
    }
    if matches!(candidate.kind, RouteKind::Bypass) {
        record_global_bypass_profile_success(&route_id, now);
    }
    info!(
        target: "socks5.route",
        route_key = %route_key,
        route = %route_id,
        "adaptive route marked healthy"
    );
    maybe_flush_classifier_store(false);
}

fn record_route_failure(route_key: &str, candidate: &RouteCandidate, reason: &'static str) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    with_route_metrics(|m| {
        match candidate.kind {
            RouteKind::Direct => {
                m.route_failure_direct = m.route_failure_direct.saturating_add(1);
                if reason == "connect-failed" {
                    m.connect_failure_direct = m.connect_failure_direct.saturating_add(1);
                }
                if reason == "zero-reply-soft" {
                    m.route_soft_zero_reply_direct =
                        m.route_soft_zero_reply_direct.saturating_add(1);
                }
            }
            RouteKind::Bypass => {
                m.route_failure_bypass = m.route_failure_bypass.saturating_add(1);
                if reason == "connect-failed" {
                    m.connect_failure_bypass = m.connect_failure_bypass.saturating_add(1);
                }
                if reason == "zero-reply-soft" {
                    m.route_soft_zero_reply_bypass =
                        m.route_soft_zero_reply_bypass.saturating_add(1);
                }
            }
        }
    });
    let health_map = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let mut consecutive = 0u8;
    if let Ok(mut guard) = health_map.lock() {
        let per_route = guard.entry(route_key.to_owned()).or_default();
        let entry = per_route.entry(route_id.clone()).or_default();
        entry.failures = entry.failures.saturating_add(1);
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1).min(32);
        if matches!(reason, "zero-reply-soft" | "suspicious-zero-reply")
            && entry.consecutive_failures < ROUTE_FAILS_BEFORE_WEAK
        {
            entry.consecutive_failures = ROUTE_FAILS_BEFORE_WEAK;
        }
        entry.last_failure_unix = now;
        consecutive = entry.consecutive_failures;
        if entry.consecutive_failures >= ROUTE_FAILS_BEFORE_WEAK {
            let penalty = ROUTE_WEAK_BASE_SECS
                .saturating_mul(u64::from(entry.consecutive_failures))
                .min(ROUTE_WEAK_MAX_SECS);
            entry.weak_until_unix = now.saturating_add(penalty);
        }
    }
    if let Ok(mut guard) = DEST_ROUTE_WINNER.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        if guard
            .get(route_key)
            .map(|w| w.route_id == route_id)
            .unwrap_or(false)
        {
            guard.remove(route_key);
        }
    }
    if matches!(candidate.kind, RouteKind::Bypass) {
        record_global_bypass_profile_failure(&route_id, reason, now);
        if reason == "zero-reply-soft" && candidate.bypass_profile_total > 1 {
            record_bypass_profile_failure(
                route_key,
                candidate.bypass_profile_idx,
                candidate.bypass_profile_total,
                "route-soft-zero-reply",
            );
        }
    }
    warn!(
        target: "socks5.route",
        route_key = %route_key,
        route = %route_id,
        reason,
        consecutive_failures = consecutive,
        "adaptive route marked weak"
    );
    maybe_flush_classifier_store(false);
}

fn record_global_bypass_profile_success(route_id: &str, now: u64) {
    if !route_id.starts_with("bypass:") {
        return;
    }
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        let entry = guard.entry(route_id.to_owned()).or_default();
        entry.successes = entry.successes.saturating_add(1);
        entry.last_success_unix = now;
        if entry.failures > 0 {
            entry.failures = entry.failures.saturating_sub(1);
        }
        if entry.connect_failures > 0 {
            entry.connect_failures = entry.connect_failures.saturating_sub(1);
        }
        if entry.soft_zero_replies > 0 {
            entry.soft_zero_replies = entry.soft_zero_replies.saturating_sub(1);
        }
        if entry.io_errors > 0 {
            entry.io_errors = entry.io_errors.saturating_sub(1);
        }
    }
}

fn record_global_bypass_profile_failure(route_id: &str, reason: &'static str, now: u64) {
    if !route_id.starts_with("bypass:") {
        return;
    }
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        let entry = guard.entry(route_id.to_owned()).or_default();
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure_unix = now;
        if reason == "connect-failed" {
            entry.connect_failures = entry.connect_failures.saturating_add(1);
        }
        if matches!(reason, "zero-reply-soft" | "suspicious-zero-reply") {
            entry.soft_zero_replies = entry.soft_zero_replies.saturating_add(1);
        }
        if reason == "io-error" {
            entry.io_errors = entry.io_errors.saturating_add(1);
        }
    }
}

fn destination_bypass_profile_idx(destination: &str, total: u8) -> u8 {
    if total <= 1 {
        return 0;
    }
    let key = bypass_profile_key(destination);
    let map = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = map.lock() {
        if let Some(v) = guard.get(&key).copied() {
            return v.min(total.saturating_sub(1));
        }
    }
    0
}

fn should_mark_bypass_profile_failure(
    port: u16,
    bytes_client_to_bypass: u64,
    bytes_bypass_to_client: u64,
    min_c2u: u64,
) -> bool {
    port == 443
        && bytes_bypass_to_client == 0
        && bytes_client_to_bypass >= min_c2u
}

fn should_mark_route_soft_zero_reply(
    port: u16,
    bytes_client_to_upstream: u64,
    bytes_upstream_to_client: u64,
) -> bool {
    port == 443
        && bytes_upstream_to_client == 0
        && bytes_client_to_upstream >= ROUTE_SOFT_ZERO_REPLY_MIN_C2U
}

fn record_bypass_profile_failure(
    destination: &str,
    current_idx: u8,
    total: u8,
    reason: &'static str,
) {
    if total == 0 {
        return;
    }
    let key = bypass_profile_key(destination);
    let next_idx = if total > 1 {
        (current_idx + 1) % total
    } else {
        0
    };
    let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = idx_map.lock() {
        guard.insert(key.clone(), next_idx);
    }
    let fail_map = DEST_BYPASS_PROFILE_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let failures = if let Ok(mut guard) = fail_map.lock() {
        let entry = guard.entry(key.clone()).or_insert(0);
        *entry = entry.saturating_add(1).min(255);
        *entry
    } else {
        0
    };
    info!(
        target: "socks5.bypass",
        destination = %destination,
        profile_key = %key,
        reason,
        current_profile = current_idx + 1,
        next_profile = next_idx + 1,
        profiles = total,
        failures,
        "bypass profile rotated for destination"
    );
    maybe_flush_classifier_store(false);
}

fn record_bypass_profile_success(destination: &str, idx: u8) {
    let key = bypass_profile_key(destination);
    let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = idx_map.lock() {
        guard.insert(key.clone(), idx);
    }
    let fail_map = DEST_BYPASS_PROFILE_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = fail_map.lock() {
        if let Some(entry) = guard.get_mut(&key) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                guard.remove(&key);
            }
        }
    }
    maybe_flush_classifier_store(false);
}

fn bypass_profile_key(destination: &str) -> String {
    if let Some((host, port)) = split_host_port_for_connect(destination) {
        let normalized_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if !normalized_host.is_empty() {
            if normalized_host.parse::<std::net::IpAddr>().is_ok() {
                return format!("{normalized_host}:{port}");
            }
            let service_bucket = host_service_bucket(&normalized_host);
            return format!("{service_bucket}:{port}");
        }
    }
    destination.trim().to_ascii_lowercase()
}

fn host_service_bucket(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    if labels.len() < 2 {
        return host.to_owned();
    }
    let tld = labels[labels.len() - 1];
    let sld = labels[labels.len() - 2];
    if labels.len() >= 3
        && tld.len() == 2
        && matches!(sld, "co" | "com" | "net" | "org" | "gov" | "edu" | "ac")
    {
        return labels[labels.len() - 3].to_owned();
    }
    sld.to_owned()
}

fn should_bypass_by_classifier_host(host: &str, port: u16) -> bool {
    if port != 443 {
        return false;
    }
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return should_bypass_by_classifier_ip(ip, port);
    }

    let key = format!("{host}:{port}");
    if destination_failures(&key) >= LEARNED_BYPASS_MIN_FAILURES_DOMAIN {
        return true;
    }

    let host_lower = host.to_ascii_lowercase();
    if host_lower != host {
        let key_lower = format!("{host_lower}:{port}");
        if destination_failures(&key_lower) >= LEARNED_BYPASS_MIN_FAILURES_DOMAIN {
            return true;
        }
    }
    false
}

fn should_bypass_by_classifier_ip(ip: std::net::IpAddr, port: u16) -> bool {
    if port != 443 || !is_bypassable_public_ip(ip) {
        return false;
    }
    let key = format!("{ip}:{port}");
    destination_failures(&key) >= LEARNED_BYPASS_MIN_FAILURES_IP
}

fn is_bypassable_public_ip(ip: std::net::IpAddr) -> bool {
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

fn learned_bypass_threshold(destination: &str) -> Option<u8> {
    let (host, port) = split_host_port_for_connect(destination)?;
    if port != 443 {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_bypassable_public_ip(ip) {
            return Some(LEARNED_BYPASS_MIN_FAILURES_IP);
        }
        return None;
    }
    Some(LEARNED_BYPASS_MIN_FAILURES_DOMAIN)
}

fn destination_failures(destination: &str) -> u8 {
    let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return 0;
    };
    guard.get(destination).copied().unwrap_or(0)
}

fn destination_preferred_stage(destination: &str) -> u8 {
    let map = DEST_PREFERRED_STAGE.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return 0;
    };
    guard.get(destination).copied().unwrap_or(0).min(4)
}

fn select_race_probe_stage(destination: &str) -> u8 {
    // Гонка v1: выбор между стадиями 1/2/3 по здоровью стадий и хэшу назначения,
    // чтобы разнести первые пробы по разным профилям.
    let stats = STAGE_RACE_STATS.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = stats.lock() else {
        return 1;
    };
    let mut candidates = vec![1u8, 2u8, 3u8];
    candidates.sort_by(|a, b| {
        let sa = guard.get(a).cloned().unwrap_or_default();
        let sb = guard.get(b).cloned().unwrap_or_default();
        let ra = stage_penalty(sa.successes, sa.failures);
        let rb = stage_penalty(sb.successes, sb.failures);
        ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
    });
    // Сохраняем исследование: выбираем один из двух лучших профилей по хэшу назначения.
    if candidates.len() >= 2 {
        let idx = (stable_hash(destination) % 2) as usize;
        return candidates[idx];
    }
    candidates.into_iter().next().unwrap_or(1)
}

fn stage_penalty(successes: u64, failures: u64) -> f64 {
    let total = successes + failures;
    if total == 0 {
        return 0.5;
    }
    failures as f64 / total as f64
}

fn stable_hash(input: &str) -> u64 {
    let mut h = 1469598103934665603u64;
    for b in input.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

fn record_stage_source_selected(source: StageSelectionSource) {
    let counters = RACE_SOURCE_COUNTERS.get_or_init(|| Mutex::new(RaceSourceCounters::default()));
    if let Ok(mut guard) = counters.lock() {
        match source {
            StageSelectionSource::Cache => guard.cache = guard.cache.saturating_add(1),
            StageSelectionSource::Probe => guard.probe = guard.probe.saturating_add(1),
            StageSelectionSource::Adaptive => guard.adaptive = guard.adaptive.saturating_add(1),
        }
    }
}

fn record_destination_failure(
    destination: &str,
    signal: BlockingSignal,
    classifier_emit_interval_secs: u64,
    stage: u8,
) {
    let now = now_unix_secs();
    let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut failures_after_update = 0u8;
    if let Ok(mut guard) = map.lock() {
        let entry = guard.entry(destination.to_owned()).or_insert(0);
        *entry = entry.saturating_add(1).min(8);
        failures_after_update = *entry;
    }
    if let Some(threshold) = learned_bypass_threshold(destination) {
        if failures_after_update == threshold {
            if let Some((host, port)) = split_host_port_for_connect(destination) {
                let promotable = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    should_bypass_by_classifier_ip(ip, port)
                } else {
                    should_bypass_by_classifier_host(&host, port)
                };
                if promotable {
                    info!(
                        target: "socks5.classifier",
                        destination = %destination,
                        failures = failures_after_update,
                        threshold,
                        "destination promoted to learned bypass routing"
                    );
                }
            }
        }
    }
    let map = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        let stats = guard.entry(destination.to_owned()).or_default();
        stats.failures = stats.failures.saturating_add(1);
        match signal {
            BlockingSignal::Reset => stats.resets = stats.resets.saturating_add(1),
            BlockingSignal::Timeout => stats.timeouts = stats.timeouts.saturating_add(1),
            BlockingSignal::EarlyClose => stats.early_closes = stats.early_closes.saturating_add(1),
            BlockingSignal::BrokenPipe => stats.broken_pipes = stats.broken_pipes.saturating_add(1),
            BlockingSignal::SuspiciousZeroReply => {
                stats.suspicious_zero_replies = stats.suspicious_zero_replies.saturating_add(1)
            }
        }
        stats.last_seen_unix = now;
    }
    record_stage_outcome(stage, false);
    maybe_flush_classifier_store(false);
    maybe_emit_classifier_summary(classifier_emit_interval_secs.max(5));
}

fn record_destination_success(destination: &str, stage: u8, _source: StageSelectionSource) {
    let now = now_unix_secs();
    let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        if let Some(entry) = guard.get_mut(destination) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                guard.remove(destination);
            }
        }
    }
    let map = DEST_PREFERRED_STAGE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        guard.insert(destination.to_owned(), stage.min(4));
    }
    let map = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        let stats = guard.entry(destination.to_owned()).or_default();
        stats.successes = stats.successes.saturating_add(1);
        stats.last_seen_unix = now;
    }
    record_stage_outcome(stage, true);
    maybe_flush_classifier_store(false);
}

fn record_stage_outcome(stage: u8, success: bool) {
    if stage == 0 {
        return;
    }
    let stats = STAGE_RACE_STATS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = stats.lock() {
        let entry = guard.entry(stage.min(4)).or_default();
        if success {
            entry.successes = entry.successes.saturating_add(1);
        } else {
            entry.failures = entry.failures.saturating_add(1);
        }
    }
}

fn classify_io_error(e: &std::io::Error) -> BlockingSignal {
    match e.kind() {
        ErrorKind::ConnectionReset => BlockingSignal::Reset,
        ErrorKind::TimedOut => BlockingSignal::Timeout,
        ErrorKind::ConnectionAborted => BlockingSignal::EarlyClose,
        ErrorKind::BrokenPipe => BlockingSignal::BrokenPipe,
        _ => BlockingSignal::EarlyClose,
    }
}

fn blocking_signal_label(signal: BlockingSignal) -> &'static str {
    match signal {
        BlockingSignal::Reset => "reset",
        BlockingSignal::Timeout => "timeout",
        BlockingSignal::EarlyClose => "early-close",
        BlockingSignal::BrokenPipe => "broken-pipe",
        BlockingSignal::SuspiciousZeroReply => "suspicious-zero-reply",
    }
}

fn should_mark_suspicious_zero_reply(
    port: u16,
    bytes_client_to_upstream: u64,
    bytes_upstream_to_client: u64,
    min_c2u: usize,
) -> bool {
    port == 443 && bytes_upstream_to_client == 0 && bytes_client_to_upstream >= min_c2u as u64
}

fn maybe_emit_classifier_summary(interval_secs: u64) {
    let now = now_unix_secs();
    let last = LAST_CLASSIFIER_EMIT_UNIX.load(Ordering::Relaxed);
    if now.saturating_sub(last) < interval_secs {
        return;
    }
    if LAST_CLASSIFIER_EMIT_UNIX
        .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    let map = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return;
    };
    if !guard.is_empty() {
        let mut entries: Vec<(&String, &DestinationClassifier)> = guard.iter().collect();
        entries.sort_by_key(|(_, s)| std::cmp::Reverse(s.failures));
        let top = entries.into_iter().take(3).collect::<Vec<_>>();
        for (destination, s) in top {
            info!(
                target: "socks5.classifier",
                destination = %destination,
                failures = s.failures,
                resets = s.resets,
                timeouts = s.timeouts,
                early_closes = s.early_closes,
                broken_pipes = s.broken_pipes,
                suspicious_zero_replies = s.suspicious_zero_replies,
                successes = s.successes,
                "blocking classifier summary"
            );
        }
    }
    if let Ok(guard) = RACE_SOURCE_COUNTERS
        .get_or_init(|| Mutex::new(RaceSourceCounters::default()))
        .lock()
    {
        let total = guard.cache + guard.probe + guard.adaptive;
        if total > 0 {
            info!(
                target: "socks5.classifier",
                cache = guard.cache,
                probe = guard.probe,
                adaptive = guard.adaptive,
                total,
                "strategy selection source counters"
            );
        }
    }
    if let Ok(guard) = STAGE_RACE_STATS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    {
        let mut stages: Vec<(u8, StageRaceStats)> =
            guard.iter().map(|(k, v)| (*k, v.clone())).collect();
        stages.sort_by_key(|(stage, _)| *stage);
        for (stage, stats) in stages.into_iter().take(4) {
            let total = stats.successes + stats.failures;
            if total == 0 {
                continue;
            }
            let hit_rate = stats.successes as f64 / total as f64;
            info!(
                target: "socks5.classifier",
                stage,
                successes = stats.successes,
                failures = stats.failures,
                hit_rate = hit_rate,
                "strategy stage hit-rate"
            );
        }
    }
    if let Ok(guard) = ROUTE_METRICS
        .get_or_init(|| Mutex::new(RouteMetrics::default()))
        .lock()
    {
        let selected_total = guard.route_selected_direct + guard.route_selected_bypass;
        let race_wins_total = guard.race_winner_direct + guard.race_winner_bypass;
        let winner_cache_total = guard.winner_cache_hits + guard.winner_cache_misses;
        if selected_total > 0 || guard.race_started > 0 || guard.race_skipped > 0 {
            info!(
                target: "socks5.classifier",
                selected_total,
                selected_direct = guard.route_selected_direct,
                selected_bypass = guard.route_selected_bypass,
                races_started = guard.race_started,
                races_skipped = guard.race_skipped,
                race_wins_total,
                race_wins_direct = guard.race_winner_direct,
                race_wins_bypass = guard.race_winner_bypass,
                route_success_direct = guard.route_success_direct,
                route_success_bypass = guard.route_success_bypass,
                route_failure_direct = guard.route_failure_direct,
                route_failure_bypass = guard.route_failure_bypass,
                soft_zero_reply_direct = guard.route_soft_zero_reply_direct,
                soft_zero_reply_bypass = guard.route_soft_zero_reply_bypass,
                connect_fail_direct = guard.connect_failure_direct,
                connect_fail_bypass = guard.connect_failure_bypass,
                "adaptive route counters"
            );
        }
        if winner_cache_total > 0 {
            let winner_cache_hit_rate = guard.winner_cache_hits as f64 / winner_cache_total as f64;
            info!(
                target: "socks5.classifier",
                winner_cache_hits = guard.winner_cache_hits,
                winner_cache_misses = guard.winner_cache_misses,
                winner_cache_hit_rate,
                reason_no_winner = guard.race_reason_no_winner,
                reason_empty_winner = guard.race_reason_empty_winner,
                reason_winner_stale = guard.race_reason_winner_stale,
                reason_winner_weak = guard.race_reason_winner_weak,
                reason_winner_missing = guard.race_reason_winner_missing,
                reason_winner_healthy = guard.race_reason_winner_healthy,
                reason_single_candidate = guard.race_reason_single_candidate,
                reason_non_tls = guard.race_reason_non_tls,
                "adaptive route race diagnostics"
            );
        }
    }
    if let Ok(guard) = GLOBAL_BYPASS_PROFILE_HEALTH
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    {
        if !guard.is_empty() {
            let mut profiles: Vec<(&String, &BypassProfileHealth)> = guard.iter().collect();
            profiles.sort_by(|a, b| {
                let a_score = bypass_profile_score_from_health(a.1, now);
                let b_score = bypass_profile_score_from_health(b.1, now);
                b_score.cmp(&a_score).then_with(|| a.0.cmp(b.0))
            });
            for (route_id, health) in profiles.into_iter().take(3) {
                info!(
                    target: "socks5.classifier",
                    route = %route_id,
                    score = bypass_profile_score_from_health(health, now),
                    successes = health.successes,
                    failures = health.failures,
                    connect_failures = health.connect_failures,
                    soft_zero_replies = health.soft_zero_replies,
                    io_errors = health.io_errors,
                    "global bypass profile health"
                );
            }
        }
    }
    maybe_flush_classifier_store(false);
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn init_classifier_store(relay_opts: &RelayOptions) {
    let _ = CLASSIFIER_STORE_CFG.get_or_init(|| {
        if !relay_opts.classifier_persist_enabled {
            return None;
        }
        let path = relay_opts
            .classifier_cache_path
            .clone()
            .map(|p| expand_tilde(&p))
            .unwrap_or_else(default_classifier_store_path);
        Some(ClassifierStoreConfig {
            path,
            entry_ttl_secs: relay_opts.classifier_entry_ttl_secs.max(60),
        })
    });
}

fn default_classifier_store_path() -> PathBuf {
    if let Some(dir) = dirs::cache_dir() {
        return dir.join("prime-net-engine").join("relay-classifier.json");
    }
    expand_tilde("~/.cache/prime-net-engine/relay-classifier.json")
}

fn load_classifier_store_if_needed() {
    if CLASSIFIER_STORE_LOADED.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(cfg) = CLASSIFIER_STORE_CFG.get().and_then(Clone::clone) else {
        return;
    };
    let Ok(Some(snapshot)) = read_classifier_snapshot(&cfg.path) else {
        return;
    };
    let now = now_unix_secs();
    let mut restored = 0usize;
    let failures = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let preferred = DEST_PREFERRED_STAGE.get_or_init(|| Mutex::new(HashMap::new()));
    let classifier = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    let bypass_idx = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    let bypass_failures = DEST_BYPASS_PROFILE_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let route_health = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let route_winner = DEST_ROUTE_WINNER.get_or_init(|| Mutex::new(HashMap::new()));
    let global_bypass = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut failures_guard) = failures.lock() else {
        return;
    };
    let Ok(mut preferred_guard) = preferred.lock() else {
        return;
    };
    let Ok(mut classifier_guard) = classifier.lock() else {
        return;
    };
    let Ok(mut bypass_idx_guard) = bypass_idx.lock() else {
        return;
    };
    let Ok(mut bypass_failures_guard) = bypass_failures.lock() else {
        return;
    };
    let Ok(mut route_health_guard) = route_health.lock() else {
        return;
    };
    let Ok(mut route_winner_guard) = route_winner.lock() else {
        return;
    };
    let Ok(mut global_bypass_guard) = global_bypass.lock() else {
        return;
    };
    let ClassifierSnapshot {
        entries,
        global_bypass_health,
        ..
    } = snapshot;
    for (destination, mut entry) in entries {
        entry.preferred_stage = entry.preferred_stage.min(4);
        let last_seen = snapshot_entry_last_seen_unix(&entry);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            continue;
        }
        if entry.failures > 0 {
            failures_guard.insert(destination.clone(), entry.failures.min(8));
        }
        if entry.preferred_stage > 0 {
            preferred_guard.insert(destination.clone(), entry.preferred_stage);
        }
        if !destination_classifier_is_empty(&entry.stats) {
            classifier_guard.insert(destination.clone(), entry.stats);
        }
        if let Some(idx) = entry.bypass_profile_idx {
            bypass_idx_guard.insert(destination.clone(), idx);
        }
        if entry.bypass_profile_failures > 0 {
            bypass_failures_guard.insert(destination.clone(), entry.bypass_profile_failures);
        }
        if let Some(winner) = entry.route_winner.take() {
            if !winner.route_id.trim().is_empty() {
                route_winner_guard.insert(destination.clone(), winner);
            }
        }
        if !entry.route_health.is_empty() {
            let mut per_route: HashMap<String, RouteHealth> = HashMap::new();
            for (route_id, mut health) in entry.route_health {
                let route_id = route_id.trim();
                if route_id.is_empty() {
                    continue;
                }
                health.consecutive_failures = health.consecutive_failures.min(32);
                if route_health_is_empty(&health) {
                    continue;
                }
                per_route.insert(route_id.to_owned(), health);
            }
            if !per_route.is_empty() {
                route_health_guard.insert(destination.clone(), per_route);
            }
        }
        restored = restored.saturating_add(1);
    }
    for (route_id, health) in global_bypass_health {
        let route_id = route_id.trim();
        if route_id.is_empty() || !route_id.starts_with("bypass:") {
            continue;
        }
        if bypass_profile_health_is_empty(&health) {
            continue;
        }
        let last_seen = bypass_profile_health_last_seen_unix(&health);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            continue;
        }
        global_bypass_guard.insert(route_id.to_owned(), health);
    }
    if restored > 0 {
        info!(
            target: "socks5.classifier",
            restored,
            path = %cfg.path.display(),
            "restored persisted relay classifier entries"
        );
    }
}

fn destination_classifier_is_empty(stats: &DestinationClassifier) -> bool {
    stats.failures == 0
        && stats.resets == 0
        && stats.timeouts == 0
        && stats.early_closes == 0
        && stats.broken_pipes == 0
        && stats.suspicious_zero_replies == 0
        && stats.successes == 0
}

fn route_health_is_empty(health: &RouteHealth) -> bool {
    health.successes == 0
        && health.failures == 0
        && health.consecutive_failures == 0
        && health.weak_until_unix == 0
        && health.last_success_unix == 0
        && health.last_failure_unix == 0
}

fn route_health_last_seen_unix(health: &RouteHealth) -> u64 {
    health
        .last_success_unix
        .max(health.last_failure_unix)
        .max(health.weak_until_unix)
}

fn snapshot_entry_last_seen_unix(entry: &ClassifierSnapshotEntry) -> u64 {
    let mut last_seen = entry.stats.last_seen_unix;
    if let Some(winner) = entry.route_winner.as_ref() {
        last_seen = last_seen.max(winner.updated_at_unix);
    }
    for health in entry.route_health.values() {
        last_seen = last_seen.max(route_health_last_seen_unix(health));
    }
    last_seen
}

fn read_classifier_snapshot(path: &Path) -> std::io::Result<Option<ClassifierSnapshot>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path)?;
    let parsed: ClassifierSnapshot = serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok(Some(parsed))
}

fn maybe_flush_classifier_store(force: bool) {
    let Some(cfg) = CLASSIFIER_STORE_CFG.get().and_then(Clone::clone) else {
        return;
    };
    CLASSIFIER_STORE_DIRTY.store(true, Ordering::Relaxed);
    let now = now_unix_secs();
    let last = CLASSIFIER_STORE_LAST_FLUSH_UNIX.load(Ordering::Relaxed);
    if !force && now.saturating_sub(last) < CLASSIFIER_PERSIST_DEBOUNCE_SECS {
        return;
    }
    if CLASSIFIER_STORE_LAST_FLUSH_UNIX
        .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    if !CLASSIFIER_STORE_DIRTY.swap(false, Ordering::SeqCst) {
        return;
    }
    if let Err(e) = write_classifier_snapshot(&cfg) {
        CLASSIFIER_STORE_DIRTY.store(true, Ordering::Relaxed);
        warn!(
            target: "socks5.classifier",
            error = %e,
            path = %cfg.path.display(),
            "failed to persist relay classifier cache"
        );
    }
}

fn write_classifier_snapshot(cfg: &ClassifierStoreConfig) -> std::io::Result<()> {
    let failures = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let preferred = DEST_PREFERRED_STAGE.get_or_init(|| Mutex::new(HashMap::new()));
    let classifier = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    let bypass_idx = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    let bypass_failures = DEST_BYPASS_PROFILE_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let route_health = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let route_winner = DEST_ROUTE_WINNER.get_or_init(|| Mutex::new(HashMap::new()));
    let global_bypass = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));

    let failures_guard = failures.lock().map_err(|_| {
        std::io::Error::other("failed to lock destination failures while persisting classifier")
    })?;
    let preferred_guard = preferred.lock().map_err(|_| {
        std::io::Error::other("failed to lock preferred stages while persisting classifier")
    })?;
    let classifier_guard = classifier.lock().map_err(|_| {
        std::io::Error::other("failed to lock classifier stats while persisting classifier")
    })?;
    let bypass_idx_guard = bypass_idx.lock().map_err(|_| {
        std::io::Error::other("failed to lock bypass profile index while persisting classifier")
    })?;
    let bypass_failures_guard = bypass_failures.lock().map_err(|_| {
        std::io::Error::other("failed to lock bypass profile failures while persisting classifier")
    })?;
    let route_health_guard = route_health.lock().map_err(|_| {
        std::io::Error::other("failed to lock route health while persisting classifier")
    })?;
    let route_winner_guard = route_winner.lock().map_err(|_| {
        std::io::Error::other("failed to lock route winner while persisting classifier")
    })?;
    let global_bypass_guard = global_bypass.lock().map_err(|_| {
        std::io::Error::other("failed to lock global bypass health while persisting classifier")
    })?;

    let now = now_unix_secs();
    let mut entries: HashMap<String, ClassifierSnapshotEntry> = HashMap::new();
    for (destination, stats) in classifier_guard.iter() {
        entries.insert(
            destination.clone(),
            ClassifierSnapshotEntry {
                failures: 0,
                preferred_stage: 0,
                stats: stats.clone(),
                bypass_profile_idx: None,
                bypass_profile_failures: 0,
                route_winner: None,
                route_health: HashMap::new(),
            },
        );
    }
    for (destination, value) in failures_guard.iter() {
        entries.entry(destination.clone()).or_default().failures = (*value).min(8);
    }
    for (destination, stage) in preferred_guard.iter() {
        entries
            .entry(destination.clone())
            .or_default()
            .preferred_stage = (*stage).min(4);
    }
    for (destination, idx) in bypass_idx_guard.iter() {
        entries
            .entry(destination.clone())
            .or_default()
            .bypass_profile_idx = Some(*idx);
    }
    for (destination, value) in bypass_failures_guard.iter() {
        entries
            .entry(destination.clone())
            .or_default()
            .bypass_profile_failures = *value;
    }
    for (destination, winner) in route_winner_guard.iter() {
        if winner.route_id.trim().is_empty() {
            continue;
        }
        entries
            .entry(destination.clone())
            .or_default()
            .route_winner = Some(winner.clone());
    }
    for (destination, per_route) in route_health_guard.iter() {
        if per_route.is_empty() {
            continue;
        }
        let mut filtered = HashMap::new();
        for (route_id, health) in per_route.iter() {
            if route_id.trim().is_empty() || route_health_is_empty(health) {
                continue;
            }
            filtered.insert(route_id.clone(), health.clone());
        }
        if !filtered.is_empty() {
            entries
                .entry(destination.clone())
                .or_default()
                .route_health = filtered;
        }
    }
    entries.retain(|_, entry| {
        let last_seen = snapshot_entry_last_seen_unix(entry);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            return false;
        }
        entry.failures > 0
            || entry.preferred_stage > 0
            || !destination_classifier_is_empty(&entry.stats)
            || entry.bypass_profile_idx.is_some()
            || entry.bypass_profile_failures > 0
            || entry
                .route_winner
                .as_ref()
                .map(|winner| !winner.route_id.trim().is_empty())
                .unwrap_or(false)
            || !entry.route_health.is_empty()
    });
    let mut global_bypass_health = HashMap::new();
    for (route_id, health) in global_bypass_guard.iter() {
        let route_id = route_id.trim();
        if route_id.is_empty() || !route_id.starts_with("bypass:") {
            continue;
        }
        if bypass_profile_health_is_empty(health) {
            continue;
        }
        let last_seen = bypass_profile_health_last_seen_unix(health);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            continue;
        }
        global_bypass_health.insert(route_id.to_owned(), health.clone());
    }

    let snapshot = ClassifierSnapshot {
        version: 2,
        updated_at_unix: now,
        entries,
        global_bypass_health,
    };
    if let Some(parent) = cfg.path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data =
        serde_json::to_vec_pretty(&snapshot).map_err(|e| std::io::Error::other(e.to_string()))?;
    fs::write(&cfg.path, data)?;
    Ok(())
}

async fn relay_bidirectional(
    client: &mut TcpStream,
    upstream: &mut BoxStream,
    relay_opts: RelayOptions,
) -> std::io::Result<(u64, u64)> {
    if !relay_opts.fragment_client_hello {
        return tokio::io::copy_bidirectional(client, upstream).await;
    }

    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut upstream_r, upstream_w) = tokio::io::split(upstream);

    let upstream_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream_seen_c2u = upstream_seen.clone();
    let c2u = async move {
        let mut total = 0u64;
        let mut budget = relay_opts.fragment_budget_bytes;
        let started = tokio::time::Instant::now();
        let mut buf = [0u8; 16 * 1024];
        let mut maybe_tls = None;

        let fragment_cfg = FragmentConfig {
            first_write_max: relay_opts.fragment_size.clamp(1, 64),
            first_write_plan: if relay_opts.client_hello_split_offsets.is_empty() {
                None
            } else {
                Some(offsets_to_plan(&relay_opts.client_hello_split_offsets))
            },
            fragment_size: relay_opts.fragment_size.max(1),
            sleep_ms: relay_opts.fragment_sleep_ms,
            jitter_ms: None,
            randomize_fragment_size: false,
            split_at_sni: relay_opts.split_at_sni,
        };
        let (mut frag_upstream_w, frag_handle) =
            FragmentingIo::new(upstream_w, fragment_cfg.clone());

        loop {
            let n = client_r.read(&mut buf).await?;
            if n == 0 {
                frag_upstream_w.shutdown().await?;
                break;
            }
            total += n as u64;

            if maybe_tls.is_none() {
                maybe_tls = Some(is_tls_client_hello(&buf[..n]));
                if !maybe_tls.unwrap_or(false) {
                    frag_handle.disable();
                }
            }

            // Фрагментируем только в раннем окне handshake или до первых байтов от upstream.
            let within_handshake_window = started.elapsed() <= Duration::from_secs(3);
            let upstream_has_responded = upstream_seen_c2u.load(Ordering::Relaxed);
            let use_fragmentation = maybe_tls.unwrap_or(false)
                && budget > 0
                && within_handshake_window
                && !upstream_has_responded;

            if use_fragmentation {
                let to_fragment = n.min(budget);
                frag_upstream_w.write_all(&buf[..to_fragment]).await?;
                if to_fragment < n {
                    frag_handle.disable();
                    frag_upstream_w.write_all(&buf[to_fragment..n]).await?;
                }
                budget -= to_fragment;
                if budget == 0 {
                    frag_handle.disable();
                }
            } else {
                frag_handle.disable();
                frag_upstream_w.write_all(&buf[..n]).await?;
            }
        }
        Ok::<u64, std::io::Error>(total)
    };

    let u2c = async {
        let mut total = 0u64;
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = upstream_r.read(&mut buf).await?;
            if n == 0 {
                client_w.shutdown().await?;
                break;
            }
            upstream_seen.store(true, Ordering::Relaxed);
            total += n as u64;
            client_w.write_all(&buf[..n]).await?;
        }
        Ok::<u64, std::io::Error>(total)
    };

    let (bytes_client_to_upstream, bytes_upstream_to_client) = tokio::try_join!(c2u, u2c)?;
    Ok((bytes_client_to_upstream, bytes_upstream_to_client))
}

fn offsets_to_plan(offsets: &[usize]) -> Vec<usize> {
    offsets
        .iter()
        .copied()
        .scan(0usize, |prev, off| {
            if off > *prev {
                let out = off - *prev;
                *prev = off;
                Some(Some(out))
            } else {
                Some(None)
            }
        })
        .flatten()
        .collect()
}

fn is_tls_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 3 && buf[0] == 0x16 && buf[1] == 0x03
}

async fn read_cstring(tcp: &mut TcpStream, limit: usize) -> Result<String> {
    let mut data = Vec::new();
    let mut b = [0u8; 1];
    loop {
        tcp.read_exact(&mut b).await?;
        if b[0] == 0 {
            break;
        }
        data.push(b[0]);
        if data.len() > limit {
            return Err(EngineError::InvalidInput(
                "SOCKS string too long".to_owned(),
            ));
        }
    }
    String::from_utf8(data)
        .map_err(|_| EngineError::InvalidInput("SOCKS string is not UTF-8".to_owned()))
}

async fn read_socks_target_addr(tcp: &mut TcpStream, atyp: u8) -> Result<TargetAddr> {
    match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            tcp.read_exact(&mut b).await?;
            Ok(TargetAddr::Ip(std::net::IpAddr::V4(
                std::net::Ipv4Addr::from(b),
            )))
        }
        0x03 => {
            let mut lb = [0u8; 1];
            tcp.read_exact(&mut lb).await?;
            let len = lb[0] as usize;
            let mut b = vec![0u8; len];
            tcp.read_exact(&mut b).await?;
            let s = String::from_utf8(b).map_err(|_| {
                EngineError::InvalidInput("SOCKS5 domain is not valid UTF-8".to_owned())
            })?;
            Ok(TargetAddr::Domain(s))
        }
        0x04 => {
            let mut b = [0u8; 16];
            tcp.read_exact(&mut b).await?;
            Ok(TargetAddr::Ip(std::net::IpAddr::V6(
                std::net::Ipv6Addr::from(b),
            )))
        }
        other => Err(EngineError::InvalidInput(format!(
            "SOCKS5 invalid ATYP 0x{other:02x}"
        ))),
    }
}

async fn handle_socks5_udp_associate(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    client: String,
    request_addr: TargetAddr,
    request_port: u16,
    silent_drop: bool,
) -> Result<()> {
    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let udp = UdpSocket::bind(bind).await?;
    let udp_bind = udp.local_addr()?;
    let reply = build_socks5_bind_reply(0x00, udp_bind);
    tcp.write_all(&reply).await?;

    let mut client_udp_addr = match request_addr {
        TargetAddr::Ip(ip) if request_port != 0 => Some(SocketAddr::new(ip, request_port)),
        _ => None,
    };
    info!(
        target: "socks5",
        conn_id,
        peer = %peer,
        client = %client,
        udp_bind = %udp_bind,
        client_udp_hint = ?client_udp_addr,
        "SOCKS5 UDP relay active"
    );

    let mut tcp_probe = [0u8; 1];
    let mut udp_buf = vec![0u8; 65535];
    let mut remote_to_key: HashMap<SocketAddr, String> = HashMap::new();
    let mut policies: HashMap<String, UdpDestinationPolicy> = HashMap::new();

    loop {
        tokio::select! {
            res = tcp.read(&mut tcp_probe) => {
                match res {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            res = udp.recv_from(&mut udp_buf) => {
                let Ok((n, src)) = res else { continue; };
                if is_client_udp_packet(src, peer, client_udp_addr) {
                    if client_udp_addr.is_none() {
                        client_udp_addr = Some(src);
                    }
                    let Some((target_addr, target_port, payload_offset)) = parse_socks5_udp_request(&udp_buf[..n]) else {
                        continue;
                    };
                    let payload = &udp_buf[payload_offset..n];
                    let key = format_target(&target_addr, target_port);
                    let now = now_unix_secs();
                    let policy = policies.entry(key.clone()).or_default();
                    if now < policy.disabled_until_unix {
                        continue;
                    }
                    let target = match resolve_udp_target_addr(&target_addr, target_port).await {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(target: "socks5.udp", conn_id, destination = %key, error = %e, "UDP target resolve failed");
                            continue;
                        }
                    };
                    if udp.send_to(payload, target).await.is_ok() {
                        policy.sent = policy.sent.saturating_add(1);
                        remote_to_key.insert(target, key.clone());
                        if policy.sent >= UDP_POLICY_DISABLE_THRESHOLD && policy.recv == 0 {
                            policy.disabled_until_unix = now.saturating_add(UDP_POLICY_DISABLE_SECS);
                            warn!(
                                target: "socks5.udp",
                                conn_id,
                                destination = %key,
                                disable_secs = UDP_POLICY_DISABLE_SECS,
                                "UDP policy: no replies detected, temporarily disabling UDP to accelerate TCP fallback"
                            );
                        }
                    }
                    continue;
                }

                let Some(client_addr) = client_udp_addr else { continue; };
                if let Some(key) = remote_to_key.get(&src) {
                    let policy = policies.entry(key.clone()).or_default();
                    policy.recv = policy.recv.saturating_add(1);
                    policy.disabled_until_unix = 0;
                }
                let response = build_socks5_udp_response(src, &udp_buf[..n]);
                let _ = udp.send_to(&response, client_addr).await;
            }
        }
    }

    if !silent_drop {
        let _ = tcp.shutdown().await;
    }
    info!(target: "socks5", conn_id, peer = %peer, client = %client, "SOCKS5 UDP ASSOCIATE closed");
    Ok(())
}

fn is_client_udp_packet(
    src: SocketAddr,
    peer: SocketAddr,
    client_udp_addr: Option<SocketAddr>,
) -> bool {
    if src.ip() != peer.ip() {
        return false;
    }
    if let Some(addr) = client_udp_addr {
        return src.port() == addr.port();
    }
    true
}

fn parse_socks5_udp_request(packet: &[u8]) -> Option<(TargetAddr, u16, usize)> {
    if packet.len() < 10 {
        return None;
    }
    if packet[0] != 0 || packet[1] != 0 {
        return None;
    }
    // В этом реле фрагментация не поддерживается.
    if packet[2] != 0 {
        return None;
    }
    let atyp = packet[3];
    let mut idx = 4usize;
    let addr = match atyp {
        0x01 => {
            if idx + 4 > packet.len() {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(
                packet[idx],
                packet[idx + 1],
                packet[idx + 2],
                packet[idx + 3],
            );
            idx += 4;
            TargetAddr::Ip(std::net::IpAddr::V4(ip))
        }
        0x03 => {
            if idx + 1 > packet.len() {
                return None;
            }
            let len = packet[idx] as usize;
            idx += 1;
            if idx + len > packet.len() {
                return None;
            }
            let host = std::str::from_utf8(&packet[idx..idx + len])
                .ok()?
                .to_owned();
            idx += len;
            TargetAddr::Domain(host)
        }
        0x04 => {
            if idx + 16 > packet.len() {
                return None;
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&packet[idx..idx + 16]);
            idx += 16;
            TargetAddr::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)))
        }
        _ => return None,
    };
    if idx + 2 > packet.len() {
        return None;
    }
    let port = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
    idx += 2;
    Some((addr, port, idx))
}

async fn resolve_udp_target_addr(addr: &TargetAddr, port: u16) -> std::io::Result<SocketAddr> {
    match addr {
        TargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, port)),
        TargetAddr::Domain(host) => {
            let mut addrs = lookup_host((host.as_str(), port)).await?;
            addrs
                .next()
                .ok_or_else(|| std::io::Error::other("UDP resolve produced no addresses"))
        }
    }
}

fn build_socks5_bind_reply(rep: u8, bind: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.push(0x05);
    out.push(rep);
    out.push(0x00);
    match bind {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out
}

fn build_socks5_udp_response(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 22);
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    match source {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

fn split_host_port_for_connect(target: &str) -> Option<(String, u16)> {
    let t = target.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with('[') {
        let end = t.find(']')?;
        let host = t[1..end].trim();
        if host.is_empty() {
            return None;
        }
        let rest = t.get(end + 1..)?.trim();
        let port = rest.strip_prefix(':')?.trim().parse::<u16>().ok()?;
        return Some((host.to_owned(), port));
    }
    let (host, port) = t.rsplit_once(':')?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let port = port.trim().parse::<u16>().ok()?;
    Some((host.to_owned(), port))
}

#[derive(Debug)]
struct HttpForwardTarget {
    host: String,
    port: u16,
    request_uri: String,
}

fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn parse_http_forward_target(target: &str, request_head: &str) -> Option<HttpForwardTarget> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }

    if let Ok(url) = url::Url::parse(target) {
        if !url.scheme().eq_ignore_ascii_case("http") {
            return None;
        }
        let host = url.host_str()?.to_owned();
        let port = url.port_or_known_default().unwrap_or(80);
        let mut request_uri = url.path().to_owned();
        if request_uri.is_empty() {
            request_uri = "/".to_owned();
        }
        if let Some(q) = url.query() {
            request_uri.push('?');
            request_uri.push_str(q);
        }
        return Some(HttpForwardTarget {
            host,
            port,
            request_uri,
        });
    }

    if target.starts_with('/') || target == "*" {
        let host_header = extract_header_value(request_head, "Host")?;
        let (host, port) = split_host_port_with_default(&host_header, 80)?;
        return Some(HttpForwardTarget {
            host,
            port,
            request_uri: target.to_owned(),
        });
    }

    None
}

fn rewrite_http_forward_head(
    method: &str,
    version: &str,
    request_uri: &str,
    request_head: &str,
    host: &str,
    port: u16,
) -> String {
    let mut out = String::new();
    out.push_str(method);
    out.push(' ');
    out.push_str(request_uri);
    out.push(' ');
    out.push_str(version);
    out.push_str("\r\n");

    let mut saw_host = false;
    for line in request_head.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name_trimmed = name.trim();
        if name_trimmed.eq_ignore_ascii_case("Proxy-Connection") {
            continue;
        }
        if name_trimmed.eq_ignore_ascii_case("Host") {
            saw_host = true;
            out.push_str("Host: ");
            out.push_str(&format_host_header(host, port));
            out.push_str("\r\n");
            continue;
        }
        out.push_str(name_trimmed);
        out.push(':');
        out.push_str(value);
        out.push_str("\r\n");
    }
    if !saw_host {
        out.push_str("Host: ");
        out.push_str(&format_host_header(host, port));
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

fn extract_header_value(request_head: &str, header_name: &str) -> Option<String> {
    for line in request_head.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(header_name) {
            return Some(value.trim().to_owned());
        }
    }
    None
}

fn split_host_port_with_default(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = authority[1..end].trim().to_owned();
        if host.is_empty() {
            return None;
        }
        let rest = authority.get(end + 1..).unwrap_or_default().trim();
        if rest.is_empty() {
            return Some((host, default_port));
        }
        let port = rest.strip_prefix(':')?.trim().parse::<u16>().ok()?;
        return Some((host, port));
    }

    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let host = host.trim();
        if host.is_empty() {
            return None;
        }
        if !host.contains(':') {
            let port = port_str.trim().parse::<u16>().ok()?;
            return Some((host.to_owned(), port));
        }
        return None;
    }

    Some((authority.to_owned(), default_port))
}

fn format_host_header(host: &str, port: u16) -> String {
    let host_rendered = if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == 80 {
        host_rendered
    } else {
        format!("{host_rendered}:{port}")
    }
}

fn format_target(addr: &TargetAddr, port: u16) -> String {
    match addr {
        TargetAddr::Ip(ip) => format!("{ip}:{port}"),
        TargetAddr::Domain(host) => format!("{host}:{port}"),
    }
}

fn is_expected_disconnect(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
    )
}

async fn resolve_client_label(peer: SocketAddr, listen_addr: SocketAddr) -> String {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || describe_client(peer, listen_addr))
            .await
            .unwrap_or_else(|_| format!("unknown-app ({peer})"))
    }
    #[cfg(not(windows))]
    {
        describe_client(peer, listen_addr)
    }
}

fn describe_client(peer: SocketAddr, _listen_addr: SocketAddr) -> String {
    #[cfg(windows)]
    {
        if let Some(pid) = resolve_client_pid_netstat(peer, _listen_addr) {
            let name = resolve_process_name(pid).unwrap_or_else(|| "unknown".to_owned());
            return format!("{name} (pid {pid})");
        }
    }
    format!("unknown-app ({peer})")
}

#[cfg(windows)]
fn resolve_client_pid_netstat(peer: SocketAddr, listen_addr: SocketAddr) -> Option<u32> {
    let output = std::process::Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || !parts[0].eq_ignore_ascii_case("tcp") {
            continue;
        }
        let local = parts[1];
        let remote = parts[2];
        if endpoint_matches(local, peer) && endpoint_matches(remote, listen_addr) {
            if let Ok(pid) = parts[parts.len() - 1].parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(windows)]
fn endpoint_matches(token: &str, addr: SocketAddr) -> bool {
    let t = token.trim().to_ascii_lowercase();
    let direct = addr.to_string().to_ascii_lowercase();
    if t == direct {
        return true;
    }

    // netstat может показывать IPv4-адрес loopback в IPv6-mapped виде.
    if let SocketAddr::V4(v4) = addr {
        let mapped = format!("[::ffff:{}]:{}", v4.ip(), v4.port()).to_ascii_lowercase();
        if t == mapped {
            return true;
        }
    }

    false
}

#[cfg(windows)]
fn resolve_process_name(pid: u32) -> Option<String> {
    let cache = PID_NAME_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(name) = guard.get(&pid) {
            return Some(name.clone());
        }
    }

    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8(output.stdout).ok()?;
    let first = text.lines().next()?.trim();
    if first.is_empty() || first.starts_with("INFO:") {
        return None;
    }
    let name = parse_first_csv_column(first)?;
    if let Ok(mut guard) = cache.lock() {
        guard.insert(pid, name.clone());
    }
    Some(name)
}

#[cfg(windows)]
fn parse_first_csv_column(line: &str) -> Option<String> {
    let line = line.trim();
    if !line.starts_with('"') {
        return line
            .split(',')
            .next()
            .map(|v| v.trim().trim_matches('"').to_owned());
    }
    let mut out = String::new();
    let mut chars = line.chars();
    let _ = chars.next();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            if let Some('"') = chars.clone().next() {
                out.push('"');
                let _ = chars.next();
                continue;
            }
            break;
        }
        out.push(ch);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_route_state_for_test(route_key: &str) {
        if let Ok(mut guard) = DEST_ROUTE_HEALTH
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.remove(route_key);
        }
        if let Ok(mut guard) = DEST_ROUTE_WINNER
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.remove(route_key);
        }
    }

    fn clear_global_bypass_health_for_test() {
        if let Ok(mut guard) = GLOBAL_BYPASS_PROFILE_HEALTH
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.clear();
        }
    }

    #[test]
    fn connect_target_rejects_empty_host() {
        assert!(split_host_port_for_connect(":443").is_none());
        assert!(split_host_port_for_connect("[]:443").is_none());
    }

    #[test]
    fn connect_target_rejects_invalid_port() {
        assert!(split_host_port_for_connect("example.com:notaport").is_none());
    }

    #[test]
    fn host_header_rejects_invalid_port() {
        assert!(split_host_port_with_default("example.com:notaport", 80).is_none());
    }

    #[test]
    fn host_header_rejects_empty_bracketed_host() {
        assert!(split_host_port_with_default("[]:80", 80).is_none());
    }

    #[test]
    fn parse_http_forward_target_rejects_bad_host_header() {
        let req = "GET / HTTP/1.1\r\nHost: example.com:notaport\r\n\r\n";
        assert!(parse_http_forward_target("/", req).is_none());
    }

    #[test]
    fn learned_bypass_activates_after_failures_for_tls_domain() {
        let key = "learned-bypass-test.invalid:443".to_owned();
        let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
        {
            let mut guard = map.lock().expect("lock failures map");
            guard.insert(key.clone(), LEARNED_BYPASS_MIN_FAILURES_DOMAIN);
        }

        assert!(should_bypass_by_classifier_host(
            "learned-bypass-test.invalid",
            443
        ));
        assert!(!should_bypass_by_classifier_host("127.0.0.1", 443));
        assert!(!should_bypass_by_classifier_host(
            "learned-bypass-test.invalid",
            80
        ));

        {
            let mut guard = map.lock().expect("lock failures map");
            guard.remove(&key);
        }
    }

    #[test]
    fn learned_bypass_activates_for_public_ip_but_not_loopback() {
        let pub_key = "79.133.169.98:443".to_owned();
        let loopback_key = "127.0.0.1:443".to_owned();
        let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
        {
            let mut guard = map.lock().expect("lock failures map");
            guard.insert(pub_key.clone(), LEARNED_BYPASS_MIN_FAILURES_IP);
            guard.insert(loopback_key.clone(), LEARNED_BYPASS_MIN_FAILURES_IP);
        }

        assert!(should_bypass_by_classifier_ip(
            "79.133.169.98".parse().expect("ip"),
            443
        ));
        assert!(!should_bypass_by_classifier_ip(
            "127.0.0.1".parse().expect("ip"),
            443
        ));

        {
            let mut guard = map.lock().expect("lock failures map");
            guard.remove(&pub_key);
            guard.remove(&loopback_key);
        }
    }

    #[test]
    fn adaptive_route_candidates_include_bypass_for_public_tls_domain() {
        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec![
                "127.0.0.1:19080".parse().expect("addr"),
                "127.0.0.1:19081".parse().expect("addr"),
            ],
            ..RelayOptions::default()
        };
        let candidates = select_route_candidates(
            &relay_opts,
            &TargetAddr::Domain("service.example.com".to_owned()),
            443,
            "service.example.com:443",
        );
        assert_eq!(candidates.len(), 3);
        assert!(candidates.iter().any(|c| c.kind == RouteKind::Direct));
        assert_eq!(
            candidates
                .iter()
                .filter(|c| c.kind == RouteKind::Bypass)
                .count(),
            2
        );
    }

    #[test]
    fn adaptive_route_weakens_and_recovers_after_cooldown() {
        let route_key = "adaptive-route-test:443";
        clear_route_state_for_test(route_key);
        let candidate = RouteCandidate::bypass(
            "test",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            1,
        );
        record_route_failure(route_key, &candidate, "unit-failure");
        record_route_failure(route_key, &candidate, "unit-failure");
        assert!(route_is_temporarily_weak(
            route_key,
            &candidate.route_id(),
            now_unix_secs()
        ));

        if let Ok(mut guard) = DEST_ROUTE_HEALTH
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            if let Some(per_route) = guard.get_mut(route_key) {
                if let Some(entry) = per_route.get_mut(&candidate.route_id()) {
                    entry.weak_until_unix = now_unix_secs().saturating_sub(1);
                }
            }
        }
        assert!(!route_is_temporarily_weak(
            route_key,
            &candidate.route_id(),
            now_unix_secs()
        ));

        record_route_success(route_key, &candidate);
        let winner = route_winner_for_key(route_key).expect("winner");
        assert_eq!(winner.route_id, candidate.route_id());
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn adaptive_route_reraces_when_cached_winner_is_unavailable() {
        let route_key = "adaptive-route-missing-winner:443";
        clear_route_state_for_test(route_key);
        if let Ok(mut guard) = DEST_ROUTE_WINNER
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.insert(
                route_key.to_owned(),
                RouteWinner {
                    route_id: "bypass:3".to_owned(),
                    updated_at_unix: now_unix_secs(),
                },
            );
        }

        let candidates = vec![
            RouteCandidate::direct("test"),
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1),
        ];
        assert_eq!(
            route_race_decision(443, route_key, &candidates),
            (true, RouteRaceReason::WinnerMissingFromCandidates)
        );
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn adaptive_route_skips_race_when_cached_winner_is_healthy() {
        let route_key = "adaptive-route-healthy-winner:443";
        clear_route_state_for_test(route_key);
        if let Ok(mut guard) = DEST_ROUTE_WINNER
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.insert(
                route_key.to_owned(),
                RouteWinner {
                    route_id: "direct".to_owned(),
                    updated_at_unix: now_unix_secs(),
                },
            );
        }
        let candidates = vec![
            RouteCandidate::direct("test"),
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1),
        ];
        let decision = route_race_decision(443, route_key, &candidates);
        assert_eq!(decision, (false, RouteRaceReason::WinnerHealthy));
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn snapshot_last_seen_uses_route_state_timestamps() {
        let mut entry = ClassifierSnapshotEntry {
            stats: DestinationClassifier {
                last_seen_unix: 9,
                ..DestinationClassifier::default()
            },
            ..ClassifierSnapshotEntry::default()
        };
        entry.route_winner = Some(RouteWinner {
            route_id: "direct".to_owned(),
            updated_at_unix: 13,
        });
        entry.route_health.insert(
            "direct".to_owned(),
            RouteHealth {
                last_failure_unix: 17,
                ..RouteHealth::default()
            },
        );

        assert_eq!(snapshot_entry_last_seen_unix(&entry), 17);
    }

    #[test]
    fn soft_zero_reply_marks_tls_no_reply_with_client_hello_sized_payload() {
        assert!(should_mark_route_soft_zero_reply(443, 517, 0));
        assert!(!should_mark_route_soft_zero_reply(443, 200, 0));
        assert!(!should_mark_route_soft_zero_reply(443, 517, 1));
        assert!(!should_mark_route_soft_zero_reply(80, 517, 0));
    }

    #[test]
    fn route_soft_zero_reply_immediately_sets_weak_cooldown() {
        let route_key = "adaptive-route-soft-zero:443";
        clear_route_state_for_test(route_key);
        let candidate = RouteCandidate::bypass(
            "test",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            1,
        );
        record_route_failure(route_key, &candidate, "zero-reply-soft");
        assert!(route_is_temporarily_weak(
            route_key,
            &candidate.route_id(),
            now_unix_secs()
        ));
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn global_bypass_health_reorders_profiles_without_service_rules() {
        clear_global_bypass_health_for_test();
        let now = now_unix_secs();
        if let Ok(mut guard) = GLOBAL_BYPASS_PROFILE_HEALTH
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.insert(
                "bypass:1".to_owned(),
                BypassProfileHealth {
                    failures: 5,
                    connect_failures: 2,
                    last_failure_unix: now,
                    ..BypassProfileHealth::default()
                },
            );
            guard.insert(
                "bypass:2".to_owned(),
                BypassProfileHealth {
                    successes: 6,
                    last_success_unix: now,
                    ..BypassProfileHealth::default()
                },
            );
        }
        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec![
                "127.0.0.1:19080".parse().expect("addr"),
                "127.0.0.1:19081".parse().expect("addr"),
            ],
            ..RelayOptions::default()
        };
        let route_key = "global-bypass-health:443";
        clear_route_state_for_test(route_key);
        let candidates = select_route_candidates(
            &relay_opts,
            &TargetAddr::Domain("example.org".to_owned()),
            443,
            "example.org:443",
        );
        let ordered = ordered_route_candidates(route_key, candidates);
        let pos1 = ordered
            .iter()
            .position(|c| c.route_id() == "bypass:1")
            .expect("bypass:1 present");
        let pos2 = ordered
            .iter()
            .position(|c| c.route_id() == "bypass:2")
            .expect("bypass:2 present");
        assert!(pos2 < pos1);
        clear_global_bypass_health_for_test();
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn route_order_prefers_direct_when_scores_are_equal() {
        clear_global_bypass_health_for_test();
        let route_key = "route-order-direct-first:443";
        clear_route_state_for_test(route_key);
        let candidates = vec![
            RouteCandidate::direct("test"),
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1),
        ];
        let ordered = ordered_route_candidates(route_key, candidates);
        assert_eq!(ordered.first().map(|c| c.route_id()), Some("direct".to_owned()));
        clear_route_state_for_test(route_key);
    }
}
