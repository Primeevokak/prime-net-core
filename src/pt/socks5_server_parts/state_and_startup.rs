static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);
static WARNED_SOCKS4_LIMITATIONS: AtomicBool = AtomicBool::new(false);
static WARNED_SOCKS4_AGGRESSIVE: AtomicBool = AtomicBool::new(false);

static DEST_FAILURES: OnceLock<DashMap<String, u8>> = OnceLock::new();
static DEST_PREFERRED_STAGE: OnceLock<DashMap<String, u8>> = OnceLock::new();
static DEST_CLASSIFIER: OnceLock<DashMap<String, DestinationClassifier>> = OnceLock::new();
static DEST_BYPASS_PROFILE_IDX: OnceLock<DashMap<String, u8>> = OnceLock::new();
static DEST_BYPASS_PROFILE_FAILURES: OnceLock<DashMap<String, u8>> = OnceLock::new();
static GLOBAL_BYPASS_PROFILE_HEALTH: OnceLock<DashMap<String, BypassProfileHealth>> =
    OnceLock::new();
static DEST_ROUTE_WINNER: OnceLock<DashMap<String, RouteWinner>> = OnceLock::new();
static DEST_ROUTE_HEALTH: OnceLock<DashMap<String, DashMap<String, RouteHealth>>> =
    OnceLock::new();
static STAGE_RACE_STATS: OnceLock<DashMap<u8, StageRaceStats>> = OnceLock::new();
static RACE_SOURCE_COUNTERS: OnceLock<RaceSourceCounters> = OnceLock::new();
static ROUTE_METRICS: OnceLock<RwLock<RouteMetrics>> = OnceLock::new();
static ROUTE_CAPABILITIES: OnceLock<RwLock<RouteCapabilities>> = OnceLock::new();
static BYPASS_POOL: OnceLock<DashMap<SocketAddr, Vec<TcpStream>>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayOptions {
    pub fragment_client_hello: bool,
    pub split_at_sni: bool,
    pub client_hello_split_offsets: Vec<usize>,
    pub fragment_size_min: usize,
    pub fragment_size_max: usize,
    pub randomize_fragment_size: bool,
    pub fragment_sleep_ms: u64,
    pub fragment_budget_bytes: usize,
    pub tcp_window_trick: bool,
    pub tcp_window_size: u16,
    pub sni_spoofing: bool,
    pub sni_case_toggle: bool,
    pub classifier_persist_enabled: bool,
    pub classifier_cache_path: String,
    pub classifier_entry_ttl_secs: u64,
    pub classifier_emit_interval_secs: u64,
    pub strategy_race_enabled: bool,
    pub suspicious_zero_reply_min_c2u: usize,
    pub stage1_failures: u8,
    pub stage2_failures: u8,
    pub stage3_failures: u8,
    pub udp_padding_range: Option<(usize, usize)>,
    pub block_quic: bool,
    pub upstream_socks5: Option<SocketAddr>,
    pub bypass_socks5: Option<SocketAddr>,
    pub bypass_socks5_pool: Vec<SocketAddr>,
    #[serde(skip)]
    pub bypass_domain_check: Option<fn(&str) -> bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum StageSelectionSource {
    #[default]
    Adaptive,
    Cache,
    Probe,
}

#[derive(Debug, Clone, Default)]
pub struct TunedRelay {
    pub options: RelayOptions,
    pub stage: u8,
    pub source: StageSelectionSource,
}

#[derive(Debug, Default)]
pub struct RaceSourceCounters {
    pub cache: AtomicU64,
    pub probe: AtomicU64,
    pub adaptive: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct RouteMetrics {
    pub route_selected_direct: u64,
    pub route_selected_bypass: u64,
    pub race_started: u64,
    pub race_skipped: u64,
    pub race_winner_direct: u64,
    pub race_winner_bypass: u64,
    pub route_success_direct: u64,
    pub route_success_bypass: u64,
    pub route_failure_direct: u64,
    pub route_failure_bypass: u64,
    pub route_soft_zero_reply_direct: u64,
    pub route_soft_zero_reply_bypass: u64,
    pub connect_failure_direct: u64,
    pub connect_failure_bypass: u64,
    pub winner_cache_hits: u64,
    pub winner_cache_misses: u64,
    pub race_reason_no_winner: u64,
    pub race_reason_empty_winner: u64,
    pub race_reason_winner_stale: u64,
    pub race_reason_winner_weak: u64,
    pub race_reason_winner_missing: u64,
    pub race_reason_winner_healthy: u64,
    pub race_reason_single_candidate: u64,
    pub race_reason_non_tls: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DestinationClassifier {
    pub failures: u64,
    pub resets: u64,
    pub timeouts: u64,
    pub silent_drops: u64,
    pub early_closes: u64,
    pub broken_pipes: u64,
    pub suspicious_zero_replies: u64,
    pub successes: u64,
    pub last_seen_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageRaceStats {
    pub successes: u64,
    pub failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Direct,
    Bypass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteIpFamily {
    Any,
    V4,
    V6,
}

impl RouteIpFamily {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteCandidate {
    pub source: &'static str,
    pub kind: RouteKind,
    pub bypass_addr: Option<SocketAddr>,
    pub bypass_profile_idx: u8,
    pub bypass_profile_total: u8,
    pub family: RouteIpFamily,
}

impl RouteCandidate {
    pub fn direct(source: &'static str) -> Self {
        Self {
            source,
            kind: RouteKind::Direct,
            bypass_addr: None,
            bypass_profile_idx: 0,
            bypass_profile_total: 0,
            family: RouteIpFamily::Any,
        }
    }

    pub fn direct_with_family(source: &'static str, family: RouteIpFamily) -> Self {
        Self {
            source,
            kind: RouteKind::Direct,
            bypass_addr: None,
            bypass_profile_idx: 0,
            bypass_profile_total: 0,
            family,
        }
    }

    pub fn bypass(source: &'static str, addr: SocketAddr, idx: u8, total: u8) -> Self {
        Self {
            source,
            kind: RouteKind::Bypass,
            bypass_addr: Some(addr),
            bypass_profile_idx: idx,
            bypass_profile_total: total,
            family: RouteIpFamily::Any,
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
            source,
            kind: RouteKind::Bypass,
            bypass_addr: Some(addr),
            bypass_profile_idx: idx,
            bypass_profile_total: total,
            family,
        }
    }

    pub fn route_id(&self) -> String {
        match self.kind {
            RouteKind::Direct => "direct".to_owned(),
            RouteKind::Bypass => format!("bypass:{}", self.bypass_profile_idx + 1),
        }
    }

    pub fn route_label(&self) -> String {
        match self.kind {
            RouteKind::Direct => "direct".to_owned(),
            RouteKind::Bypass => format!("bypass:{}", self.bypass_profile_idx + 1),
        }
    }

    pub fn kind_rank(&self) -> u8 {
        match self.kind {
            RouteKind::Direct => 0,
            RouteKind::Bypass => 1,
        }
    }
}

pub struct ConnectedRoute {
    pub stream: BoxStream,
    pub candidate: RouteCandidate,
    pub route_key: String,
    pub raced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRaceReason {
    NoWinner,
    EmptyWinner,
    WinnerStale,
    WinnerMissingFromCandidates,
    WinnerWeak,
    WinnerHealthy,
    SingleCandidate,
    NonTlsPort,
}

#[derive(Debug, Clone, Default)]
pub struct RouteCapabilities {
    pub direct_v4_weak_until_unix: u64,
    pub direct_v6_weak_until_unix: u64,
    pub bypass_v4_weak_until_unix: u64,
    pub bypass_v6_weak_until_unix: u64,
}

#[derive(Debug)]
pub struct Socks5ServerGuard {
    listen_addr: SocketAddr,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl Socks5ServerGuard {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

pub async fn start_socks5_server(
    bind: &str,
    outbound: Arc<dyn OutboundConnector>,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<Socks5ServerGuard> {
    let listener = TcpListener::bind(bind).await.map_err(EngineError::Io)?;
    let listen_addr = listener.local_addr().map_err(EngineError::Io)?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    let outbound = Arc::new(outbound);
    let relay_opts = Arc::new(relay_opts);
    
    init_classifier_store(&relay_opts);
    load_classifier_store_if_needed();

    tokio::spawn(async move {
        info!(target: "socks5", listen_addr = %listen_addr, silent_drop, "SOCKS5 server started");
        let mut join_set = JoinSet::new();

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((tcp, peer)) => {
                            let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::SeqCst);
                            let relay_opts_val = (*relay_opts).clone();
                            let outbound = outbound.clone();
                            join_set.spawn(async move {
                                if let Err(e) = handle_client(conn_id, tcp, peer, listen_addr, outbound, silent_drop, relay_opts_val).await {
                                    debug!(target: "socks5", conn_id, error = %e, "client session failed");
                                }
                            });
                        }
                        Err(e) => {
                            error!(target: "socks5", error = %e, "failed to accept connection");
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    info!(target: "socks5", "SOCKS5 server shutting down");
                    break;
                }
            }
        }
        join_set.shutdown().await;
    });

    Ok(Socks5ServerGuard {
        listen_addr,
        shutdown_tx,
    })
}

async fn connect_bypass_upstream(
    conn_id: u64,
    target: &TargetEndpoint,
    target_label: &str,
    bypass_addr: SocketAddr,
    bypass_profile_idx: u8,
    bypass_profile_total: u8,
    resolver: Option<Arc<ResolverChain>>,
) -> Result<TcpStream> {
    // 1. Try to get a connection from the pool
    let mut pooled_bypass = None;
    let pool_map = BYPASS_POOL.get_or_init(DashMap::new);
    
    loop {
        let s_opt = pool_map.get_mut(&bypass_addr).and_then(|mut list| list.pop());
        
        let s = match s_opt {
            Some(s) => s,
            None => break,
        };

        let mut buf = [0u8; 1];
        match tokio::time::timeout(std::time::Duration::from_millis(1), s.peek(&mut buf)).await {
            Ok(Ok(0)) => {
                debug!(target: "socks5", conn_id, bypass = %bypass_addr, "discarding dead pooled connection");
                continue;
            }
            Ok(Ok(_)) => {
                pooled_bypass = Some(s);
                break;
            }
            Ok(Err(_)) => {
                continue;
            }
            Err(_) => {
                pooled_bypass = Some(s);
                break;
            }
        }
    }

    let mut bypass = if let Some(s) = pooled_bypass {
        debug!(target: "socks5", conn_id, bypass = %bypass_addr, "reusing live pooled bypass connection");
        s
    } else {
        let pool_addr = bypass_addr;
        tokio::spawn(async move {
            let pool_map = BYPASS_POOL.get_or_init(DashMap::new);
            let current_len = pool_map.get(&pool_addr).map(|l| l.len()).unwrap_or(0);
            if current_len < 4 {
                if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(pool_addr)).await {
                    let _ = s.set_nodelay(true);
                    pool_map.entry(pool_addr).or_default().push(s);
                }
            }
        });

        let mut last_e = None;
        let mut connected = None;
        for _ in 0..2 {
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(bypass_addr)).await {
                Ok(Ok(s)) => {
                    connected = Some(s);
                    break;
                }
                Ok(Err(e)) => last_e = Some(e),
                Err(_) => {}
            }
        }
        match connected {
            Some(s) => s,
            None => {
                let e = last_e.unwrap_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "bypass connect timeout")
                });
                warn!(target: "socks5", conn_id, destination = %target_label, bypass = %bypass_addr, error = %e, "bypass connect failed after retries");
                record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "connect-failed");
                return Err(e.into());
            }
        }
    };

    let _ = bypass.set_nodelay(true);

    let resolved_target_addr = if let TargetAddr::Domain(host) = &target.addr {
        if let Some(r) = &resolver {
            match r.resolve(host).await {
                Ok(ips) if !ips.is_empty() => {
                    let picked_ip = if host.contains("discord") {
                        ips.iter().find(|ip| ip.is_ipv4()).copied().unwrap_or(ips[0])
                    } else {
                        ips[0]
                    };
                    debug!(target: "socks5", conn_id, host, ip = %picked_ip, "resolved domain for bypass via internal resolver");
                    Some(TargetAddr::Ip(picked_ip))
                }
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    let addr_to_send = resolved_target_addr.as_ref().unwrap_or(&target.addr);

    if let Err(e) = bypass.write_all(&[0x05, 0x01, 0x00]).await {
        record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "handshake-io");
        return Err(e.into());
    }
    let mut method = [0u8; 2];
    if let Err(e) = bypass.read_exact(&mut method).await {
        record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "handshake-io");
        return Err(e.into());
    }
    if method[0] != 0x05 || method[1] != 0x00 {
        record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "auth-rejected");
        return Err(EngineError::Internal(format!("bypass socks5 auth rejected: {:02x} {:02x}", method[0], method[1])));
    }

    let mut req: Vec<u8> = vec![0x05, 0x01, 0x00];
    match addr_to_send {
        TargetAddr::Domain(host) => {
            let b = host.as_bytes();
            if b.len() > 255 { return Err(EngineError::Internal("bypass domain too long".to_owned())); }
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
    if let Err(e) = bypass.write_all(&req).await {
        record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "handshake-io");
        return Err(e.into());
    }

    let mut reply_hdr = [0u8; 4];
    if let Err(e) = bypass.read_exact(&mut reply_hdr).await {
        record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "handshake-io");
        return Err(e.into());
    }
    if reply_hdr[0] != 0x05 {
        record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "invalid-reply-version");
        return Err(EngineError::Internal(format!("bypass socks5 invalid reply version: 0x{:02x}", reply_hdr[0])));
    }
    if reply_hdr[1] != 0x00 {
        record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "rep-nonzero");
        return Err(EngineError::Internal(format!("ciadpi rejected connect: REP=0x{:02x}", reply_hdr[1])));
    }
    match reply_hdr[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            if let Err(e) = bypass.read_exact(&mut b).await {
                record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "handshake-io");
                return Err(e.into());
            }
        }
        0x03 => {
            let mut l = [0u8; 1];
            if let Err(e) = bypass.read_exact(&mut l).await {
                record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "handshake-io");
                return Err(e.into());
            }
            let mut b = vec![0u8; l[0] as usize + 2];
            if let Err(e) = bypass.read_exact(&mut b).await {
                record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "handshake-io");
                return Err(e.into());
            }
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            if let Err(e) = bypass.read_exact(&mut b).await {
                record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "handshake-io");
                return Err(e.into());
            }
        }
        other => {
            record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "invalid-addr-type");
            return Err(EngineError::Internal(format!("bypass invalid addr type: 0x{other:02x}")));
        }
    }

    Ok(bypass)
}
