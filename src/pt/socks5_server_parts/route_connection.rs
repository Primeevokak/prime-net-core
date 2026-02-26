use super::*;

pub async fn connect_route_candidate(
    conn_id: u64,
    target: &TargetEndpoint,
    target_label: &str,
    candidate: &RouteCandidate,
    outbound: DynOutbound,
    _relay_opts: &RelayOptions,
) -> Result<BoxStream> {
    match candidate.kind {
        RouteKind::Direct => {
            let res = outbound.connect((*target).clone()).await?;
            Ok(res)
        }
        RouteKind::Bypass => {
            let addr = candidate.bypass_addr.ok_or_else(|| {
                EngineError::Internal("bypass route candidate missing address".to_owned())
            })?;
            let res = connect_bypass_upstream(
                conn_id,
                target,
                target_label,
                addr,
                candidate.bypass_profile_idx,
                candidate.bypass_profile_total,
                outbound.resolver(),
            )
            .await?;
            Ok(Box::new(res))
        }
    }
}

pub fn maybe_mark_route_capability_failure(candidate: &RouteCandidate, e: &EngineError) {
    if candidate.family == RouteIpFamily::Any {
        return;
    }
    let msg = e.to_string().to_lowercase();
    if msg.contains("socks5 invalid reply version") || msg.contains("auth rejected") || msg.contains("rejected connect: rep=0x03") {
        mark_route_capability_weak(candidate.kind, candidate.family, "rep-error", 120);
    }
}

pub fn should_ignore_route_failure(_candidate: &RouteCandidate, e: &EngineError) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("dns resolver returned only unspecified/sinkhole ips")
}

pub fn route_race_candidate_delay_ms(
    index: usize,
    candidate: &RouteCandidate,
    direct_present: bool,
    _destination: &str,
) -> u64 {
    if index == 0 {
        return 0;
    }
    let mut delay = ROUTE_RACE_BASE_DELAY_MS;
    if direct_present && candidate.kind == RouteKind::Bypass {
        delay += ROUTE_RACE_DIRECT_HEADSTART_MS;
        delay += match candidate.source {
            "builtin" => ROUTE_RACE_BYPASS_EXTRA_DELAY_BUILTIN_MS,
            "learned-domain" | "learned-ip" => ROUTE_RACE_BYPASS_EXTRA_DELAY_LEARNED_MS,
            _ => ROUTE_RACE_BYPASS_EXTRA_DELAY_MS,
        };
    }
    delay
}

pub fn route_race_launch_candidates(ordered: &[RouteCandidate]) -> Vec<RouteCandidate> {
    ordered
        .iter()
        .take(ROUTE_RACE_MAX_CANDIDATES)
        .cloned()
        .collect()
}

pub async fn connect_via_best_route(
    conn_id: u64,
    target: &TargetEndpoint,
    target_label: &str,
    candidates: Vec<RouteCandidate>,
    outbound: DynOutbound,
    relay_opts: &RelayOptions,
) -> Result<ConnectedRoute> {
    let (race, reason) = route_race_decision(target.port, target_label, &candidates);
    record_route_race_decision(race, reason);

    if !race {
        let candidate = candidates[0].clone();
        record_route_selected(&candidate, false);
        let stream = connect_route_candidate(conn_id, target, target_label, &candidate, outbound, relay_opts).await?;
        return Ok(ConnectedRoute {
            stream,
            candidate,
            route_key: target_label.to_owned(),
            raced: false,
        });
    }

    let mut winners = JoinSet::new();
    let launch = route_race_launch_candidates(&candidates);
    let direct_present = candidates.iter().any(|c| c.kind == RouteKind::Direct);

    for (idx, cand) in launch.into_iter().enumerate() {
        let delay = route_race_candidate_delay_ms(idx, &cand, direct_present, target_label);
        let outbound_c = outbound.clone();
        let target_c = (*target).clone();
        let target_label_c = target_label.to_owned();
        let relay_opts_c = (*relay_opts).clone();
        
        winners.spawn(async move {
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let res = connect_route_candidate(conn_id, &target_c, &target_label_c, &cand, outbound_c, &relay_opts_c).await;
            (cand, res)
        });
    }

    let mut last_err = None;
    while let Some(res) = winners.join_next().await {
        let (candidate, connect_res) = match res {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    target: "socks5",
                    conn_id,
                    error = %e,
                    "route race worker task failed"
                );
                last_err = Some(EngineError::Internal(format!(
                    "route race worker task failed: {e}"
                )));
                continue;
            }
        };
        match connect_res {
            Ok(stream) => {
                winners.abort_all();
                record_route_selected(&candidate, true);
                return Ok(ConnectedRoute {
                    stream,
                    candidate,
                    route_key: target_label.to_owned(),
                    raced: true,
                });
            }
            Err(e) => {
                maybe_mark_route_capability_failure(&candidate, &e);
                if !should_ignore_route_failure(&candidate, &e) {
                    last_err = Some(e);
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| EngineError::Internal("all route candidates failed".to_owned())))
}

pub(super) async fn resolve_client_label(peer: SocketAddr, listen_addr: SocketAddr) -> String {
    format!("client-{}-{}", peer, listen_addr)
}

pub async fn handle_client(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    listen_addr: SocketAddr,
    outbound: DynOutbound,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    let client = resolve_client_label(peer, listen_addr).await;
    debug!(target: "socks5", conn_id, client = %client, peer = %peer, "SOCKS5 client accepted");
    let _ = tcp.set_nodelay(true);

    let mut hdr = [0u8; 2];
    if tcp.read_exact(&mut hdr).await.is_err() {
        return Ok(());
    }
    if hdr[0] != 0x05 {
        if hdr[0] == 0x04 {
            return handle_socks4(conn_id, tcp, peer, client, outbound, hdr[1], silent_drop, relay_opts).await;
        }
        if hdr[0].is_ascii_alphabetic() {
            return handle_http_proxy(conn_id, tcp, peer, client, outbound, hdr, relay_opts).await;
        }
        return silent_or_err(&mut tcp, silent_drop, "SOCKS5 invalid version").await;
    }
    
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    tcp.read_exact(&mut methods).await.map_err(EngineError::Io)?;
    tcp.write_all(&[0x05, 0x00]).await.map_err(EngineError::Io)?;

    let mut req_hdr = [0u8; 4];
    tcp.read_exact(&mut req_hdr).await.map_err(EngineError::Io)?;
    if req_hdr[1] != 0x01 {
        return silent_or_err(&mut tcp, silent_drop, "SOCKS5 unsupported command").await;
    }

    let target_addr = match req_hdr[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            tcp.read_exact(&mut ip).await.map_err(EngineError::Io)?;
            TargetAddr::Ip(std::net::IpAddr::V4(ip.into()))
        }
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await.map_err(EngineError::Io)?;
            let mut host = vec![0u8; len[0] as usize];
            tcp.read_exact(&mut host).await.map_err(EngineError::Io)?;
            TargetAddr::Domain(String::from_utf8_lossy(&host).into_owned())
        }
        0x04 => {
            let mut ip = [0u8; 16];
            tcp.read_exact(&mut ip).await.map_err(EngineError::Io)?;
            TargetAddr::Ip(std::net::IpAddr::V6(ip.into()))
        }
        _ => return silent_or_err(&mut tcp, silent_drop, "SOCKS5 invalid atyp").await,
    };

    let mut port_bytes = [0u8; 2];
    tcp.read_exact(&mut port_bytes).await.map_err(EngineError::Io)?;
    let port = u16::from_be_bytes(port_bytes);
    let target = TargetEndpoint { addr: target_addr, port };
    let target_label = route_decision_key(&target.to_string(), &target.addr);

    let candidates = select_route_candidates(&relay_opts, &target.addr, target.port, &target_label);
    let ordered = ordered_route_candidates(&target_label, candidates);
    
    let is_bypass = ordered[0].kind == RouteKind::Bypass;
    let tuned = tune_relay_for_target(relay_opts.clone(), target.port, &target_label, false, is_bypass);

    match connect_via_best_route(conn_id, &target, &target_label, ordered, outbound, &relay_opts).await {
        Ok(mut connected) => {
            tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.map_err(EngineError::Io)?;
            let _ = relay_bidirectional(&mut tcp, &mut connected.stream, tuned.options).await;
            Ok(())
        }
        Err(e) => silent_or_err(&mut tcp, silent_drop, &e.to_string()).await,
    }
}

pub(super) async fn silent_or_err(tcp: &mut TcpStream, silent: bool, msg: &str) -> Result<()> {
    if !silent {
        let _ = tcp.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
    }
    Err(EngineError::Internal(msg.to_owned()))
}
