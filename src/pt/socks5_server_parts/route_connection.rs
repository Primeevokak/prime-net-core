use super::*;
use crate::config::EngineConfig;
use crate::pt::direct::DirectOutbound;

pub async fn connect_route_candidate(
    conn_id: u64,
    target: &TargetEndpoint,
    target_label: &str,
    candidate: &RouteCandidate,
    outbound: DynOutbound,
    relay_opts: &RelayOptions,
    cfg: Arc<EngineConfig>,
) -> Result<BoxStream> {
    match candidate.kind {
        RouteKind::Direct => {
            let resolver = outbound.resolver().ok_or_else(|| EngineError::Internal("outbound resolver missing".to_owned()))?;
            let direct = DirectOutbound::new(resolver);
            direct
                .connect((*target).clone())
                .await
        }
        RouteKind::Bypass => {
            let bypass_addr = candidate
                .bypass_addr
                .ok_or_else(|| EngineError::Config("bypass address missing".to_owned()))?;
            
            connect_bypass_upstream(
                conn_id,
                target,
                target_label,
                bypass_addr,
                candidate.bypass_profile_idx,
                candidate.bypass_profile_total,
                None, 
                cfg,
                relay_opts.clone(),
            )
            .await
            .map(|stream| Box::new(stream) as BoxStream)
        }
    }
}

pub fn route_decision_key(destination: &str, target: &TargetAddr, cfg: &EngineConfig) -> String {
    format!(
        "{}|{}",
        route_state_key(destination, cfg),
        route_family_for_target(target).label()
    )
}

pub fn route_destination_key(route_key: &str) -> &str {
    route_key.split('|').next().unwrap_or(route_key)
}

pub fn is_expected_disconnect(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted
    )
}

fn reap_route_race_losers_v2(
    mut losers: JoinSet<Result<(RouteCandidate, BoxStream)>>,
    conn_id: u64,
    target_label: String,
) {
    tokio::spawn(async move {
        while let Some(joined) = losers.join_next().await {
            if let Ok(Ok((candidate, stream))) = joined {
                drop(stream);
                debug!(
                    target: "socks5",
                    conn_id,
                    destination = %target_label,
                    route = candidate.route_label(),
                    "closed losing raced route connection"
                );
            }
        }
    });
}

pub async fn connect_via_best_route(
    conn_id: u64,
    target: &TargetEndpoint,
    target_label: &str,
    candidates: Vec<RouteCandidate>,
    outbound: DynOutbound,
    relay_opts: &RelayOptions,
    cfg: &EngineConfig,
    initial_client_data: Option<Vec<u8>>,
) -> Result<ConnectedRoute> {
    let decision_id = begin_route_decision_event(target_label, &candidates, false, cfg);
    let initial_data_ref = initial_client_data.as_ref();

    let (race, _reason) = route_race_decision(target.port, target_label, &candidates, cfg);
    if !race {
        // Sequential fallback
        let mut last_err = None;
        let mut last_failed_candidate: Option<RouteCandidate> = None;
        for candidate in candidates {
            match connect_route_candidate(
                conn_id,
                target,
                target_label,
                &candidate,
                outbound.clone(),
                relay_opts,
                Arc::new(cfg.clone()),
            )
            .await
            {
                Ok(mut stream) => {
                    if let Some(data) = initial_data_ref {
                        if candidate.kind == RouteKind::Direct && relay_opts.fragment_client_hello && is_tls_client_hello(data) {
                            let _ = fragment_and_send_tls_hello(data, &mut stream, relay_opts).await;
                        } else {
                            let _ = stream.write_all(data).await;
                        }
                    }
                    record_route_success(target_label, &candidate, cfg);
                    record_route_selected(&candidate, false);
                    return Ok(ConnectedRoute {
                        stream,
                        candidate: candidate.clone(),
                        route_key: target_label.to_owned(),
                        raced: false,
                        decision_id,
                    });
                }
                Err(e) => {
                    maybe_mark_route_capability_failure(&candidate, &e);
                    if !should_ignore_route_failure(&candidate, &e)
                        && !is_noise_probe_https_destination(route_destination_key(target_label))
                    {
                        record_route_failure(target_label, &candidate, "connect-failed", cfg);
                    }
                    last_failed_candidate = Some(candidate.clone());
                    last_err = Some(e);
                }
            }
        }
        complete_route_outcome_event(
            decision_id,
            target_label,
            last_failed_candidate.as_ref(),
            false,
            false,
            0,
            0,
            "connect-failed",
            cfg,
        );
        return Err(last_err.unwrap_or_else(|| {
            EngineError::Internal("all route candidates failed sequentially".to_owned())
        }));
    }

    let mut winners = JoinSet::new();
    let launch = route_race_launch_candidates(&candidates, target_label, cfg);
    let launched_ids: std::collections::HashSet<String> = launch
        .iter()
        .map(|candidate| candidate.route_id())
        .collect();
    let direct_present = candidates.iter().any(|c| c.kind == RouteKind::Direct);
    
    let race_start = Instant::now();

    for (idx, cand) in launch.into_iter().enumerate() {
        let delay = route_race_candidate_delay_ms(idx, &cand, direct_present, target_label);
        let outbound_c = outbound.clone();
        let target_c = (*target).clone();
        let target_label_c = target_label.to_owned();
        let relay_opts_c = (*relay_opts).clone();
        let initial_data_c = initial_client_data.clone();
        let cfg_c = cfg.clone();

        winners.spawn(async move {
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let res = connect_route_candidate(
                conn_id,
                &target_c,
                &target_label_c,
                &cand,
                outbound_c,
                &relay_opts_c,
                Arc::new(cfg_c),
            )
            .await;

            match res {
                Ok(mut stream) => {
                    if let Some(data) = initial_data_c {
                        if cand.kind == RouteKind::Direct && relay_opts_c.fragment_client_hello && is_tls_client_hello(&data) {
                            let _ = fragment_and_send_tls_hello(&data, &mut stream, &relay_opts_c).await;
                        } else {
                            let _ = stream.write_all(&data).await;
                        }
                    }
                    Ok((cand, stream))
                }
                Err(e) => Err(e),
            }
        });
    }

    let mut last_err = None;

    while let Some(res) = winners.join_next().await {
        let (candidate, stream) = match res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                last_err = Some(e);
                continue;
            }
            Err(e) => {
                warn!(target: "socks5", conn_id, error = %e, "route race worker task failed");
                continue;
            }
        };

        let bucket = host_service_bucket(target_label, cfg);
        let is_censored_or_google = matches!(
            bucket.as_str(),
            "meta-group:youtube" | "meta-group:discord" | "meta-group:google"
        );

        if candidate.kind == RouteKind::Direct && is_censored_or_google {
            let elapsed = race_start.elapsed().as_millis() as u64;
            if elapsed < 250 {
                let wait_more = 250 - elapsed;
                match tokio::time::timeout(Duration::from_millis(wait_more), winners.join_next()).await {
                    Ok(Some(joined)) => {
                        if let Ok(Ok((next_cand, next_stream))) = joined {
                            if next_cand.kind == RouteKind::Bypass {
                                drop(stream); 
                                winners.abort_all();
                                reap_route_race_losers_v2(winners, conn_id, target_label.to_owned());
                                record_route_success(target_label, &next_cand, cfg);
                                record_route_selected(&next_cand, true);
                                return Ok(ConnectedRoute {
                                    stream: next_stream,
                                    candidate: next_cand,
                                    route_key: target_label.to_owned(),
                                    raced: true,
                                    decision_id,
                                });
                            } else {
                                drop(next_stream);
                            }
                        }
                    }
                    _ => {} 
                }
            }
        }

        winners.abort_all();
        reap_route_race_losers_v2(winners, conn_id, target_label.to_owned());
        record_route_success(target_label, &candidate, cfg);
        record_route_selected(&candidate, true);
        return Ok(ConnectedRoute {
            stream,
            candidate,
            route_key: target_label.to_owned(),
            raced: true,
            decision_id,
        });
    }

    let mut last_failed_candidate: Option<RouteCandidate> = None;
    for candidate in candidates
        .iter()
        .filter(|candidate| !launched_ids.contains(&candidate.route_id()))
    {
        match connect_route_candidate(
            conn_id,
            target,
            target_label,
            candidate,
            outbound.clone(),
            relay_opts,
            Arc::new(cfg.clone()),
        )
        .await
        {
            Ok(mut stream) => {
                if let Some(data) = initial_data_ref {
                    if let Err(e) = stream.write_all(data).await {
                        maybe_mark_route_capability_failure(candidate, &EngineError::from(e));
                        last_failed_candidate = Some(candidate.clone());
                        continue;
                    }
                }

                record_route_success(target_label, candidate, cfg);
                record_route_selected(candidate, false);
                return Ok(ConnectedRoute {
                    stream,
                    candidate: candidate.clone(),
                    route_key: target_label.to_owned(),
                    raced: false,
                    decision_id,
                });
            }
            Err(e) => {
                maybe_mark_route_capability_failure(candidate, &e);
                if !should_ignore_route_failure(candidate, &e)
                    && !is_noise_probe_https_destination(route_destination_key(target_label))
                {
                    record_route_failure(target_label, candidate, "connect-failed", cfg);
                }
                last_failed_candidate = Some(candidate.clone());
                last_err = Some(e);
            }
        }
    }

    complete_route_outcome_event(
        decision_id,
        target_label,
        last_failed_candidate.as_ref(),
        false,
        false,
        0,
        0,
        "connect-failed",
        cfg,
    );
    Err(last_err.unwrap_or_else(|| EngineError::Internal("all route candidates failed".to_owned())))
}

pub async fn handle_socks5_request(
    conn_id: u64,
    mut tcp: TcpStream,
    _peer: SocketAddr,
    _client: SocketAddr,
    outbound: DynOutbound,
    relay_opts: Arc<RelayOptions>,
    cfg: Arc<EngineConfig>,
    silent_drop: bool,
) -> Result<()> {
    let mut header = [0u8; 3];
    tcp.read_exact(&mut header).await?;
    let ver = header[0];
    let cmd = header[1];
    if ver != 0x05 || cmd != 0x01 {
        return silent_or_err(&mut tcp, silent_drop, "socks5 version/cmd mismatch").await;
    }

    let target = match read_socks5_target_endpoint(&mut tcp).await {
        Ok(t) => t,
        Err(e) => return silent_or_err(&mut tcp, silent_drop, &e.to_string()).await,
    };
    let target_label = route_decision_key(&target.to_string(), &target.addr, &cfg);
    let candidates = select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg);
    let ordered = ordered_route_candidates(&target_label, candidates, &cfg);

    match connect_via_best_route(
        conn_id,
        &target,
        &target_label,
        ordered,
        outbound,
        &relay_opts,
        &cfg,
        None,
    )
    .await
    {
        Ok(mut connected) => {
            tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.map_err(EngineError::from)?;

            let mut tuned = tune_relay_for_target(
                (*relay_opts).clone(),
                target.port,
                &target_label,
                false,
                connected.candidate.kind == RouteKind::Bypass,
            );
            if connected.candidate.kind == RouteKind::Bypass {
                tuned.options.fragment_client_hello = false;
            }

            let relay_started = Instant::now();
            match relay_bidirectional(&mut tcp, &mut connected.stream, tuned.options, Vec::new()).await {
                Ok((c2u, u2c)) => {
                    info!(target: "socks5", conn_id, bytes_c2u = c2u, bytes_u2c = u2c, duration_ms = relay_started.elapsed().as_millis(), "session finished normally");
                    complete_route_outcome_event(
                        connected.decision_id,
                        &connected.route_key,
                        Some(&connected.candidate),
                        true,
                        u2c > 0,
                        u2c,
                        relay_started.elapsed().as_millis() as u64,
                        "ok",
                        &cfg,
                    );
                }
                Err(e) => {
                    let lifetime_ms = relay_started.elapsed().as_millis() as u64;
                    if is_expected_disconnect(&e) {
                        info!(target: "socks5", conn_id, error = %e, lifetime_ms, "session finished with expected disconnect");
                        let mut error_class = "client-disconnect";
                        if should_penalize_disconnect_as_soft_zero_reply(
                            &connected.route_key,
                            &connected.candidate,
                            lifetime_ms,
                            &cfg,
                        ) {
                            record_route_failure(
                                &connected.route_key,
                                &connected.candidate,
                                "zero-reply-soft",
                                &cfg,
                            );
                            error_class = "zero-reply-soft";
                        }
                        complete_route_outcome_event(
                            connected.decision_id,
                            &connected.route_key,
                            Some(&connected.candidate),
                            true,
                            false,
                            0,
                            lifetime_ms,
                            error_class,
                            &cfg,
                        );
                    } else {
                        warn!(target: "socks5", conn_id, error = %e, lifetime_ms, "session finished with relay error");
                        complete_route_outcome_event(
                            connected.decision_id,
                            &connected.route_key,
                            Some(&connected.candidate),
                            true,
                            false,
                            0,
                            lifetime_ms,
                            "relay-io",
                            &cfg,
                        );
                    }
                }
            }
            Ok(())
        }
        Err(e) => silent_or_err(&mut tcp, silent_drop, &e.to_string()).await,
    }
}

pub async fn handle_client(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    listen_addr: SocketAddr,
    outbound: DynOutbound,
    cfg: Arc<EngineConfig>,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    let client_label = resolve_client_label(peer, listen_addr).await;
    debug!(target: "socks5", conn_id, client = %client_label, peer = %peer, "NEW connection accepted");
    let _ = tcp.set_nodelay(true);

    let mut hdr = [0u8; 2];
    if let Err(e) = tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut hdr)).await {
        debug!(target: "socks5", conn_id, "failed to read SOCKS version/nmethods: {}", e);
        return Ok(());
    }
    
    if hdr[0] != 0x05 {
        if hdr[0] == 0 {
            return Ok(());
        }
        if hdr[0] == 0x04 {
            return handle_socks4(
                conn_id,
                tcp,
                peer,
                client_label,
                outbound,
                cfg,
                hdr[1],
                silent_drop,
                relay_opts,
            )
            .await;
        }
        if hdr[0].is_ascii_alphabetic() {
            return handle_http_proxy(conn_id, tcp, peer, client_label, outbound, cfg, hdr, relay_opts).await;
        }
        return silent_or_err(&mut tcp, silent_drop, "SOCKS5 invalid version").await;
    }

    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if let Err(e) = tcp.read_exact(&mut methods).await {
        warn!(target: "socks5", conn_id, "failed to read auth methods: {}", e);
        return Ok(());
    }
    
    tcp.write_all(&[0x05, 0x00])
        .await
        .map_err(EngineError::Io)?;

    let mut req_hdr = [0u8; 4];
    if let Err(e) = tcp.read_exact(&mut req_hdr).await {
        warn!(target: "socks5", conn_id, "failed to read request header: {}", e);
        return Ok(());
    }
    
    if req_hdr[1] != 0x01 {
        warn!(target: "socks5", conn_id, cmd = req_hdr[1], "unsupported SOCKS5 command");
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
        _ => {
            warn!(target: "socks5", conn_id, atyp = req_hdr[3], "invalid SOCKS5 atyp");
            return silent_or_err(&mut tcp, silent_drop, "SOCKS5 invalid atyp").await;
        }
    };

    let mut port_bytes = [0u8; 2];
    tcp.read_exact(&mut port_bytes).await.map_err(EngineError::Io)?;
    let port = u16::from_be_bytes(port_bytes);
    
    let _target = TargetEndpoint { addr: target_addr, port };

    handle_socks5_request(
        conn_id,
        tcp,
        peer,
        peer,
        outbound,
        Arc::new(relay_opts),
        cfg,
        silent_drop,
    ).await
}

async fn silent_or_err(tcp: &mut TcpStream, silent: bool, msg: &str) -> Result<()> {
    if !silent {
        let _ = tcp
            .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
    }
    Err(EngineError::Internal(msg.to_owned()))
}

pub async fn read_socks5_target_endpoint(tcp: &mut TcpStream) -> Result<TargetEndpoint> {
    let mut atyp_buf = [0u8; 1];
    tcp.read_exact(&mut atyp_buf).await.map_err(EngineError::Io)?;
    
    let addr = match atyp_buf[0] {
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
        _ => return Err(EngineError::Internal("invalid SOCKS5 atyp".to_owned())),
    };

    let mut port_bytes = [0u8; 2];
    tcp.read_exact(&mut port_bytes).await.map_err(EngineError::Io)?;
    let port = u16::from_be_bytes(port_bytes);
    
    Ok(TargetEndpoint { addr, port })
}

pub async fn resolve_client_label(peer: SocketAddr, _listen_addr: SocketAddr) -> String {
    format!("client-{}", peer)
}
