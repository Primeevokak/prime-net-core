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
            let resolver = outbound
                .resolver()
                .ok_or_else(|| EngineError::Internal("outbound resolver missing".to_owned()))?;
            let direct = DirectOutbound::new(resolver);
            direct.connect((*target).clone()).await
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
    let (race, reason) = route_race_decision(target.port, target_label, &candidates, cfg);
    record_route_race_decision(race, reason);
    let decision_id = begin_route_decision_event(target_label, &candidates, race, cfg);
    let initial_data_ref = initial_client_data.as_ref();

    info!(
        target: "socks5.route",
        conn_id,
        target_label,
        candidates_count = candidates.len(),
        race,
        ?reason,
        "starting route selection"
    );

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
                Ok(stream) => {
                    record_route_success(target_label, &candidate, cfg);
                    record_route_selected(&candidate, false);
                    return Ok(ConnectedRoute {
                        stream,
                        candidate: candidate.clone(),
                        route_key: target_label.to_owned(),
                        decision_id,
                        initial_client_data: initial_client_data.clone().unwrap_or_default(),
                        initial_upstream_data: Vec::new(),
                        client_data_sent: false,
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

    let mut winners: JoinSet<Result<(RouteCandidate, BoxStream, Vec<u8>, bool)>> = JoinSet::new();
    let launch = route_race_launch_candidates(&candidates, target_label, cfg);
    let launched_ids: std::collections::HashSet<String> = launch
        .iter()
        .map(|candidate| candidate.route_id())
        .collect();
    let direct_present = candidates.iter().any(|c| c.kind == RouteKind::Direct);

    for (idx, cand) in launch.into_iter().enumerate() {
        let delay = route_race_candidate_delay_ms(idx, &cand, direct_present, target_label, cfg);
        let outbound_c = outbound.clone();
        let target_c = (*target).clone();
        let target_label_c = target_label.to_owned();
        let relay_opts_c = (*relay_opts).clone();
        let initial_data_c = initial_client_data.clone();
        let cfg_c = cfg.clone();

        winners.spawn(async move {
            let start = Instant::now();
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let cfg_arc = Arc::new(cfg_c.clone());
            let res = connect_route_candidate(
                conn_id,
                &target_c,
                &target_label_c,
                &cand,
                outbound_c,
                &relay_opts_c,
                cfg_arc,
            )
            .await;

            let connect_elapsed = start.elapsed().as_millis();

            match res {
                Ok(mut stream) => {
                    let mut initial_u2c = Vec::new();
                    let mut client_data_sent = false;

                    if let Some(ref data) = initial_data_c {
                        if !data.is_empty() {
                            // Only perform Data Race verification for Direct routes.
                            // Bypass routes (local proxies) are verified by TCP connection success only.
                            if cand.kind == RouteKind::Direct && is_censored_domain(&target_label_c, &cfg_c) {
                                if let Err(e) = stream.write_all(data).await {
                                     info!(target: "socks5.route", conn_id, route = cand.route_label(), error = %e, "race worker failed to send initial data");
                                     return Err(e.into());
                                }
                                let _ = stream.flush().await;
                                client_data_sent = true;

                                let mut buf = [0u8; 1];
                                if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(2000), stream.read(&mut buf)).await {
                                    if n > 0 {
                                        initial_u2c.extend_from_slice(&buf[..n]);
                                    }
                                }
                            }
                        }
                    }
                    info!(
                        target: "socks5.route",
                        conn_id,
                        route = cand.route_label(),
                        connect_ms = connect_elapsed,
                        has_initial_u2c = !initial_u2c.is_empty(),
                        "race worker finished successfully"
                    );
                    Ok((cand, stream, initial_u2c, client_data_sent))
                }
                Err(e) => {
                    info!(
                        target: "socks5.route",
                        conn_id,
                        route = cand.route_label(),
                        connect_ms = connect_elapsed,
                        error = %e,
                        "race worker connection failed"
                    );
                    Err(e)
                }
            }
        });
    }

    let mut last_err = None;

    while let Some(res) = winners.join_next().await {
        let (candidate, stream, initial_u2c, client_data_sent) = match res {
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

        info!(
            target: "socks5.route",
            conn_id,
            route = candidate.route_label(),
            has_initial_data = !initial_u2c.is_empty(),
            initial_data_len = initial_u2c.len(),
            "selected race winner"
        );

        record_route_success(target_label, &candidate, cfg);
        record_route_selected(&candidate, true);
        
        reap_route_race_losers_v3(winners, conn_id, target_label.to_owned());

        return Ok(ConnectedRoute {
            stream,
            candidate,
            route_key: target_label.to_owned(),
            decision_id,
            initial_client_data: initial_client_data.clone().unwrap_or_default(),
            initial_upstream_data: initial_u2c,
            client_data_sent,
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
                    decision_id,
                    initial_client_data: initial_client_data.clone().unwrap_or_default(),
                    initial_upstream_data: Vec::new(),
                    client_data_sent: false,
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

pub async fn handle_socks5_request_with_target(
    conn_id: u64,
    mut tcp: TcpStream,
    _peer: SocketAddr,
    _client: SocketAddr,
    outbound: DynOutbound,
    relay_opts: Arc<RelayOptions>,
    cfg: Arc<EngineConfig>,
    silent_drop: bool,
    target: TargetEndpoint,
    initial_client_data: Vec<u8>,
) -> Result<()> {
    let target_label = route_decision_key(&target.to_string(), &target.addr, &cfg);
    let candidates =
        select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg);
    let ordered = ordered_route_candidates(&target_label, candidates, &cfg);

    match connect_via_best_route(
        conn_id,
        &target,
        &target_label,
        ordered,
        outbound,
        &relay_opts,
        &cfg,
        Some(initial_client_data),
    )
    .await
    {
        Ok(mut connected) => {
            info!(target: "socks5.route", conn_id, "route connection established, preparing relay");
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
            let is_censored = is_censored_domain(&connected.route_key, &cfg);

            let relay_res = if connected.candidate.kind == RouteKind::Direct && is_censored {
                relay_bidirectional_with_first_byte_timeout(
                    &mut tcp,
                    &mut connected.stream,
                    tuned.options.clone(),
                    connected.initial_client_data,
                    connected.initial_upstream_data,
                    connected.client_data_sent,
                    Duration::from_secs(7),
                ).await
            } else {
                relay_bidirectional(
                    &mut tcp, 
                    &mut connected.stream, 
                    tuned.options, 
                    connected.initial_client_data, 
                    connected.initial_upstream_data,
                    connected.client_data_sent
                ).await
            };

            match relay_res {
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
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    let lifetime_ms = relay_started.elapsed().as_millis() as u64;
                    warn!(
                        target: "socks5.route",
                        conn_id,
                        route_key = %connected.route_key,
                        route = connected.candidate.route_label(),
                        lifetime_ms,
                        "direct route timed out waiting for first byte; classifying as soft failure"
                    );
                    record_route_failure(
                        &connected.route_key,
                        &connected.candidate,
                        "zero-reply-soft",
                        &cfg,
                    );
                    complete_route_outcome_event(
                        connected.decision_id,
                        &connected.route_key,
                        Some(&connected.candidate),
                        true,
                        false,
                        0,
                        lifetime_ms,
                        "zero-reply-soft",
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
        info!(target: "socks5", conn_id, "failed to read SOCKS version/nmethods: {}", e);
        return Ok(());
    }

    info!(target: "socks5", conn_id, peer = %peer, "initial bytes received: {:02X?}", hdr);

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
            return handle_http_proxy(
                conn_id,
                tcp,
                peer,
                client_label,
                outbound,
                cfg,
                hdr,
                relay_opts,
            )
            .await;
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

    let target = match read_socks5_target_endpoint_with_atyp(&mut tcp, req_hdr[3]).await {
        Ok(t) => t,
        Err(e) => return silent_or_err(&mut tcp, silent_drop, &e.to_string()).await,
    };

    // Break protocol deadlock: send SOCKS5 success reply immediately.
    // This tells the browser it can start sending application data (like TLS Client Hello).
    tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(EngineError::from)?;

    // Peek/Read for initial client data (e.g. TLS Client Hello) after the SOCKS5 success is sent.
    // This enables Data Race verification for the chosen route.
    let mut peek_buf = [0u8; 2048];
    let initial_client_data = match tokio::time::timeout(Duration::from_millis(100), tcp.read(&mut peek_buf)).await {
        Ok(Ok(n)) if n > 0 => {
            info!(target: "socks5.route", conn_id, bytes = n, "peeked initial client data");
            peek_buf[..n].to_vec()
        },
        _ => Vec::new(),
    };

    handle_socks5_request_with_target(
        conn_id,
        tcp,
        peer,
        peer,
        outbound,
        Arc::new(relay_opts),
        cfg,
        silent_drop,
        target,
        initial_client_data,
    )
    .await
}

async fn silent_or_err(tcp: &mut TcpStream, silent: bool, msg: &str) -> Result<()> {
    if !silent {
        let _ = tcp
            .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
    }
    Err(EngineError::Internal(msg.to_owned()))
}

pub async fn read_socks5_target_endpoint_with_atyp(
    tcp: &mut TcpStream,
    atyp: u8,
) -> Result<TargetEndpoint> {
    let addr = match atyp {
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
    tcp.read_exact(&mut port_bytes)
        .await
        .map_err(EngineError::Io)?;
    let port = u16::from_be_bytes(port_bytes);

    Ok(TargetEndpoint { addr, port })
}

pub async fn resolve_client_label(peer: SocketAddr, _listen_addr: SocketAddr) -> String {
    format!("client-{}", peer)
}

fn reap_route_race_losers_v3(
    mut winners: JoinSet<Result<(RouteCandidate, BoxStream, Vec<u8>, bool)>>,
    conn_id: u64,
    target_label: String,
) {
    tokio::spawn(async move {
        while let Some(res) = winners.join_next().await {
            if let Ok(Ok((cand, stream, _, _))) = res {
                debug!(target: "socks5", conn_id, route = cand.route_label(), target_label, "closing late race winner");
                drop(stream);
            }
        }
    });
}
