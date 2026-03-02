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

    for (idx, candidate) in launch.into_iter().enumerate() {
        let delay_ms = route_race_candidate_delay_ms(
            idx,
            &candidate,
            launched_ids.contains("direct"),
            target_label,
            cfg,
        );
        let cand = candidate.clone();
        let target_c = target.clone();
        let target_label_c = target_label.to_owned();
        let outbound_c = outbound.clone();
        let relay_opts_c = relay_opts.clone();
        let cfg_c = Arc::new(cfg.clone());
        let initial_client_data_c = initial_client_data.clone();

        winners.spawn(async move {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            let mut stream = connect_route_candidate(
                conn_id,
                &target_c,
                &target_label_c,
                &cand,
                outbound_c,
                &relay_opts_c,
                cfg_c.clone(),
            )
            .await?;

            let mut initial_u2c = Vec::new();
            let mut client_data_sent = false;

            if let Some(ref data) = initial_client_data_c {
                if cand.kind == RouteKind::Direct && is_censored_domain(&target_label_c, &cfg_c) {
                    if let Err(e) = stream.write_all(data).await {
                        info!(target: "socks5.route", conn_id, route = cand.route_label(), error = %e, "race worker failed to send initial data");
                        return Err(e.into());
                    }
                    let _ = stream.flush().await;
                    client_data_sent = true;

                    let mut buf = [0u8; 1];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_millis(2000), stream.read(&mut buf))
                            .await
                    {
                        if n > 0 {
                            initial_u2c.push(buf[0]);
                        }
                    }
                }
            }

            Ok((cand, stream, initial_u2c, client_data_sent))
        });
    }

    let mut last_failed_candidate = None;
    while let Some(res) = winners.join_next().await {
        let (candidate, stream, initial_u2c, client_data_sent) = match res {
            Ok(Ok(val)) => val,
            Ok(Err(e)) => {
                debug!(target: "socks5.route", conn_id, error = %e, "race worker failed");
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

    complete_route_outcome_event(
        decision_id,
        target_label,
        last_failed_candidate.as_ref(),
        false,
        false,
        0,
        0,
        "race-failed",
        cfg,
    );
    Err(EngineError::Internal("all race workers failed".to_owned()))
}

pub struct ConnectedRoute {
    pub stream: BoxStream,
    pub candidate: RouteCandidate,
    pub route_key: String,
    pub decision_id: u64,
    pub initial_client_data: Vec<u8>,
    pub initial_upstream_data: Vec<u8>,
    pub client_data_sent: bool,
}

pub async fn handle_socks5_connection(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    client_label: &str,
    outbound: DynOutbound,
    cfg: Arc<EngineConfig>,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    let mut hdr = [0u8; 2];
    if let Err(e) = tcp.read_exact(&mut hdr).await {
        if is_expected_disconnect(&e) {
            return Ok(());
        }
        return silent_or_err(&mut tcp, silent_drop, &format!("failed to read SOCKS5 header: {}", e)).await;
    }

    if hdr[0] != 0x05 {
        if hdr[0] == 0x04 {
            return handle_socks4(
                conn_id,
                tcp,
                peer,
                client_label.to_string(),
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
                client_label.to_string(),
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

    tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(EngineError::from)?;

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
        client_label,
        &target,
        outbound,
        cfg,
        relay_opts,
        if initial_client_data.is_empty() { None } else { Some(initial_client_data) },
    )
    .await
}

async fn handle_socks5_request_with_target(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    client_label: &str,
    target: &TargetEndpoint,
    outbound: DynOutbound,
    cfg: Arc<EngineConfig>,
    relay_opts: RelayOptions,
    initial_client_data: Option<Vec<u8>>,
) -> Result<()> {
    let target_label = route_decision_key(&target.to_string(), &target.addr, &cfg);
    let candidates = select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg);
    let ordered = ordered_route_candidates(&target_label, candidates, &cfg);

    let route = match connect_via_best_route(
        conn_id,
        target,
        &target_label,
        ordered,
        outbound,
        &relay_opts,
        &cfg,
        initial_client_data,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(target: "socks5", conn_id, destination = %target, error = %e, "failed to connect to any route");
            return Ok(());
        }
    };

    info!(target: "socks5.route", conn_id, "route connection established, preparing relay");
    let start = Instant::now();
    let mut upstream = route.stream;

    let relay_res = relay_bidirectional(
        &mut tcp,
        &mut upstream,
        relay_opts,
        route.initial_client_data,
        route.initial_upstream_data,
        route.client_data_sent,
    )
    .await;

    let (c2u, u2c) = match relay_res {
        Ok(counts) => counts,
        Err(e) => {
            if !is_expected_disconnect(&e) {
                warn!(target: "socks5", conn_id, error = %e, "relay failed");
            }
            (0, 0)
        }
    };

    let lifetime = start.elapsed();
    complete_route_outcome_event(
        route.decision_id,
        &route.route_key,
        Some(&route.candidate),
        true,
        u2c >= 1,
        c2u,
        lifetime.as_millis() as u64,
        "normal",
        &cfg,
    );

    info!(
        target: "socks5",
        conn_id,
        bytes_c2u = c2u,
        bytes_u2c = u2c,
        duration_ms = lifetime.as_millis(),
        "socks5 session finished normally"
    );

    Ok(())
}

async fn read_socks5_target_endpoint_with_atyp(
    tcp: &mut TcpStream,
    atyp: u8,
) -> Result<TargetEndpoint> {
    let addr = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            tcp.read_exact(&mut ip).await.map_err(EngineError::Io)?;
            TargetAddr::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await.map_err(EngineError::Io)?;
            let mut domain = vec![0u8; len[0] as usize];
            tcp.read_exact(&mut domain).await.map_err(EngineError::Io)?;
            TargetAddr::Domain(String::from_utf8_lossy(&domain).to_string())
        }
        0x04 => {
            let mut ip = [0u8; 16];
            tcp.read_exact(&mut ip).await.map_err(EngineError::Io)?;
            TargetAddr::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)))
        }
        _ => return Err(EngineError::Internal("unsupported ATYP".to_owned())),
    };

    let mut port = [0u8; 2];
    tcp.read_exact(&mut port).await.map_err(EngineError::Io)?;
    let port = u16::from_be_bytes(port);

    Ok(TargetEndpoint { addr, port })
}

pub async fn silent_or_err(tcp: &mut TcpStream, silent: bool, msg: &str) -> Result<()> {
    if !silent {
        let _ = tcp.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
    }
    Err(EngineError::Internal(msg.to_owned()))
}

fn reap_route_race_losers_v3(
    winners: JoinSet<Result<(RouteCandidate, BoxStream, Vec<u8>, bool)>>,
    conn_id: u64,
    target_label: String,
) {
    tokio::spawn(async move {
        let mut winners = winners;
        while let Some(res) = winners.join_next().await {
            if let Ok(Ok((cand, stream, _, _))) = res {
                debug!(target: "socks5", conn_id, route = cand.route_label(), target_label, "closing late race winner");
                drop(stream);
            }
        }
    });
}
