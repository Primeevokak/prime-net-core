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
    if msg.contains("socks5 invalid reply version")
        || msg.contains("auth rejected")
        || msg.contains("rejected connect: rep=0x03")
    {
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
    destination: &str,
) -> u64 {
    if index == 0 {
        return 0;
    }
    let bucket = host_service_bucket(destination);
    let is_censored = matches!(bucket.as_str(), "meta-group:youtube" | "meta-group:discord");

    let mut delay = ROUTE_RACE_BASE_DELAY_MS.saturating_mul(index as u64);

    if is_censored {
        // For censored services, we WANT bypass to win the race even if direct TCP is faster.
        // We give bypass routes a huge advantage.
        if candidate.kind == RouteKind::Direct {
            // Penalize direct connection on YouTube/Discord to let proxy win.
            return 500;
        }
        // Sequential but fast launch for bypass backends.
        return (index as u64).saturating_mul(25);
    }

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

pub fn route_race_launch_candidates(
    ordered: &[RouteCandidate],
    destination: &str,
) -> Vec<RouteCandidate> {
    let bucket = host_service_bucket(destination);
    if bucket == "meta-group:google" {
        let mut out = Vec::with_capacity(3);
        if let Some(direct) = ordered.iter().find(|c| c.kind == RouteKind::Direct) {
            out.push(direct.clone());
        }
        // For Google we also want to probe a few bypass profiles in parallel
        // to avoid stalling if direct is TCP-silent.
        for bypass in ordered
            .iter()
            .filter(|c| c.kind == RouteKind::Bypass)
            .take(2)
        {
            out.push(bypass.clone());
        }
        if !out.is_empty() {
            return out;
        }
    }
    if matches!(bucket.as_str(), "meta-group:youtube" | "meta-group:discord") {
        let mut out = Vec::with_capacity(7);
        if let Some(direct) = ordered.iter().find(|c| c.kind == RouteKind::Direct) {
            out.push(direct.clone());
        }
        for bypass in ordered
            .iter()
            .filter(|c| c.kind == RouteKind::Bypass)
            .take(6)
        {
            out.push(bypass.clone());
        }
        if !out.is_empty() {
            if out.len() > 7 {
                out.truncate(7);
            }
            return out;
        }
    }
    ordered
        .iter()
        .take(ROUTE_RACE_MAX_CANDIDATES)
        .cloned()
        .collect()
}

fn reap_route_race_losers(
    mut losers: JoinSet<(RouteCandidate, Result<BoxStream>)>,
    conn_id: u64,
    target_label: String,
) {
    tokio::spawn(async move {
        while let Some(joined) = losers.join_next().await {
            if let Ok((candidate, Ok(stream))) = joined {
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
) -> Result<ConnectedRoute> {
    let (candidates, canary) = apply_phase3_ml_override(target_label, candidates);
    let (race, reason) = route_race_decision(target.port, target_label, &candidates);
    record_route_race_decision(race, reason);
    let decision_id =
        begin_route_decision_event_with_canary(target_label, &candidates, race, Some(canary));

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
            )
            .await
            {
                Ok(stream) => {
                    record_route_connected(target_label, &candidate);
                    record_route_selected(&candidate, false);
                    return Ok(ConnectedRoute {
                        stream,
                        candidate,
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
                        record_route_failure(target_label, &candidate, "connect-failed");
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
        );
        return Err(last_err.unwrap_or_else(|| {
            EngineError::Internal("all non-race route candidates failed".to_owned())
        }));
    }

    let mut winners = JoinSet::new();
    let launch = route_race_launch_candidates(&candidates, target_label);
    let launched_ids: std::collections::HashSet<String> = launch
        .iter()
        .map(|candidate| candidate.route_id())
        .collect();
    let direct_present = candidates.iter().any(|c| c.kind == RouteKind::Direct);
    let mut last_failed_candidate: Option<RouteCandidate> = None;

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
            let res = connect_route_candidate(
                conn_id,
                &target_c,
                &target_label_c,
                &cand,
                outbound_c,
                &relay_opts_c,
            )
            .await;
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
                reap_route_race_losers(winners, conn_id, target_label.to_owned());
                record_route_connected(target_label, &candidate);
                record_route_selected(&candidate, true);
                return Ok(ConnectedRoute {
                    stream,
                    candidate,
                    route_key: target_label.to_owned(),
                    raced: true,
                    decision_id,
                });
            }
            Err(e) => {
                maybe_mark_route_capability_failure(&candidate, &e);
                if !should_ignore_route_failure(&candidate, &e)
                    && !is_noise_probe_https_destination(route_destination_key(target_label))
                {
                    record_route_failure(target_label, &candidate, "connect-failed");
                }
                last_failed_candidate = Some(candidate.clone());
                last_err = Some(e);
            }
        }
    }

    // All raced candidates failed. Try any remaining ordered candidates sequentially
    // before giving up, so we don't miss a working lower-priority fallback.
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
        )
        .await
        {
            Ok(stream) => {
                record_route_connected(target_label, candidate);
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
                    record_route_failure(target_label, candidate, "connect-failed");
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
    );
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
            return handle_http_proxy(conn_id, tcp, peer, client, outbound, hdr, relay_opts).await;
        }
        return silent_or_err(&mut tcp, silent_drop, "SOCKS5 invalid version").await;
    }

    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    tcp.read_exact(&mut methods)
        .await
        .map_err(EngineError::Io)?;
    tcp.write_all(&[0x05, 0x00])
        .await
        .map_err(EngineError::Io)?;

    let mut req_hdr = [0u8; 4];
    tcp.read_exact(&mut req_hdr)
        .await
        .map_err(EngineError::Io)?;
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
    tcp.read_exact(&mut port_bytes)
        .await
        .map_err(EngineError::Io)?;
    let port = u16::from_be_bytes(port_bytes);
    let target = TargetEndpoint {
        addr: target_addr,
        port,
    };
    let target_label = route_decision_key(&target.to_string(), &target.addr);

    let candidates = select_route_candidates(&relay_opts, &target.addr, target.port, &target_label);
    let ordered = ordered_route_candidates(&target_label, candidates);

    match connect_via_best_route(
        conn_id,
        &target,
        &target_label,
        ordered,
        outbound,
        &relay_opts,
    )
    .await
    {
        Ok(mut connected) => {
            let tuned = tune_relay_for_target(
                relay_opts.clone(),
                target.port,
                &target_label,
                false,
                connected.candidate.kind == RouteKind::Bypass,
            );
            if let Err(e) = tcp
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
            {
                complete_route_outcome_event(
                    connected.decision_id,
                    &connected.route_key,
                    Some(&connected.candidate),
                    true,
                    false,
                    0,
                    0,
                    "client-reply-io",
                );
                return Err(e.into());
            }
            let relay_started = Instant::now();
            match relay_bidirectional(&mut tcp, &mut connected.stream, tuned.options).await {
                Ok((_c2u, u2c)) => {
                    complete_route_outcome_event(
                        connected.decision_id,
                        &connected.route_key,
                        Some(&connected.candidate),
                        true,
                        u2c > 0,
                        u2c,
                        relay_started.elapsed().as_millis() as u64,
                        "ok",
                    );
                }
                Err(e) if is_expected_disconnect(&e) => {
                    let lifetime_ms = relay_started.elapsed().as_millis() as u64;
                    let mut error_class = "client-disconnect";
                    if should_penalize_disconnect_as_soft_zero_reply(
                        &connected.route_key,
                        &connected.candidate,
                        lifetime_ms,
                    ) {
                        record_route_failure(
                            &connected.route_key,
                            &connected.candidate,
                            "zero-reply-soft",
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
                    );
                }
                Err(e) => {
                    complete_route_outcome_event(
                        connected.decision_id,
                        &connected.route_key,
                        Some(&connected.candidate),
                        true,
                        false,
                        0,
                        relay_started.elapsed().as_millis() as u64,
                        "relay-io",
                    );
                    debug!(
                        target: "socks5",
                        conn_id,
                        client = %client,
                        peer = %peer,
                        destination = %target_label,
                        error = %e,
                        "SOCKS5 relay interrupted"
                    );
                }
            }
            Ok(())
        }
        Err(e) => silent_or_err(&mut tcp, silent_drop, &e.to_string()).await,
    }
}

pub(super) async fn silent_or_err(tcp: &mut TcpStream, silent: bool, msg: &str) -> Result<()> {
    if !silent {
        let _ = tcp
            .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
    }
    Err(EngineError::Internal(msg.to_owned()))
}
