async fn connect_via_best_route(
    conn_id: u64,
    outbound: DynOutbound,
    relay_opts: &RelayOptions,
    target_endpoint: &TargetEndpoint,
    destination: &str,
) -> Result<ConnectedRoute> {
    let route_key = route_decision_key(destination, &target_endpoint.addr);
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
        let has_direct = ordered.iter().any(|c| c.kind == RouteKind::Direct);
        let launch_order = route_race_launch_candidates(&ordered);
        info!(
            target: "socks5.route",
            destination = %destination,
            route_key = %route_key,
            candidates = ordered.len(),
            launched = launch_order.len(),
            reason = route_race_reason_label(race_reason),
            "adaptive route race started"
        );
        let mut set = JoinSet::new();
        for (idx, candidate) in launch_order.into_iter().enumerate() {
            let outbound = outbound.clone();
            let target = target_endpoint.clone();
            let destination = destination.to_owned();
            let launch_delay_ms = route_race_candidate_delay_ms(idx, &candidate, has_direct);
            set.spawn(async move {
                if launch_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(launch_delay_ms)).await;
                }
                let started = Instant::now();
                let res = connect_route_candidate(
                    conn_id,
                    outbound,
                    target,
                    destination,
                    candidate.clone(),
                )
                .await;
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
                    maybe_mark_route_capability_failure(&candidate, &e);
                    if should_ignore_route_failure(&candidate, &e) {
                        info!(
                            target: "socks5.route",
                            route_key = %route_key,
                            route = %candidate.route_id(),
                            error = %e,
                            "route failure ignored due to DNS sinkhole resolution"
                        );
                    } else {
                        record_route_failure(&route_key, &candidate, "connect-failed");
                    }
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
                maybe_mark_route_capability_failure(&candidate, &e);
                if should_ignore_route_failure(&candidate, &e) {
                    info!(
                        target: "socks5.route",
                        route_key = %route_key,
                        route = %candidate.route_id(),
                        error = %e,
                        "route failure ignored due to DNS sinkhole resolution"
                    );
                } else {
                    record_route_failure(&route_key, &candidate, "connect-failed");
                }
                last_error = Some(e);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        EngineError::Internal("failed to connect via all route candidates".to_owned())
    }))
}

fn route_race_candidate_delay_ms(idx: usize, candidate: &RouteCandidate, has_direct: bool) -> u64 {
    let base = ROUTE_RACE_BASE_DELAY_MS.saturating_mul(idx as u64);
    if has_direct && candidate.kind == RouteKind::Bypass {
        base.saturating_add(ROUTE_RACE_DIRECT_HEADSTART_MS)
            .saturating_add(route_race_bypass_extra_delay_ms(candidate.source))
    } else {
        base
    }
}

fn route_race_launch_candidates(ordered: &[RouteCandidate]) -> Vec<RouteCandidate> {
    if !ordered.iter().any(|c| c.kind == RouteKind::Direct) {
        return ordered
            .iter()
            .take(ROUTE_RACE_MAX_CANDIDATES)
            .cloned()
            .collect();
    }

    // Keep direct probe first, then race a capped set of bypass profiles.
    // This avoids dropping all but two bypass candidates when direct exists.
    let mut launch =
        Vec::with_capacity(ordered.len().min(ROUTE_RACE_MAX_CANDIDATES.saturating_add(1)));
    launch.extend(
        ordered
            .iter()
            .filter(|candidate| candidate.kind == RouteKind::Direct)
            .cloned(),
    );
    launch.extend(
        ordered
            .iter()
            .filter(|candidate| candidate.kind == RouteKind::Bypass)
            .take(ROUTE_RACE_MAX_CANDIDATES)
            .cloned(),
    );
    launch
}

fn route_race_bypass_extra_delay_ms(source: &str) -> u64 {
    match source {
        "builtin" => ROUTE_RACE_BYPASS_EXTRA_DELAY_BUILTIN_MS,
        "learned-domain" | "learned-ip" => ROUTE_RACE_BYPASS_EXTRA_DELAY_LEARNED_MS,
        _ => ROUTE_RACE_BYPASS_EXTRA_DELAY_MS,
    }
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
    if let Err(e) = tcp
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
    {
        if is_expected_disconnect(&e) {
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %target,
                error = %e,
                "SOCKS5 client disconnected before connect reply"
            );
            return Ok(());
        }
        return Err(e.into());
    }

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
        let bypass_tunnel_started = Instant::now();
        match tokio::io::copy_bidirectional(&mut tcp, &mut connected.stream).await {
            Ok((c2u, u2c)) => {
                let lifetime_ms = bypass_tunnel_started.elapsed().as_millis() as u64;
                info!(
                    target: "socks5",
                    conn_id,
                    destination = %target,
                    bytes_client_to_bypass = c2u,
                    bytes_bypass_to_client = u2c,
                    session_lifetime_ms = lifetime_ms,
                    bypass_profile = connected.candidate.bypass_profile_idx + 1,
                    bypass_profiles = connected.candidate.bypass_profile_total,
                    "bypass tunnel closed"
                );
                if should_skip_empty_session_scoring(c2u, u2c) {
                    if should_mark_empty_bypass_session_as_soft_failure(&connected.candidate, port)
                    {
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
                            destination = %target,
                            "adaptive route marked empty bypass session as soft failure"
                        );
                    } else {
                        info!(
                            target: "socks5.route",
                            conn_id,
                            route_key = %connected.route_key,
                            route = connected.candidate.route_label(),
                            destination = %target,
                            "adaptive route skipped scoring for empty bypass session"
                        );
                    }
                } else if should_mark_bypass_profile_failure(
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
                } else if should_mark_bypass_zero_reply_soft(port, c2u, u2c, lifetime_ms) {
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
                        destination = %target,
                        bytes_client_to_bypass = c2u,
                        bytes_bypass_to_client = u2c,
                        session_lifetime_ms = lifetime_ms,
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
            if should_skip_empty_session_scoring(bytes_client_to_upstream, bytes_upstream_to_client)
            {
                info!(
                    target: "socks5.route",
                    conn_id,
                    route_key = %connected.route_key,
                    route = connected.candidate.route_label(),
                    destination = %target,
                    "adaptive route skipped scoring for empty direct session"
                );
            } else if should_mark_suspicious_zero_reply(
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
        Err(e) if is_expected_disconnect(&e) => {
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %target,
                error = %e,
                "SOCKS5 relay closed by peer"
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

