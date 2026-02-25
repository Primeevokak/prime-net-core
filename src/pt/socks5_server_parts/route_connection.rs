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
        // Enable Hot Shadowing for EVERYTHING to counter aggressive antivirus resets.
        let is_sensitive = true; 
        
        info!(
            target: "socks5.route",
            destination = %destination,
            route_key = %route_key,
            candidates = ordered.len(),
            launched = launch_order.len(),
            reason = route_race_reason_label(race_reason),
            is_global_shadowing = is_sensitive,
            "adaptive route race started"
        );
        let mut set = JoinSet::new();
        for (idx, candidate) in launch_order.into_iter().enumerate() {
            let outbound = outbound.clone();
            let target = target_endpoint.clone();
            let destination = destination.to_owned();
            let launch_delay_ms = route_race_candidate_delay_ms(idx, &candidate, has_direct, &destination);
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
        
        let mut first_winner: Option<(RouteCandidate, BoxStream, u128)> = None;
        let mut shadow_winner: Option<BoxStream> = None;
        let mut last_error: Option<EngineError> = None;

        let shadow_timeout = Duration::from_millis(350);
        let _race_start = Instant::now();

        while let Some(joined) = if first_winner.is_some() && is_sensitive {
             tokio::time::timeout(shadow_timeout, set.join_next()).await.unwrap_or(None)
        } else {
             set.join_next().await
        } {
            match joined {
                Ok((candidate, elapsed_ms, Ok(stream))) => {
                    if first_winner.is_none() {
                        first_winner = Some((candidate.clone(), stream, elapsed_ms));
                        if !is_sensitive {
                            set.abort_all();
                            break;
                        }
                        // Continue to look for a shadow connection
                    } else {
                        // This is our shadow connection!
                        debug!(
                            target: "socks5.route",
                            destination = %destination,
                            route = %candidate.route_id(),
                            "shadow connection established for hot-standby"
                        );
                        shadow_winner = Some(stream);
                        set.abort_all();
                        break;
                    }
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

        if let Some((candidate, stream, elapsed_ms)) = first_winner {
            info!(
                target: "socks5.route",
                destination = %destination,
                route_key = %route_key,
                route = %candidate.route_id(),
                source = candidate.source,
                elapsed_ms,
                has_shadow = shadow_winner.is_some(),
                "adaptive route race winner selected"
            );
            record_route_selected(&candidate, true);
            return Ok(ConnectedRoute {
                candidate,
                stream,
                shadow_stream: shadow_winner,
                route_key,
                raced: true,
            });
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
                    shadow_stream: None,
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

fn route_race_candidate_delay_ms(idx: usize, candidate: &RouteCandidate, has_direct: bool, destination: &str) -> u64 {
    let mut base = ROUTE_RACE_BASE_DELAY_MS.saturating_mul(idx as u64);
    
    // ACCELERATION: For YouTube and previews, reduce delay even further to avoid client-side timeouts (10053)
    if destination.contains("ytimg") || destination.contains("googlevideo") || destination.contains("ggpht") {
        base = base / 2;
    }

    if has_direct && candidate.kind == RouteKind::Bypass {
        let headstart = if destination.contains("youtube") || destination.contains("discord") {
            ROUTE_RACE_DIRECT_HEADSTART_MS / 2
        } else {
            ROUTE_RACE_DIRECT_HEADSTART_MS
        };
        base = base.saturating_add(headstart)
            .saturating_add(route_race_bypass_extra_delay_ms(candidate.source));
    }

    // EXTRA PROTECTION: If multiple bypass profiles are in the race, give the "learned" one a headstart.
    // Otherwise, a broken profile that handshakes fast will always win the race but fail the data phase.
    if candidate.kind == RouteKind::Bypass {
        let preferred_idx = destination_bypass_profile_idx(destination, candidate.bypass_profile_total);
        if candidate.bypass_profile_idx != preferred_idx {
            let penalty = if destination.contains("discord") || destination.contains("youtube") || destination.contains("google") {
                500 // Strong preference for learned profile in critical groups
            } else {
                150
            };
            base = base.saturating_add(penalty);
        }
    }

    base
}

fn route_race_launch_candidates(ordered: &[RouteCandidate]) -> Vec<RouteCandidate> {
    // Respect the ordering provided by the scorer.
    // If Bypass is ranked higher (e.g. due to blocklist match), it should be launched first.
    ordered
        .iter()
        .take(ROUTE_RACE_MAX_CANDIDATES)
        .cloned()
        .collect()
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
        debug!(target: "socks5", conn_id, peer = %peer, client = %client, "client disconnected before protocol negotiation");
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
        return handle_socks5_udp_associate(
            conn_id,
            tcp,
            peer,
            client,
            dst,
            port,
            silent_drop,
            relay_opts,
        )
        .await;
    }
    info!(target: "socks5", conn_id, peer = %peer, client = %client, destination = %target, "SOCKS5 CONNECT requested");
    let target_endpoint = TargetEndpoint { addr: dst, port };

    // Attempt to establish a connection, with a single immediate fallback if the first route fails silently.
    let mut attempt = 1;
    let max_attempts = 2;
    let mut last_error: Option<EngineError> = None;

    while attempt <= max_attempts {
        let connected = match connect_via_best_route(
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
                if attempt == max_attempts {
                    if !silent_drop {
                        let _ = tcp
                            .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                        let _ = tcp.shutdown().await;
                    }
                    return Err(e);
                }
                last_error = Some(e);
                attempt += 1;
                continue;
            }
        };

        let mut primary_stream = Some(connected.stream);
        let mut shadow_stream = connected.shadow_stream;
        let mut use_shadow = false;
        let mut socks_replied = attempt > 1 && last_error.is_some();

        loop {
            let mut active_stream = if use_shadow {
                shadow_stream.take().ok_or_else(|| EngineError::Internal("shadow stream vanished".to_owned()))?
            } else {
                primary_stream.take().ok_or_else(|| EngineError::Internal("primary stream vanished".to_owned()))?
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
                    attempt,
                    is_shadow = use_shadow,
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
                    attempt,
                    is_shadow = use_shadow,
                    "SOCKS5 CONNECT route selected"
                );
            }

            // SOCKS5 reply: MUST be sent exactly once.
            if !socks_replied {
                if let Err(e) = tcp
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                {
                    if is_expected_disconnect(&e) {
                        return Ok(());
                    }
                    return Err(e.into());
                }
                socks_replied = true;
            }

            let tuned = tune_relay_for_target(relay_opts.clone(), port, &target, false, connected.candidate.kind == RouteKind::Bypass);
            let bypass_tunnel_started = Instant::now();

            match relay_bidirectional(&mut tcp, &mut active_stream, tuned.options.clone()).await {
                Ok((c2u, u2c)) => {
                    let lifetime_ms = bypass_tunnel_started.elapsed().as_millis() as u64;
                    // Proactive switch: if almost no data came back very quickly, try shadow
                    if u2c < 10 && shadow_stream.is_some() && !use_shadow && lifetime_ms < 500 {
                        warn!(target: "socks5.route", conn_id, destination = %target, "primary stream yielded too little data, switching to shadow");
                        use_shadow = true;
                        continue;
                    }

                    if connected.candidate.kind == RouteKind::Bypass {
                        info!(
                            target: "socks5",
                            conn_id,
                            destination = %target,
                            bytes_client_to_bypass = c2u,
                            bytes_bypass_to_client = u2c,
                            session_lifetime_ms = lifetime_ms,
                            bypass_profile = connected.candidate.bypass_profile_idx + 1,
                            "bypass tunnel closed"
                        );
                    } else {
                        info!(
                            target: "socks5",
                            conn_id,
                            destination = %target,
                            bytes_c2u = c2u,
                            bytes_u2c = u2c,
                            "direct session closed"
                        );
                    }
                    
                    record_route_success(&connected.route_key, &connected.candidate);
                    return Ok(());
                }
                Err(e) if is_expected_disconnect(&e) => {
                    return Ok(());
                }
                Err(e) => {
                    let is_av_block = e.raw_os_error() == Some(10013);
                    if shadow_stream.is_some() && !use_shadow && (is_av_block || e.kind() == ErrorKind::ConnectionReset || e.kind() == ErrorKind::BrokenPipe || e.kind() == ErrorKind::ConnectionAborted) {
                        warn!(target: "socks5.route", conn_id, destination = %target, error = %e, is_av_block, "primary stream failure, hot-switching to shadow connection");
                        use_shadow = true;
                        continue;
                    }
                    
                    warn!(target: "socks5.route", conn_id, destination = %target, error = %e, "connection failed, trying next attempt");
                    break; 
                }
            }
        }
        attempt += 1;
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

