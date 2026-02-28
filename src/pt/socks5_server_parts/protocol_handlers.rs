use super::*;

pub(super) async fn handle_http_proxy(
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
    let Some(req_line) = parse_http_request_line(first_line) else {
        let _ = tcp
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        let _ = tcp.shutdown().await;
        return Ok(());
    };
    let method = req_line.method.to_ascii_uppercase();
    let target = req_line.target;

    if method == "CONNECT" {
        let Some((host, port)) = split_host_port_for_connect(target) else {
            warn!(target: "socks5", conn_id, peer = %peer, client = %client, target = %target, "HTTP CONNECT target is invalid");
            let _ = tcp
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            let _ = tcp.shutdown().await;
            return Ok(());
        };

        let target_addr = if let Some(ip) = parse_ip_literal(&host) {
            TargetAddr::Ip(ip)
        } else {
            TargetAddr::Domain(host.clone())
        };
        let destination = format!("{host}:{port}");
        let target_endpoint = TargetEndpoint {
            addr: target_addr,
            port,
        };
        let target_label = route_decision_key(&destination, &target_endpoint.addr);
        let candidates = select_route_candidates(
            &relay_opts,
            &target_endpoint.addr,
            target_endpoint.port,
            &target_label,
        );
        let ordered = ordered_route_candidates(&target_label, candidates);

        debug!(target: "socks5", conn_id, peer = %peer, client = %client, destination = %destination, "HTTP CONNECT requested");

        let mut connected = match connect_via_best_route(
            conn_id,
            &target_endpoint,
            &target_label,
            ordered,
            outbound.clone(),
            &relay_opts,
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
        let service_bucket = host_service_bucket(&destination);
        let high_signal_bucket = matches!(
            service_bucket.as_str(),
            "meta-group:youtube" | "meta-group:google" | "meta-group:discord"
        );
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
        } else if high_signal_bucket {
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %destination,
                bucket = %service_bucket,
                route = connected.candidate.route_label(),
                source = connected.candidate.source,
                raced = connected.raced,
                "HTTP CONNECT route selected"
            );
        } else {
            debug!(
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

        if let Err(e) = tcp
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
        {
            if is_expected_disconnect(&e) {
                complete_route_outcome_event(
                    connected.decision_id,
                    &connected.route_key,
                    Some(&connected.candidate),
                    true,
                    false,
                    0,
                    0,
                    "client-disconnect-before-confirm",
                );
                debug!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    error = %e,
                    "HTTP CONNECT client disconnected before tunnel confirmation"
                );
                return Ok(());
            }
            complete_route_outcome_event(
                connected.decision_id,
                &connected.route_key,
                Some(&connected.candidate),
                true,
                false,
                0,
                0,
                "client-confirm-io",
            );
            return Err(e.into());
        }

        if connected.candidate.kind == RouteKind::Bypass {
            debug!(
                target: "socks5",
                conn_id,
                destination = %destination,
                bypass = ?connected.candidate.bypass_addr,
                bypass_profile = connected.candidate.bypass_profile_idx + 1,
                bypass_profiles = connected.candidate.bypass_profile_total,
                "bypass tunnel established"
            );
            let bypass_tunnel_started = Instant::now();
            let noisy_tls_destination = is_noise_probe_https_destination(&destination);
            let tuned = tune_relay_for_target(relay_opts.clone(), port, &destination, false, true);
            match relay_bidirectional(&mut tcp, &mut connected.stream, tuned.options.clone()).await
            {
                Ok((c2u, u2c)) => {
                    let lifetime_ms = bypass_tunnel_started.elapsed().as_millis() as u64;
                    let evasion_tag = if tuned.options.fragment_client_hello {
                        " (double-evasion active)"
                    } else {
                        ""
                    };
                    let outcome_error_class: &str;
                    let tls_ok_proxy = u2c > 0;

                    info!(
                        target: "socks5.bypass",
                        conn_id,
                        destination = %destination,
                        bytes_client_to_bypass = c2u,
                        bytes_bypass_to_client = u2c,
                        session_lifetime_ms = lifetime_ms,
                        bypass_profile = connected.candidate.bypass_profile_idx + 1,
                        bypass_profiles = connected.candidate.bypass_profile_total,
                        "bypass tunnel closed{}",
                        evasion_tag
                    );
                    if should_skip_empty_session_scoring(c2u, u2c) {
                        if should_mark_empty_bypass_session_as_soft_failure(
                            &connected.candidate,
                            port,
                        ) && !noisy_tls_destination
                        {
                            record_route_failure(
                                &connected.route_key,
                                &connected.candidate,
                                "zero-reply-soft",
                            );
                            outcome_error_class = "zero-reply-soft";
                        } else {
                            outcome_error_class = "empty-session";
                        }
                    } else if u2c < 20 && lifetime_ms < 1000 && !noisy_tls_destination {
                        // Very short session with almost no data is likely a TLS handshake failure
                        // disguised as a successful TCP connect.
                        record_route_failure(
                            &connected.route_key,
                            &connected.candidate,
                            "zero-reply-soft",
                        );
                        warn!(
                            target: "socks5.route",
                            conn_id,
                            destination = %destination,
                            bytes_u2c = u2c,
                            "bypass session too short/empty, marked as weak"
                        );
                        outcome_error_class = "zero-reply-soft";
                    } else if should_mark_bypass_profile_failure(
                        port,
                        c2u,
                        u2c,
                        relay_opts.suspicious_zero_reply_min_c2u as u64,
                    ) {
                        if !noisy_tls_destination {
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
                        }
                        outcome_error_class = "suspicious-zero-reply";
                    } else if should_mark_bypass_zero_reply_soft(port, c2u, u2c, lifetime_ms) {
                        if !noisy_tls_destination {
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
                                session_lifetime_ms = lifetime_ms,
                                "adaptive route observed soft zero-reply; winner confidence reduced"
                            );
                        }
                        outcome_error_class = "zero-reply-soft";
                    } else {
                        record_bypass_profile_success(
                            &destination,
                            connected.candidate.bypass_profile_idx,
                        );
                        record_route_success(&connected.route_key, &connected.candidate);
                        outcome_error_class = "ok";
                    }
                    complete_route_outcome_event(
                        connected.decision_id,
                        &connected.route_key,
                        Some(&connected.candidate),
                        true,
                        tls_ok_proxy,
                        u2c,
                        lifetime_ms,
                        outcome_error_class,
                    );
                }
                Err(e) if is_expected_disconnect(&e) => {
                    let lifetime_ms = bypass_tunnel_started.elapsed().as_millis() as u64;
                    let mut outcome_error_class = "client-disconnect";
                    if !noisy_tls_destination
                        && should_penalize_disconnect_as_soft_zero_reply(
                            &connected.route_key,
                            &connected.candidate,
                            lifetime_ms,
                        )
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
                            destination = %destination,
                            session_lifetime_ms = lifetime_ms,
                            "adaptive route reclassified expected disconnect as soft zero-reply"
                        );
                        outcome_error_class = "zero-reply-soft";
                    }
                    complete_route_outcome_event(
                        connected.decision_id,
                        &connected.route_key,
                        Some(&connected.candidate),
                        true,
                        false,
                        0,
                        lifetime_ms,
                        outcome_error_class,
                    );
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
                    if !noisy_tls_destination {
                        record_bypass_profile_failure(
                            &destination,
                            connected.candidate.bypass_profile_idx,
                            connected.candidate.bypass_profile_total,
                            "io-error",
                        );
                        record_route_failure(
                            &connected.route_key,
                            &connected.candidate,
                            "io-error",
                        );
                    }
                    complete_route_outcome_event(
                        connected.decision_id,
                        &connected.route_key,
                        Some(&connected.candidate),
                        true,
                        false,
                        0,
                        bypass_tunnel_started.elapsed().as_millis() as u64,
                        "io-error",
                    );
                }
            }
            return Ok(());
        }

        let tuned = tune_relay_for_target(relay_opts, port, &destination, false, false);

        let direct_tunnel_started = Instant::now();
        match relay_bidirectional(&mut tcp, &mut connected.stream, tuned.options.clone()).await {
            Ok((bytes_client_to_upstream, bytes_upstream_to_client)) => {
                let mut outcome_error_class = "ok";
                if should_skip_empty_session_scoring(
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                ) {
                    debug!(
                        target: "socks5.route",
                        conn_id,
                        route_key = %connected.route_key,
                        route = connected.candidate.route_label(),
                        destination = %destination,
                        "adaptive route skipped scoring for empty direct session"
                    );
                    outcome_error_class = "empty-session";
                } else if should_mark_suspicious_zero_reply(
                    port,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                    tuned.options.suspicious_zero_reply_min_c2u,
                ) {
                    if !is_noise_probe_https_destination(&destination) {
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
                        outcome_error_class = "suspicious-zero-reply";
                    }
                } else if should_mark_route_soft_zero_reply(
                    port,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                ) {
                    if !is_noise_probe_https_destination(&destination) {
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
                    }
                    outcome_error_class = "zero-reply-soft";
                } else {
                    record_destination_success(&destination, tuned.stage, tuned.source);
                    record_route_success(&connected.route_key, &connected.candidate);
                    outcome_error_class = "ok";
                }
                complete_route_outcome_event(
                    connected.decision_id,
                    &connected.route_key,
                    Some(&connected.candidate),
                    true,
                    bytes_upstream_to_client > 0,
                    bytes_upstream_to_client,
                    direct_tunnel_started.elapsed().as_millis() as u64,
                    outcome_error_class,
                );
                debug!(
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
            Err(e) if is_expected_disconnect(&e) => {
                let lifetime_ms = direct_tunnel_started.elapsed().as_millis() as u64;
                let mut outcome_error_class = "client-disconnect";
                
                // For censored services, a client disconnect with zero data from upstream 
                // is almost certainly a blocked connection that we should penalize.
                let bucket = host_service_bucket(route_destination_key(&connected.route_key));
                let is_censored = matches!(bucket.as_str(), "meta-group:youtube" | "meta-group:discord");
                
                if is_censored && lifetime_ms > 1000 {
                    record_route_failure(
                        &connected.route_key,
                        &connected.candidate,
                        "zero-reply-soft",
                    );
                    outcome_error_class = "zero-reply-soft";
                }

                complete_route_outcome_event(
                    connected.decision_id,
                    &connected.route_key,
                    Some(&connected.candidate),
                    true,
                    false,
                    0,
                    lifetime_ms,
                    outcome_error_class,
                );
                debug!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    error = %e,
                    "HTTP CONNECT relay closed by peer"
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
                complete_route_outcome_event(
                    connected.decision_id,
                    &connected.route_key,
                    Some(&connected.candidate),
                    true,
                    false,
                    0,
                    direct_tunnel_started.elapsed().as_millis() as u64,
                    blocking_signal_label(signal),
                );
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
    debug!(target: "socks5", conn_id, peer = %peer, client = %client, method = %method, destination = %destination, "HTTP proxy forward requested");
    debug!(
        target: "socks5",
        conn_id,
        peer = %peer,
        client = %client,
        method = %method,
        destination = %destination,
        route = "direct",
        "HTTP proxy forward route selected"
    );

    let target_addr = if let Some(ip) = parse_ip_literal(&parsed.host) {
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
            if is_noise_probe_http_destination(&destination) {
                debug!(target: "socks5", conn_id, peer = %peer, client = %client, method = %method, destination = %destination, error = %e, "HTTP proxy forward probe upstream failed");
            } else {
                warn!(target: "socks5", conn_id, peer = %peer, client = %client, method = %method, destination = %destination, error = %e, "HTTP proxy forward upstream failed");
            }
            let _ = tcp
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            let _ = tcp.shutdown().await;
            return Ok(());
        }
    };

    let upstream_head = rewrite_http_forward_head(request.as_ref(), &parsed);
    out.write_all(upstream_head.as_bytes()).await?;
    if !buffered_body.is_empty() {
        out.write_all(buffered_body).await?;
    }

    let tuned = tune_relay_for_target(relay_opts, parsed.port, &destination, false, false);
    match relay_bidirectional(&mut tcp, &mut out, tuned.options.clone()).await {
        Ok((bytes_client_to_upstream, bytes_upstream_to_client)) => {
            if should_skip_empty_session_scoring(bytes_client_to_upstream, bytes_upstream_to_client)
            {
                debug!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    "HTTP proxy forward classifier update skipped for empty session"
                );
            } else if should_mark_suspicious_zero_reply(
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
            debug!(
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
        Err(e) if is_expected_disconnect(&e) => {
            debug!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                method = %method,
                destination = %destination,
                error = %e,
                "HTTP proxy forward relay closed by peer"
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
            if is_noise_probe_http_destination(&destination) {
                debug!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    method = %method,
                    destination = %destination,
                    error = %e,
                    "HTTP proxy forward probe relay interrupted"
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

fn is_noise_probe_http_destination(destination: &str) -> bool {
    let host = destination
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(destination)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    host.contains("msftconnecttest")
        || host.contains("msftncsi")
        || host.contains("connectivitycheck")
        || host.contains("captive")
}

pub(super) fn is_noise_probe_https_destination(destination: &str) -> bool {
    let host = destination
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(destination)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if is_noise_probe_http_destination(destination) {
        return true;
    }
    host.contains("doubleclick.net")
        || host.contains("googlesyndication.com")
        || host.contains("googleadservices.com")
        || host.contains("ogads-pa.")
        || host.starts_with("adservice.")
}

pub(super) fn tune_relay_for_target(
    mut base: RelayOptions,
    port: u16,
    destination: &str,
    socks4_flow: bool,
    is_bypass: bool,
) -> TunedRelay {
    if is_bypass {
        // In bypass mode (external tool like ciadpi), we should NOT force internal fragmentation.
        // Doing so often breaks the connection because ciadpi already applies its own evasion.
        // We disable all internal evasion toggles to avoid "double-evasion".
        let mut opts = base.clone();
        opts.fragment_client_hello = false;
        opts.split_at_sni = false;
        opts.client_hello_split_offsets.clear();
        opts.tcp_window_trick = false;
        opts.sni_spoofing = false;
        opts.sni_case_toggle = false;

        return TunedRelay {
            options: opts,
            stage: 0,
            source: StageSelectionSource::Adaptive,
        };
    }

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

    let is_very_sensitive = destination.contains("discord")
        || destination.contains("instagram")
        || destination.contains("facebook")
        || destination.contains("fbcdn")
        || destination.contains("youtube")
        || destination.contains("ytimg")
        || destination.contains("googlevideo")
        || destination.contains("ggpht")
        || destination.contains("google.com")
        || destination.contains("discordapp")
        || destination.contains("discord.gg")
        || destination.contains("cloudflare")
        || destination.contains("aka.ms")
        || destination.contains("windowsupdate")
        || destination.contains("spotify");

    let is_discord = destination.contains("discord")
        || destination.contains("discordapp")
        || destination.contains("discord.gg");

    if is_very_sensitive {
        base.tcp_window_trick = true;
        if failures == 0 {
            // Start Discord conservatively, but allow adaptive escalation later.
            if is_discord {
                stage = stage.max(2);
            } else {
                stage = stage.max(4);
            }
        }
    }

    if failures >= base.stage1_failures {
        stage = stage.max(2); // Jump to Stage 2 immediately if Stage 1 failed
    }
    if failures >= base.stage2_failures {
        stage = stage.max(3);
    }
    if failures >= base.stage3_failures {
        stage = 4;
    }

    stage = stage.min(4);

    if socks4_flow && !WARNED_SOCKS4_AGGRESSIVE.swap(true, Ordering::Relaxed) {
        info!(
            target: "socks5",
            "SOCKS4 aggressive DPI profile enabled for :443 (adaptive stage escalation is active)"
        );
    }

    let tuned = match stage {
        0 => RelayOptions {
            fragment_client_hello: false,
            ..base
        },
        1 => RelayOptions {
            fragment_client_hello: true,
            fragment_size_min: 128,
            fragment_size_max: 256,
            fragment_sleep_ms: base.fragment_sleep_ms.min(1),
            fragment_budget_bytes: base.fragment_budget_bytes.clamp(4096, 8192),
            client_hello_split_offsets: vec![],
            ..base
        },
        2 => RelayOptions {
            fragment_client_hello: true,
            fragment_size_min: 64,
            fragment_size_max: 128,
            fragment_sleep_ms: base.fragment_sleep_ms.max(5), // Increased sleep for stability
            fragment_budget_bytes: base.fragment_budget_bytes.clamp(4096, 8192),
            client_hello_split_offsets: vec![16, 32],
            ..base
        },
        3 => RelayOptions {
            fragment_client_hello: true,
            fragment_size_min: 32,
            fragment_size_max: 64,
            fragment_sleep_ms: base.fragment_sleep_ms.min(1),
            fragment_budget_bytes: base.fragment_budget_bytes.clamp(2048, 4096),
            client_hello_split_offsets: vec![16, 32, 48],
            sni_case_toggle: true,
            ..base
        },
        _ => RelayOptions {
            fragment_client_hello: true,
            #[cfg(windows)]
            fragment_size_min: 64,
            #[cfg(windows)]
            fragment_size_max: 128,
            #[cfg(not(windows))]
            fragment_size_min: 32,
            #[cfg(not(windows))]
            fragment_size_max: 64,
            fragment_sleep_ms: base.fragment_sleep_ms.min(1),
            fragment_budget_bytes: base.fragment_budget_bytes.clamp(4096, 8192),
            client_hello_split_offsets: vec![16, 32, 64],
            sni_spoofing: true,
            sni_case_toggle: true,
            ..base
        },
    };
    if stage > 0 {
        debug!(
            target: "socks5",
            destination = %destination,
            stage,
            source = ?source,
            fragment_size_max = tuned.fragment_size_max,
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

pub(super) fn route_family_for_target(target: &TargetAddr) -> RouteIpFamily {
    match target {
        TargetAddr::Ip(std::net::IpAddr::V4(_)) => RouteIpFamily::V4,
        TargetAddr::Ip(std::net::IpAddr::V6(_)) => RouteIpFamily::V6,
        TargetAddr::Domain(host) => parse_ip_literal(host)
            .map(route_family_for_ip)
            .unwrap_or(RouteIpFamily::Any),
    }
}

pub(super) fn route_family_for_ip(ip: std::net::IpAddr) -> RouteIpFamily {
    match ip {
        std::net::IpAddr::V4(_) => RouteIpFamily::V4,
        std::net::IpAddr::V6(_) => RouteIpFamily::V6,
    }
}

pub(super) fn route_decision_key(destination: &str, target: &TargetAddr) -> String {
    format!(
        "{}|{}",
        route_state_key(destination),
        route_family_for_target(target).label()
    )
}

pub(super) fn route_destination_key(route_key: &str) -> &str {
    route_key
        .split_once('|')
        .map(|(k, _)| k)
        .unwrap_or(route_key)
}

pub(super) fn route_service_key(route_key: &str) -> Option<String> {
    let (destination_key, family) = route_key.split_once('|')?;
    let service_destination = route_service_state_key(destination_key)?;
    Some(format!("{service_destination}|{family}"))
}

pub(super) fn route_meta_service_key(route_key: &str) -> Option<String> {
    let (destination_key, family) = route_key.split_once('|')?;
    let (host, port) = split_host_port_for_connect(destination_key)?;
    let normalized_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized_host.is_empty() || parse_ip_literal(&normalized_host).is_some() {
        return None;
    }
    let bucket = host_service_bucket(&normalized_host);
    if !bucket.starts_with("meta-group:") {
        return None;
    }
    Some(format!("{bucket}:{port}|{family}"))
}

pub(super) fn route_service_state_key(destination: &str) -> Option<String> {
    let (host, port) = split_host_port_for_connect(destination)?;
    let normalized_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized_host.is_empty() {
        return None;
    }
    if parse_ip_literal(&normalized_host).is_some() {
        return None;
    }
    let service_host = registrable_domain_bucket(&normalized_host)?;
    Some(format!("{service_host}:{port}"))
}

pub(super) fn registrable_domain_bucket(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }

    const PRIVATE_SUFFIXES: &[&str] = &[
        "github.io",
        "gitlab.io",
        "pages.dev",
        "workers.dev",
        "vercel.app",
        "netlify.app",
        "herokuapp.com",
        "blogspot.com",
        "appspot.com",
        "azurewebsites.net",
        "firebaseapp.com",
        "web.app",
    ];

    for suffix in PRIVATE_SUFFIXES {
        if host == *suffix {
            return Some(host.clone());
        }
        if let Some(prefix) = host.strip_suffix(suffix).and_then(|v| v.strip_suffix('.')) {
            if prefix.is_empty() {
                continue;
            }
            if let Some(last) = prefix.rsplit('.').next() {
                return Some(format!("{last}.{suffix}"));
            }
        }
    }

    let tld = labels[labels.len() - 1];
    let sld = labels[labels.len() - 2];
    if labels.len() >= 3
        && tld.len() == 2
        && matches!(sld, "co" | "com" | "net" | "org" | "gov" | "edu" | "ac")
    {
        let third = labels[labels.len() - 3];
        return Some(format!("{third}.{sld}.{tld}"));
    }
    Some(format!("{sld}.{tld}"))
}

pub(super) fn route_state_key(destination: &str) -> String {
    if let Some((host, port)) = split_host_port_for_connect(destination) {
        let normalized_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized_host.is_empty() {
            return destination.trim().to_ascii_lowercase();
        }
        if let Some(ip) = parse_ip_literal(&normalized_host) {
            return format!("{ip}:{port}");
        }
        return format!("{normalized_host}:{port}");
    }
    destination.trim().to_ascii_lowercase()
}

pub(super) fn route_capability_is_available(
    kind: RouteKind,
    family: RouteIpFamily,
    now: u64,
) -> bool {
    let map =
        ROUTE_CAPABILITIES.get_or_init(|| std::sync::RwLock::new(RouteCapabilities::default()));
    let Ok(guard) = map.read() else {
        return true;
    };
    let until = match (kind, family) {
        (RouteKind::Direct, RouteIpFamily::V4) => guard.direct_v4_weak_until_unix,
        (RouteKind::Direct, RouteIpFamily::V6) => guard.direct_v6_weak_until_unix,
        (RouteKind::Bypass, RouteIpFamily::V4) => guard.bypass_v4_weak_until_unix,
        (RouteKind::Bypass, RouteIpFamily::V6) => guard.bypass_v6_weak_until_unix,
        (_, RouteIpFamily::Any) => 0,
    };
    until <= now
}
