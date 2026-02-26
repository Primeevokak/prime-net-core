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
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default();
    let _version = parts.next().unwrap_or("HTTP/1.1");

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
        let candidates = select_route_candidates(&relay_opts, &target_endpoint.addr, target_endpoint.port, &target_label);
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
        if connected.candidate.kind == RouteKind::Bypass {
            debug!(
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
            let tuned = tune_relay_for_target(relay_opts.clone(), port, &destination, false, true);
            match relay_bidirectional(&mut tcp, &mut connected.stream, tuned.options.clone()).await {
                Ok((c2u, u2c)) => {
                    let lifetime_ms = bypass_tunnel_started.elapsed().as_millis() as u64;
                    let evasion_tag = if tuned.options.fragment_client_hello {
                        " (double-evasion active)"
                    } else {
                        ""
                    };

                    debug!(
                        target: "socks5",
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
                        if should_mark_empty_bypass_session_as_soft_failure(&connected.candidate, port)
                        {
                            record_route_failure(
                                &connected.route_key,
                                &connected.candidate,
                                "zero-reply-soft",
                            );
                        }
                    } else if u2c < 20 && lifetime_ms < 1000 {
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
                    } else if should_mark_bypass_profile_failure(
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
                            destination = %destination,
                            bytes_client_to_bypass = c2u,
                            bytes_bypass_to_client = u2c,
                            session_lifetime_ms = lifetime_ms,
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

        let is_bypass = connected.candidate.kind == RouteKind::Bypass;
        let mut tuned = tune_relay_for_target(relay_opts, port, &destination, false, false);
        
        // CRITICAL: If we are using a Bypass route, disable internal evasion to avoid "double fragmentation"
        // which triggers antivirus resets and breaks Discord/Cloudflare.
        if is_bypass {
            tuned.options.fragment_client_hello = false;
            tuned.options.tcp_window_trick = false;
            tuned.options.sni_spoofing = false;
            tuned.options.sni_case_toggle = false;
        }

        match relay_bidirectional(&mut tcp, &mut connected.stream, tuned.options.clone()).await {
            Ok((bytes_client_to_upstream, bytes_upstream_to_client)) => {
                if should_skip_empty_session_scoring(bytes_client_to_upstream, bytes_upstream_to_client)
                {
                    debug!(
                        target: "socks5.route",
                        conn_id,
                        route_key = %connected.route_key,
                        route = connected.candidate.route_label(),
                        destination = %destination,
                        "adaptive route skipped scoring for empty direct session"
                    );
                } else if should_mark_suspicious_zero_reply(
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
        // We use base options but explicitly disable our own fragmentation to avoid "double-evasion".
        let mut opts = base.clone();
        opts.fragment_client_hello = false;
        
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
    
    let is_very_sensitive = destination.contains("discord") || destination.contains("instagram") || 
                           destination.contains("facebook") || destination.contains("fbcdn") ||
                           destination.contains("youtube") || destination.contains("ytimg") ||
                           destination.contains("googlevideo") || destination.contains("ggpht") ||
                           destination.contains("google.com") || destination.contains("discordapp") ||
                           destination.contains("discord.gg") || destination.contains("cloudflare") ||
                           destination.contains("aka.ms") || destination.contains("windowsupdate") ||
                           destination.contains("spotify");
                           
    if is_very_sensitive {
        base.tcp_window_trick = true;
        if failures == 0 {
            // Discord doesn't like Stage 4 fragmentation on some ISPs/AVs.
            // Keep it at Stage 2 for Discord initially to be safe but effective.
            // CRITICAL: For Discord, STICK to Stage 2. Do not escalate to 3 or 4.
            if destination.contains("discord") || destination.contains("discordapp") || destination.contains("discord.gg") {
                stage = 2; 
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
            fragment_size_min: 1,
            #[cfg(not(windows))]
            fragment_size_max: 1,
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
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    if labels.len() < 2 {
        return None;
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

pub(super) fn route_capability_is_available(kind: RouteKind, family: RouteIpFamily, now: u64) -> bool {
    let map = ROUTE_CAPABILITIES.get_or_init(|| std::sync::RwLock::new(RouteCapabilities::default()));
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

