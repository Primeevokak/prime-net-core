use crate::config::EngineConfig;
use crate::error::{EngineError, Result};
use crate::pt::socks5_server::ml_shadow::{complete_route_outcome_event, next_route_decision_id};
use crate::pt::socks5_server::protocol_handlers::tune_relay_for_target;
use crate::pt::{BoxStream, DynOutbound, TargetAddr, TargetEndpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::Duration;
use tracing::{debug, info, warn};

use crate::pt::socks5_server::protocol_handlers::handle_http_proxy;
use crate::pt::socks5_server::protocol_socks4::handle_socks4;
use crate::pt::socks5_server::protocol_udp::handle_udp_associate;
use crate::pt::socks5_server::relay_and_io_helpers::{
    classify_io_error, fragment_and_send_tls_hello, is_tls_client_hello, relay_bidirectional,
};
use crate::pt::socks5_server::route_scoring::*;
use crate::pt::socks5_server::state_and_startup::connect_bypass_upstream;
use crate::pt::socks5_server::*;

/// Result payload for a single route-race contestant task.
type RaceTask = (RouteCandidate, BoxStream, Vec<u8>, bool);

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
            let resolver = outbound.resolver().ok_or(EngineError::ResolverMissing)?;
            let direct = crate::pt::direct::DirectOutbound::new(resolver);
            direct.connect(target.clone()).await
        }
        RouteKind::Bypass => {
            let addr = candidate
                .bypass_addr
                .ok_or(EngineError::BypassAddrMissing)?;
            let res: Result<TcpStream> = connect_bypass_upstream(
                conn_id,
                target,
                target_label,
                addr,
                candidate.bypass_profile_idx,
                candidate.bypass_profile_total,
                None,
                cfg,
                relay_opts.clone(),
            )
            .await;
            res.map(|s| Box::new(s) as BoxStream)
        }
        RouteKind::Native => {
            // Native: direct TCP connect — the TcpDesyncEngine transforms the
            // ClientHello in connect_via_best_route before the relay starts.
            let resolver = outbound.resolver().ok_or(EngineError::ResolverMissing)?;
            let direct = crate::pt::direct::DirectOutbound::new(resolver);
            direct.connect(target.clone()).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
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
    let mut winners: JoinSet<Result<RaceTask>> = JoinSet::new();
    let cand_count = candidates.len();
    let cfg_arc = Arc::new(cfg.clone());

    for (idx, cand) in candidates.into_iter().enumerate() {
        let c = cand.clone();
        let t = target.clone();
        let tl = target_label.to_owned();
        let out = outbound.clone();
        let ro = relay_opts.clone();
        let config = cfg_arc.clone();
        let icd = initial_client_data.clone();

        winners.spawn(async move {
            // 50 ms stagger between candidates reduces thundering-herd while still
            // allowing later (potentially better-scored) profiles to start quickly.
            let delay = (idx as u64) * 50;
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            // Hard cap per candidate: 5 s covers connect + initial-response read
            // (3 s) with margin.  Losing tasks are reaped faster after a winner
            // is found.
            tokio::time::timeout(Duration::from_secs(5), async move {
                let mut initial_u2c = Vec::new();
                let mut sent = false;

                // Native routes connect via raw TcpStream to enable OOB byte injection
                // and fake low-TTL probes.  All other routes go through connect_route_candidate.
                if c.kind == RouteKind::Native {
                    if let Some(ref engine) = ro.native_bypass {
                        let profile_idx = c.bypass_profile_idx as usize;
                        let resolver = out.resolver().ok_or(EngineError::ResolverMissing)?;
                        let direct = crate::pt::direct::DirectOutbound::new(resolver);

                        // Send a fake low-TTL probe to desync the DPI's TCP state table.
                        if let Some(probe) = engine.profile_fake_probe(profile_idx) {
                            if let Ok(addr) = direct.resolve_target_ip(&t).await {
                                if let Some(sni) = probe.fake_sni.as_deref() {
                                    // Crafted TLS ClientHello probe — DPI parses the fake SNI
                                    // then loses state when the probe expires (low TTL).
                                    let _ = crate::evasion::dpi_bypass::send_fake_sni_probe(
                                        addr, probe.ttl, sni,
                                    )
                                    .await;
                                } else if probe.data_size == 0 {
                                    let _ = crate::evasion::dpi_bypass::send_tcb_desync_probe(
                                        addr, probe.ttl,
                                    )
                                    .await;
                                } else {
                                    let _ = crate::evasion::dpi_bypass::send_fake_payload_probe(
                                        addr,
                                        probe.ttl,
                                        probe.data_size,
                                    )
                                    .await;
                                }
                            }
                        }

                        let mut tcp = direct.connect_tcp_stream(t.clone()).await?;

                        if let Some(ref data) = icd {
                            engine
                                .apply_to_tcp_stream(profile_idx, &mut tcp, data)
                                .await
                                .map_err(EngineError::Io)?;
                            sent = true;
                            let label = c.route_label();
                            initial_u2c =
                                read_initial_upstream_response(&mut tcp, t.port, conn_id, &label)
                                    .await?;
                        }

                        let stream: BoxStream = Box::new(tcp);
                        return Ok((c, stream, initial_u2c, sent));
                    }
                }

                // Direct, Bypass, or Native without an engine.
                let mut stream =
                    connect_route_candidate(conn_id, &t, &tl, &c, out, &ro, config.clone()).await?;

                if let Some(ref data) = icd {
                    match c.kind {
                        RouteKind::Native => {
                            // Native without engine — pass through unchanged.
                            stream.write_all(data).await?;
                            stream.flush().await?;
                        }
                        RouteKind::Direct
                            if ro.fragment_client_hello && is_tls_client_hello(data) =>
                        {
                            let _ = fragment_and_send_tls_hello(data, &mut stream, &ro)
                                .await
                                .map_err(EngineError::Io)?;
                        }
                        _ => {
                            stream.write_all(data).await?;
                            stream.flush().await?;
                        }
                    }
                    sent = true;
                    let label = c.route_label();
                    initial_u2c =
                        read_initial_upstream_response(&mut stream, t.port, conn_id, &label)
                            .await?;
                }

                Ok((c, stream, initial_u2c, sent))
            })
            .await
            .unwrap_or_else(|_| Err(EngineError::Internal("race candidate timed out".to_owned())))
        });
    }

    let mut final_res = None;
    while let Some(res) = winners.join_next().await {
        if let Ok(Ok((cand, stream, u2c, sent))) = res {
            if cand_count > 1 {
                info!(conn_id, route = %cand.route_label(), "route race winner selected");
            }
            final_res = Some((cand, stream, u2c, sent));
            break;
        }
    }

    if let Some((cand, stream, u2c, sent)) = final_res {
        reap_route_race_losers_v3(winners, conn_id, target_label.to_owned());
        return Ok(ConnectedRoute {
            stream,
            candidate: cand,
            route_key: target_label.to_owned(),
            // Use a unique decision ID distinct from conn_id: one connection may make
            // several routing decisions (retries, race restarts), and the ML shadow keyed
            // by decision_id must not collide across them.
            decision_id: next_route_decision_id(),
            initial_client_data: initial_client_data.unwrap_or_default(),
            initial_upstream_data: u2c,
            client_data_sent: sent,
        });
    }
    Err(EngineError::Internal(
        "race failed: no working route found".to_owned(),
    ))
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

#[allow(clippy::too_many_arguments)]
pub async fn handle_socks5_connection(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    _label: &str,
    outbound: DynOutbound,
    cfg: Arc<EngineConfig>,
    _silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    let mut hdr = [0u8; 2];
    tcp.read_exact(&mut hdr).await?;

    if hdr[0] == 0x05 {
        let mut m = vec![0u8; hdr[1] as usize];
        tcp.read_exact(&mut m).await?;
        if !m.contains(&0x00) {
            // RFC 1928 §3: no acceptable method — reply 0xFF and close
            let _ = tcp.write_all(&[0x05, 0xFF]).await;
            return Err(EngineError::Internal(
                "SOCKS5 client offered no acceptable auth method".to_owned(),
            ));
        }
        tcp.write_all(&[0x05, 0x00]).await?;
        let mut req = [0u8; 4];
        tcp.read_exact(&mut req).await?;

        let target = read_socks5_target_endpoint_with_atyp(&mut tcp, req[3]).await?;
        if req[1] == 0x03 {
            let resolver = outbound.resolver().ok_or_else(|| {
                EngineError::Internal("resolver missing for UDP associate".to_owned())
            })?;
            return handle_udp_associate(conn_id, tcp, peer, resolver, cfg, relay_opts).await;
        }

        // UNBLOCK CLIENT: Send SOCKS5 success reply NOW so the client can send its first payload (e.g. TLS Client Hello)
        tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        let target_str = target.to_string();
        let route_key = route_destination_key(&target_str);
        let has_cached_winner = routing_state().dest_route_winner.contains_key(route_key);

        let mut p = [0u8; 4096];
        let wait_ms = if target.port == 443 {
            2000
        } else if has_cached_winner {
            500
        } else {
            1500
        };

        let icd = match tokio::time::timeout(Duration::from_millis(wait_ms), tcp.read(&mut p)).await
        {
            Ok(Ok(n)) if n > 0 => Some(p[..n].to_vec()),
            _ => None,
        };
        handle_socks5_request_with_target(
            conn_id, tcp, peer, "client", &target, outbound, cfg, relay_opts, icd,
        )
        .await
    } else if hdr[0] == 0x04 {
        let cmd = hdr[1];
        handle_socks4(
            conn_id,
            tcp,
            peer,
            "client".to_owned(),
            outbound,
            cfg,
            cmd,
            _silent_drop,
            relay_opts,
        )
        .await
    } else if hdr[0] == b'G' || hdr[0] == b'C' || hdr[0] == b'P' || hdr[0] == b'H' {
        handle_http_proxy(
            conn_id,
            tcp,
            peer,
            "client".to_owned(),
            outbound,
            cfg,
            hdr,
            relay_opts,
        )
        .await
    } else {
        warn!(target: "socks5", conn_id, first_byte = hdr[0], "unknown protocol detected");
        Err(EngineError::Internal("unsupported protocol".to_owned()))
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_socks5_request_with_target(
    conn_id: u64,
    mut tcp: TcpStream,
    _peer: SocketAddr,
    _cl: &str,
    target: &TargetEndpoint,
    outbound: DynOutbound,
    cfg: Arc<EngineConfig>,
    relay_opts: RelayOptions,
    icd: Option<Vec<u8>>,
) -> Result<()> {
    let target_label = target.to_string();
    let tuned = tune_relay_for_target(relay_opts, target.port, &target_label, false, false, &cfg);
    let relay_opts = tuned.options;

    let route_key = route_destination_key(&target_label);

    let cached_winner = routing_state()
        .dest_route_winner
        .get(route_key)
        .map(|w| w.clone());

    let candidates = if let Some(winner) = cached_winner {
        if now_unix_secs().saturating_sub(winner.updated_at_unix) < ROUTE_WINNER_TTL_SECS {
            let mut cands = select_route_candidates(
                &relay_opts,
                &target.addr,
                target.port,
                &target_label,
                &cfg,
            );
            cands.retain(|c| c.route_id() == winner.route_id);
            if !cands.is_empty() {
                cands
            } else {
                select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg)
            }
        } else {
            select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg)
        }
    } else {
        select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg)
    };

    // Capture native profile indices from the first race for retry logic.
    let tried_native_indices: Vec<u8> = candidates
        .iter()
        .filter(|c| c.kind == RouteKind::Native)
        .map(|c| c.bypass_profile_idx)
        .collect();
    let target_family = route_family_for_target(&target.addr);

    // Clone outbound and icd before moving — needed if a retry race is required.
    let outbound_clone = outbound.clone();
    let icd_clone = icd.clone();

    let route_res = connect_via_best_route(
        conn_id,
        target,
        &target_label,
        candidates,
        outbound,
        &relay_opts,
        &cfg,
        icd,
    )
    .await;

    // If the first race failed and the domain is not pinned to a specific native profile,
    // retry with any native profiles that were not included in the initial race.
    let route_res = if route_res.is_err()
        && !destination_has_native_pin(&target_label, &cfg)
        && !tried_native_indices.is_empty()
    {
        let retry_cands =
            build_native_retry_candidates(&tried_native_indices, &relay_opts, target_family);
        if !retry_cands.is_empty() {
            info!(
                conn_id,
                remaining = retry_cands.len(),
                "first race failed — retrying with {} unused native profile(s)",
                retry_cands.len()
            );
            let retry = connect_via_best_route(
                conn_id,
                target,
                &target_label,
                retry_cands,
                outbound_clone,
                &relay_opts,
                &cfg,
                icd_clone,
            )
            .await;
            if retry.is_ok() {
                retry
            } else {
                route_res
            }
        } else {
            route_res
        }
    } else {
        route_res
    };

    match route_res {
        Ok(route) => {
            let label = route.candidate.route_label();
            info!(conn_id, target = %target_label, route = %label, "connection established");

            routing_state().dest_route_winner.insert(
                route_key.to_owned(),
                RouteWinner {
                    route_id: route.candidate.route_id(),
                    updated_at_unix: now_unix_secs(),
                },
            );

            // Record success for the classifier
            classifier_and_persistence::record_destination_success(
                route_key,
                tuned.stage,
                tuned.source,
                &cfg,
            );

            let mut upstream = route.stream;
            let start_time = Instant::now();

            // CRITICAL: Bypass and Native both handle evasion themselves.
            // Disable internal fragmentation to avoid double-evasion (e.g. Facebook resets).
            let mut final_opts = relay_opts;
            if route.candidate.kind == RouteKind::Bypass
                || route.candidate.kind == RouteKind::Native
            {
                final_opts.fragment_client_hello = false;
            }

            let relay_res = relay_bidirectional(
                &mut tcp,
                &mut upstream,
                final_opts,
                route.initial_client_data,
                route.initial_upstream_data,
                route.client_data_sent,
            )
            .await;

            match relay_res {
                Ok((c2u, u2c)) => {
                    info!(conn_id, tx = c2u, rx = u2c, "session finished normally");
                    complete_route_outcome_event(
                        conn_id,
                        route_key,
                        Some(&route.candidate),
                        true,
                        true,
                        u2c,
                        start_time.elapsed().as_millis() as u64,
                        "",
                        &cfg,
                    );
                    Ok(())
                }
                Err(e) => {
                    let signal = classify_io_error(&e);
                    complete_route_outcome_event(
                        conn_id,
                        route_key,
                        Some(&route.candidate),
                        false,
                        false,
                        0,
                        start_time.elapsed().as_millis() as u64,
                        &format!("{:?}", signal),
                        &cfg,
                    );

                    // Always update per-route health so the ML scorer learns from relay failures
                    record_route_failure(route_key, &route.candidate, "relay-phase", &cfg);

                    // Record failure for the classifier if it's a strong blocking signal
                    if signal == BlockingSignal::Reset || signal == BlockingSignal::Timeout {
                        classifier_and_persistence::record_destination_failure(
                            route_key,
                            signal,
                            0,
                            tuned.stage,
                            &cfg,
                        );

                        debug!(conn_id, error = %e, signal = ?signal, "upstream failure, invalidating cache for {}", route_key);
                        routing_state().dest_route_winner.remove(route_key);
                    }
                    Err(EngineError::Io(std::io::Error::new(
                        e.kind(),
                        e.to_string(),
                    )))
                }
            }
        }
        Err(e) => {
            routing_state().dest_route_winner.remove(route_key);
            // All route candidates failed — record a blocking signal so the dynamic
            // classifier learns this destination is blocked.  Without this call the
            // classifier never sees the failure and keeps treating the destination as
            // unblocked on every subsequent connection (e.g. Telegram IP addresses).
            classifier_and_persistence::record_destination_failure(
                route_key,
                BlockingSignal::Timeout,
                0,
                tuned.stage,
                &cfg,
            );
            Err(e)
        }
    }
}

async fn read_socks5_target_endpoint_with_atyp(
    tcp: &mut TcpStream,
    atyp: u8,
) -> Result<TargetEndpoint> {
    let addr = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            tcp.read_exact(&mut ip).await?;
            TargetAddr::Ip(std::net::IpAddr::V4(ip.into()))
        }
        0x03 => {
            let mut l = [0u8; 1];
            tcp.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            tcp.read_exact(&mut d).await?;
            TargetAddr::Domain(String::from_utf8_lossy(&d).to_string())
        }
        0x04 => {
            // RFC 1928 §5: IPv6 address, 16 octets in network byte order.
            let mut ip = [0u8; 16];
            tcp.read_exact(&mut ip).await?;
            TargetAddr::Ip(std::net::IpAddr::V6(ip.into()))
        }
        _ => {
            return Err(EngineError::Internal(format!(
                "unsupported SOCKS5 atyp: {atyp:#x}"
            )))
        }
    };
    let mut p = [0u8; 2];
    tcp.read_exact(&mut p).await?;
    Ok(TargetEndpoint {
        addr,
        port: u16::from_be_bytes(p),
    })
}

/// Wait for the first bytes from the upstream and validate them.
///
/// Returns the collected initial response bytes, or an error if the response
/// looks like a DPI block page or if no data arrives within 3 seconds.
async fn read_initial_upstream_response<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    port: u16,
    conn_id: u64,
    route_label: &str,
) -> Result<Vec<u8>> {
    let mut initial = Vec::new();
    let mut buf = [0u8; 4096];

    // Wait up to 3 s for the first byte — bypass routes are slower than Direct.
    if let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(3000), stream.read(&mut buf)).await
    {
        if n > 0 {
            // Validate TLS record type on HTTPS ports (443 and 8443 are always TLS;
            // other ports in the native-candidate range can carry plaintext).
            let is_tls_port = port == 443 || port == 8443;
            if is_tls_port && buf[0] != 0x16 {
                debug!(
                    conn_id,
                    route = %route_label,
                    byte = buf[0],
                    "REJECTED: invalid TLS handshake record type (likely DPI)"
                );
                return Err(EngineError::Internal(
                    "invalid tls handshake (dpi)".to_owned(),
                ));
            }
            // TLS alert on port 80 indicates a DPI block page.
            if port == 80 && buf[0] == 0x15 {
                return Err(EngineError::Internal("DPI block page detected".to_owned()));
            }
            initial.extend_from_slice(&buf[..n]);

            // Read more data for up to 50 ms — some servers send ServerHello
            // in multiple TCP segments (e.g. strict Meta servers).
            let mut extra = [0u8; 4096];
            let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
            while let Ok(Ok(en)) = tokio::time::timeout_at(deadline, stream.read(&mut extra)).await
            {
                if en == 0 {
                    break;
                }
                initial.extend_from_slice(&extra[..en]);
                if initial.len() > 8192 {
                    break;
                }
            }
        }
    }

    if initial.is_empty() && (port == 443 || port == 80) {
        return Err(EngineError::Internal(
            "no response from candidate".to_owned(),
        ));
    }
    Ok(initial)
}

fn reap_route_race_losers_v3(mut winners: JoinSet<Result<RaceTask>>, _cid: u64, _tl: String) {
    winners.abort_all();
    tokio::spawn(async move { while winners.join_next().await.is_some() {} });
}
