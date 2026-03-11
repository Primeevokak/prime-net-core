use crate::config::EngineConfig;
use crate::error::{EngineError, Result};
use crate::pt::socks5_server::ml_shadow::complete_route_outcome_event;
use crate::pt::socks5_server::protocol_handlers::tune_relay_for_target;
use crate::pt::{BoxStream, DynOutbound, TargetAddr, TargetEndpoint};
use dashmap::DashMap;
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
        let config = cfg_arc.clone(); // CORRECT: Clone Arc, don't move cfg
        let icd = initial_client_data.clone();

        winners.spawn(async move {
            let delay = (idx as u64) * 100;
            if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }

            let mut stream = connect_route_candidate(conn_id, &t, &tl, &c, out, &ro, config.clone()).await?;
            let mut initial_u2c = Vec::new();
            let mut sent = false;

            if let Some(ref data) = icd {
                // Send data using the appropriate technique for this route kind:
                // - Native:  apply TcpDesyncEngine (TLS record split / TCP segment split)
                // - Direct:  optional internal ClientHello fragmentation
                // - Bypass:  pass raw bytes; the external proxy handles evasion
                if c.kind == RouteKind::Native {
                    if let Some(ref engine) = ro.native_bypass {
                        engine
                            .apply(c.bypass_profile_idx as usize, &mut stream, data)
                            .await
                            .map_err(EngineError::Io)?;
                    } else {
                        stream.write_all(data).await?;
                        stream.flush().await?;
                    }
                } else if c.kind == RouteKind::Direct
                    && ro.fragment_client_hello
                    && is_tls_client_hello(data)
                {
                    let _ = fragment_and_send_tls_hello(data, &mut stream, &ro)
                        .await
                        .map_err(EngineError::Io)?;
                } else {
                    stream.write_all(data).await?;
                    stream.flush().await?;
                }
                sent = true;

                let mut buf = [0u8; 4096];
                // Wait for the TLS record header or some response data.
                // Increase timeout to 3s for slower bypass routes like Discord
                if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(3000), stream.read(&mut buf)).await {
                    if n > 0 {
                        // Validate TLS on HTTPS port 443
                        if t.port == 443 && buf[0] != 0x16 {
                            debug!(conn_id, route = %c.route_label(), byte = buf[0], "REJECTED: invalid TLS handshake record type (likely DPI)");
                            return Err(EngineError::Internal("invalid tls handshake (dpi)".to_owned()));
                        }
                        // Validate HTTP on port 80 (common fake redirect)
                        if t.port == 80 && buf[0] == 0x15 {
                            return Err(EngineError::Internal("DPI block page detected".to_owned()));
                        }
                        initial_u2c.extend_from_slice(&buf[..n]);

                        // TRY TO READ MORE: Strict Meta servers might send Server Hello in multiple segments.
                        // Capture as much as possible in 50ms to avoid breaking the flight.
                        let mut extra = [0u8; 4096];
                        while let Ok(Ok(Ok(en))) = tokio::time::timeout(Duration::from_millis(50), tokio::time::timeout(Duration::from_millis(10), stream.read(&mut extra))).await {
                            if en == 0 { break; }
                            initial_u2c.extend_from_slice(&extra[..en]);
                            if initial_u2c.len() > 8192 { break; }
                        }
                    }
                }

                if initial_u2c.is_empty() && (t.port == 443 || t.port == 80) {
                    return Err(EngineError::Internal("no response from candidate".to_owned()));
                }
            }
            Ok((c, stream, initial_u2c, sent))
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
            decision_id: conn_id,
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
        let has_cached_winner = {
            let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
            map.contains_key(route_key)
        };

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
    let tuned = tune_relay_for_target(relay_opts, target.port, &target_label, false, false);
    let relay_opts = tuned.options;

    let route_key = route_destination_key(&target_label);

    let cached_winner = {
        let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        map.get(route_key).map(|w| w.clone())
    };

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

    match route_res {
        Ok(route) => {
            let label = route.candidate.route_label();
            info!(conn_id, target = %target_label, route = %label, "connection established");

            {
                let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
                map.insert(
                    route_key.to_owned(),
                    RouteWinner {
                        route_id: route.candidate.route_id(),
                        updated_at_unix: now_unix_secs(),
                    },
                );
            }

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
                        let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
                        map.remove(route_key);
                    }
                    Err(EngineError::Io(std::io::Error::new(
                        e.kind(),
                        e.to_string(),
                    )))
                }
            }
        }
        Err(e) => {
            let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
            map.remove(route_key);
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
        _ => return Err(EngineError::Internal("unsupported atyp".to_owned())),
    };
    let mut p = [0u8; 2];
    tcp.read_exact(&mut p).await?;
    Ok(TargetEndpoint {
        addr,
        port: u16::from_be_bytes(p),
    })
}

fn reap_route_race_losers_v3(mut winners: JoinSet<Result<RaceTask>>, _cid: u64, _tl: String) {
    winners.abort_all();
    tokio::spawn(async move { while winners.join_next().await.is_some() {} });
}
