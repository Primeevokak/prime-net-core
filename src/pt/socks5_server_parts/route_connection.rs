use crate::config::EngineConfig;
use crate::error::{EngineError, Result};
use crate::pt::{BoxStream, DynOutbound, TargetEndpoint, TargetAddr};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};
use dashmap::DashMap;

use crate::pt::socks5_server::*;
use crate::pt::socks5_server::route_scoring::*;
use crate::pt::socks5_server::state_and_startup::connect_bypass_upstream;
use crate::pt::socks5_server::relay_and_io_helpers::{relay_bidirectional, classify_io_error};
use crate::pt::socks5_server::protocol_socks4::handle_socks4;
use crate::pt::socks5_server::protocol_handlers::handle_http_proxy;
use crate::pt::socks5_server::protocol_udp::handle_udp_associate;

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
            let resolver = outbound.resolver().ok_or_else(|| EngineError::Internal("resolver missing".to_owned()))?;
            let direct = crate::pt::direct::DirectOutbound::new(resolver);
            direct.connect(target.clone()).await
        }
        RouteKind::Bypass => {
            let addr = candidate.bypass_addr.ok_or_else(|| EngineError::Config("bypass addr missing".to_owned()))?;
            let res: Result<TcpStream> = connect_bypass_upstream(conn_id, target, target_label, addr, candidate.bypass_profile_idx, candidate.bypass_profile_total, None, cfg, relay_opts.clone()).await;
            res.map(|s| Box::new(s) as BoxStream)
        }
    }
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
    let mut winners: JoinSet<Result<(RouteCandidate, BoxStream, Vec<u8>, bool)>> = JoinSet::new();
    let cand_count = candidates.len();
    
    for (idx, cand) in candidates.into_iter().enumerate() {
        let c: RouteCandidate = cand.clone();
        let t = target.clone();
        let tl = target_label.to_owned();
        let out = outbound.clone();
        let ro = relay_opts.clone();
        let config = Arc::new(cfg.clone());
        let icd = initial_client_data.clone();
        winners.spawn(async move {
            let delay = (idx as u64) * 100;
            if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
            
            let mut stream = connect_route_candidate(conn_id, &t, &tl, &c, out, &ro, config).await?;
            let mut initial_u2c = Vec::new();
            let mut sent = false;
            
            // SNIPER MODE: For port 443, we MUST verify the connection by sending data and reading a response.
            // This prevents "fake fast" connections that win the race but fail immediately on data.
            if let Some(ref data) = icd {
                stream.write_all(data).await?; 
                stream.flush().await?; 
                sent = true;
                
                let mut buf = [0u8; 1];
                // Wait for the first byte of response (e.g., Server Hello 0x16)
                if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(3000), stream.read(&mut buf)).await {
                    if n > 0 {
                        // Basic TLS check: Server Hello starts with 0x16 (Handshake)
                        if t.port == 443 && buf[0] != 0x16 {
                            debug!(conn_id, route = %c.route_label(), byte = buf[0], "invalid tls handshake response (dpi block?)");
                            return Err(EngineError::Internal("invalid tls handshake (dpi)".to_owned()));
                        }
                        initial_u2c.push(buf[0]);
                    }
                }
                
                // If we're on port 443, we REQUIRE a response to win the race.
                if t.port == 443 && initial_u2c.is_empty() {
                    return Err(EngineError::Internal("no response from upstream".to_owned()));
                }
            } else if t.port == 443 {
                // If port 443 but we have no client data, this candidate cannot win a race 
                // against other potentially better candidates that we can't probe yet.
                // We let it fail so a more stable route is chosen once we HAVE data.
                return Err(EngineError::Internal("missing client data for race probing".to_owned()));
            }
            Ok((c, stream, initial_u2c, sent))
        });
    }

    while let Some(res) = winners.join_next().await {
        if let Ok(Ok((cand, stream, u2c, sent))) = res {
            if cand_count > 1 {
                info!(conn_id, route = %cand.route_label(), "route race winner selected");
            }
            reap_route_race_losers_v3(winners, conn_id, target_label.to_owned());
            return Ok(ConnectedRoute { 
                stream, 
                candidate: cand, 
                route_key: target_label.to_owned(), 
                decision_id: 0, 
                initial_client_data: initial_client_data.unwrap_or_default(), 
                initial_upstream_data: u2c, 
                client_data_sent: sent 
            });
        }
    }
    Err(EngineError::Internal("race failed: no working route found".to_owned()))
}

pub struct ConnectedRoute { pub stream: BoxStream, pub candidate: RouteCandidate, pub route_key: String, pub decision_id: u64, pub initial_client_data: Vec<u8>, pub initial_upstream_data: Vec<u8>, pub client_data_sent: bool }

pub async fn handle_socks5_connection(conn_id: u64, mut tcp: TcpStream, peer: SocketAddr, _label: &str, outbound: DynOutbound, cfg: Arc<EngineConfig>, _silent_drop: bool, relay_opts: RelayOptions) -> Result<()> {
    let mut hdr = [0u8; 2];
    tcp.read_exact(&mut hdr).await?;

    if hdr[0] == 0x05 {
        let mut m = vec![0u8; hdr[1] as usize];
        tcp.read_exact(&mut m).await?;
        tcp.write_all(&[0x05, 0x00]).await?;
        let mut req = [0u8; 4];
        tcp.read_exact(&mut req).await?;
        
        if req[1] == 0x03 {
            // UDP ASSOCIATE - Now supported with selective QUIC blocking
            return handle_udp_associate(conn_id, tcp, peer).await;
        }

        let target = read_socks5_target_endpoint_with_atyp(&mut tcp, req[3]).await?;
        
        tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        
        let target_str = target.to_string();
        let route_key = route_destination_key(&target_str);
        let has_cached_winner = {
            let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
            map.contains_key(route_key)
        };

        let mut p = [0u8; 4096];
        // CRITICAL: For port 443, we MUST wait for the TLS Client Hello to perform a safe 'route race'.
        let wait_ms = if target.port == 443 { 2000 } else if has_cached_winner { 500 } else { 1500 };
        
        let icd = match tokio::time::timeout(Duration::from_millis(wait_ms), tcp.read(&mut p)).await {
            Ok(Ok(n)) if n > 0 => Some(p[..n].to_vec()),
            _ => None,
        };
        handle_socks5_request_with_target(conn_id, tcp, peer, "client", &target, outbound, cfg, relay_opts, icd).await
    } else if hdr[0] == 0x04 {
        let cmd = hdr[1];
        handle_socks4(conn_id, tcp, peer, "client".to_owned(), outbound, cfg, cmd, _silent_drop, relay_opts).await
    } else if hdr[0] == b'G' || hdr[0] == b'C' || hdr[0] == b'P' || hdr[0] == b'H' {
        handle_http_proxy(conn_id, tcp, peer, "client".to_owned(), outbound, cfg, hdr, relay_opts).await
    } else {
        warn!(target: "socks5", conn_id, first_byte = hdr[0], "unknown protocol detected");
        Err(EngineError::Internal("unsupported protocol".to_owned()))
    }
}

pub async fn handle_socks5_request_with_target(conn_id: u64, mut tcp: TcpStream, _peer: SocketAddr, _cl: &str, target: &TargetEndpoint, outbound: DynOutbound, cfg: Arc<EngineConfig>, relay_opts: RelayOptions, icd: Option<Vec<u8>>) -> Result<()> {
    let target_label = target.to_string();
    let route_key = route_destination_key(&target_label);
    
    // 1. Check cached winner
    let cached_winner = {
        let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        map.get(route_key).map(|w| w.clone())
    };

    let candidates = if let Some(winner) = cached_winner {
        if now_unix_secs().saturating_sub(winner.updated_at_unix) < ROUTE_WINNER_TTL_SECS {
            let mut cands = select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg);
            cands.retain(|c| c.route_id() == winner.route_id);
            if !cands.is_empty() { cands } else { select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg) }
        } else { select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg) }
    } else { select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg) };
    
    let route_res = connect_via_best_route(conn_id, target, &target_label, candidates, outbound, &relay_opts, &cfg, icd).await;
    
    match route_res {
        Ok(route) => {
            {
                let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
                map.insert(route_key.to_owned(), RouteWinner {
                    route_id: route.candidate.route_id(),
                    updated_at_unix: now_unix_secs(),
                });
            }
            let mut upstream = route.stream;
            let relay_res = relay_bidirectional(&mut tcp, &mut upstream, relay_opts, route.initial_client_data, route.initial_upstream_data, route.client_data_sent).await;
            if let Err(ref e) = relay_res {
                let signal = classify_io_error(e);
                if signal == BlockingSignal::Reset || signal == BlockingSignal::Timeout {
                    debug!(conn_id, error = %e, signal = ?signal, "upstream relay failed, invalidating cache for {}", route_key);
                    let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
                    map.remove(route_key);
                } else {
                    debug!(conn_id, error = %e, signal = ?signal, "client disconnected, keeping cache for {}", route_key);
                }
                return Err(EngineError::Io(std::io::Error::new(e.kind(), e.to_string())));
            }
            Ok(())
        }
        Err(e) => {
            let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
            map.remove(route_key);
            Err(e)
        }
    }
}

async fn read_socks5_target_endpoint_with_atyp(tcp: &mut TcpStream, atyp: u8) -> Result<TargetEndpoint> {
    let addr = match atyp {
        0x01 => { let mut ip = [0u8; 4]; tcp.read_exact(&mut ip).await?; TargetAddr::Ip(std::net::IpAddr::V4(ip.into())) }
        0x03 => { let mut l = [0u8; 1]; tcp.read_exact(&mut l).await?; let mut d = vec![0u8; l[0] as usize]; tcp.read_exact(&mut d).await?; TargetAddr::Domain(String::from_utf8_lossy(&d).to_string()) }
        _ => return Err(EngineError::Internal("unsupported atyp".to_owned())),
    };
    let mut p = [0u8; 2]; tcp.read_exact(&mut p).await?;
    Ok(TargetEndpoint { addr, port: u16::from_be_bytes(p) })
}

fn reap_route_race_losers_v3(mut winners: JoinSet<Result<(RouteCandidate, BoxStream, Vec<u8>, bool)>>, _cid: u64, _tl: String) {
    // CRITICAL FIX: Abort all pending connections immediately so they don't leak sockets.
    winners.abort_all();
    tokio::spawn(async move { while let Some(_) = winners.join_next().await {} });
}