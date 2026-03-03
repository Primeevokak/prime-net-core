use crate::config::EngineConfig;
use crate::error::{EngineError, Result};
use crate::pt::{BoxStream, DynOutbound, TargetEndpoint};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::pt::socks5_server::*;
use crate::pt::socks5_server::route_scoring::*;
use crate::pt::socks5_server::classifier_and_persistence::*;
use crate::pt::socks5_server::ml_shadow::*;
use crate::pt::socks5_server::state_and_startup::connect_bypass_upstream;
use crate::pt::socks5_server::relay_and_io_helpers::relay_bidirectional;
use crate::pt::socks5_server::protocol_socks4::handle_socks4;
use crate::pt::socks5_server::protocol_handlers::handle_http_proxy;

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
    for (idx, cand) in candidates.into_iter().enumerate() {
        let c: RouteCandidate = cand.clone();
        let t = target.clone();
        let tl = target_label.to_owned();
        let out = outbound.clone();
        let ro = relay_opts.clone();
        let config = Arc::new(cfg.clone());
        let icd = initial_client_data.clone();
        winners.spawn(async move {
            if idx > 0 { tokio::time::sleep(Duration::from_millis((idx as u64) * 50)).await; }
            let mut stream = connect_route_candidate(conn_id, &t, &tl, &c, out, &ro, config).await?;
            let mut initial_u2c = Vec::new();
            let mut sent = false;
            if let Some(ref data) = icd {
                // To win the race, we MUST send the request and wait for the first byte of response.
                stream.write_all(data).await?; 
                stream.flush().await?; 
                sent = true;
                
                let mut buf = [0u8; 1];
                // Wait for the first byte of response to confirm the route is actually working (bypassing DPI).
                if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(1500), stream.read(&mut buf)).await {
                    if n > 0 { initial_u2c.push(buf[0]); }
                }
            }
            Ok((c, stream, initial_u2c, sent))
        });
    }

    while let Some(res) = winners.join_next().await {
        if let Ok(Ok((cand, stream, u2c, sent))) = res {
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
    Err(EngineError::Internal("race failed: all candidates timed out or failed to connect".to_owned()))
}

pub struct ConnectedRoute { pub stream: BoxStream, pub candidate: RouteCandidate, pub route_key: String, pub decision_id: u64, pub initial_client_data: Vec<u8>, pub initial_upstream_data: Vec<u8>, pub client_data_sent: bool }

pub async fn handle_socks5_connection(conn_id: u64, mut tcp: TcpStream, peer: SocketAddr, _label: &str, outbound: DynOutbound, cfg: Arc<EngineConfig>, _silent_drop: bool, relay_opts: RelayOptions) -> Result<()> {
    let mut hdr = [0u8; 2]; tcp.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 { return Err(EngineError::Internal("not socks5".to_owned())); }
    let mut m = vec![0u8; hdr[1] as usize]; tcp.read_exact(&mut m).await?;
    tcp.write_all(&[0x05, 0x00]).await?;
    let mut req = [0u8; 4]; tcp.read_exact(&mut req).await?;
    let target = read_socks5_target_endpoint_with_atyp(&mut tcp, req[3]).await?;
    
    // We NO LONGER send Success here. We wait for the race to finish.
    
    let mut p = [0u8; 2048];
    // We still try to peek at the first data packet (e.g. TLS Client Hello) if it's already in the buffer.
    // Some clients send it immediately after the SOCKS request (Optimistic Data), but most wait for Success.
    let icd = match tokio::time::timeout(Duration::from_millis(5), tcp.read(&mut p)).await {
        Ok(Ok(n)) if n > 0 => Some(p[..n].to_vec()),
        _ => None,
    };
    handle_socks5_request_with_target(conn_id, tcp, peer, "client", &target, outbound, cfg, relay_opts, icd).await
}

pub async fn handle_socks5_request_with_target(conn_id: u64, mut tcp: TcpStream, peer: SocketAddr, _cl: &str, target: &TargetEndpoint, outbound: DynOutbound, cfg: Arc<EngineConfig>, relay_opts: RelayOptions, icd: Option<Vec<u8>>) -> Result<()> {
    let target_label = target.to_string();
    let candidates = select_route_candidates(&relay_opts, &target.addr, target.port, &target_label, &cfg);
    
    // If we don't have ICD yet (browser waited for Success), we send Success now to provoke the browser.
    // BUT we need a connected stream first to be SOCKS-compliant.
    // So we run the race first. If the browser waited for Success, the race will connect but won't send/receive any data.
    
    let route = connect_via_best_route(conn_id, target, &target_label, candidates, outbound, &relay_opts, &cfg, icd).await?;
    
    // Now that we have a winner, we MUST send SOCKS5 Success if we haven't yet.
    tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0,0,0]).await?;
    
    let mut upstream = route.stream;
    relay_bidirectional(&mut tcp, &mut upstream, relay_opts, route.initial_client_data, route.initial_upstream_data, route.client_data_sent).await?;
    Ok(())
}

async fn read_socks5_target_endpoint_with_atyp(tcp: &mut TcpStream, atyp: u8) -> Result<TargetEndpoint> {
    let addr = match atyp {
        0x01 => { let mut ip = [0u8; 4]; tcp.read_exact(&mut ip).await?; crate::pt::TargetAddr::Ip(std::net::IpAddr::V4(ip.into())) }
        0x03 => { let mut l = [0u8; 1]; tcp.read_exact(&mut l).await?; let mut d = vec![0u8; l[0] as usize]; tcp.read_exact(&mut d).await?; crate::pt::TargetAddr::Domain(String::from_utf8_lossy(&d).to_string()) }
        _ => return Err(EngineError::Internal("unsupported atyp".to_owned())),
    };
    let mut p = [0u8; 2]; tcp.read_exact(&mut p).await?;
    Ok(TargetEndpoint { addr, port: u16::from_be_bytes(p) })
}

fn reap_route_race_losers_v3(winners: JoinSet<Result<(RouteCandidate, BoxStream, Vec<u8>, bool)>>, _cid: u64, _tl: String) {
    tokio::spawn(async move { let mut winners = winners; while let Some(_) = winners.join_next().await {} });
}
