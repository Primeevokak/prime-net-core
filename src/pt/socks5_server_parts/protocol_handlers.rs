use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::EngineConfig;
use crate::error::Result;
use crate::pt::{DynOutbound, TargetAddr, TargetEndpoint};
use crate::pt::socks5_server::*;
use crate::pt::socks5_server::route_scoring::*;
use crate::pt::socks5_server::route_connection::*;
use crate::pt::socks5_server::relay_and_io_helpers::*;

pub async fn handle_http_proxy(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    client: String,
    outbound: DynOutbound,
    cfg: Arc<EngineConfig>,
    first_two: [u8; 2],
    relay_opts: RelayOptions,
) -> Result<()> {
    let mut buf = Vec::with_capacity(2048);
    buf.extend_from_slice(&first_two);
    let mut tmp = [0u8; 512];
    loop {
        if find_http_header_end(&buf).is_some() { break; }
        let n = tcp.read(&mut tmp).await?;
        if n == 0 { return Ok(()); }
        buf.extend_from_slice(&tmp[..n]);
    }

    let header_end = find_http_header_end(&buf).unwrap();
    let header_bytes = &buf[..header_end];
    let request = String::from_utf8_lossy(header_bytes);
    let first_line = request.lines().next().unwrap();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap();
    let target = parts.next().unwrap();

    if method == "CONNECT" {
        let (host, port) = split_host_port_for_connect(target).unwrap();
        let target_addr = if let Some(ip) = parse_ip_literal(&host) { TargetAddr::Ip(ip) } else { TargetAddr::Domain(host.clone()) };
        let target_endpoint = TargetEndpoint { addr: target_addr, port };
        let target_label = target_endpoint.to_string();
        let _candidates = select_route_candidates(&relay_opts, &target_endpoint.addr, target_endpoint.port, &target_label, &cfg);
        
        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        
        // Wait for the client to send the first payload (e.g. TLS Client Hello) after we told it the connection is established.
        let mut p = [0u8; 4096];
        let icd = match tokio::time::timeout(std::time::Duration::from_millis(5000), tcp.read(&mut p)).await {
            Ok(Ok(n)) if n > 0 => Some(p[..n].to_vec()),
            _ => None,
        };
        
        handle_socks5_request_with_target(conn_id, tcp, peer, &client, &target_endpoint, outbound, cfg, relay_opts, icd).await
    } else {
        Ok(())
    }
}

pub fn tune_relay_for_target(opts: RelayOptions, _p: u16, _d: &str, _s4: bool, _http: bool) -> TunedRelay {
    TunedRelay { options: opts, stage: 1, source: StageSelectionSource::Default }
}
