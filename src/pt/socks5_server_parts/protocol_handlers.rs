use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::EngineConfig;
use crate::error::{EngineError, Result};
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

    let header_end = find_http_header_end(&buf).ok_or_else(|| EngineError::Internal("malformed http header".to_owned()))?;
    let header_bytes = &buf[..header_end];
    let request = String::from_utf8_lossy(header_bytes);
    let first_line = request.lines().next().ok_or_else(|| EngineError::Internal("empty http request".to_owned()))?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().ok_or_else(|| EngineError::Internal("invalid http method".to_owned()))?;
    let target = parts.next().ok_or_else(|| EngineError::Internal("invalid http target".to_owned()))?;

    if method == "CONNECT" {
        let (host, port) = split_host_port_for_connect(target).ok_or_else(|| EngineError::Internal("invalid http connect target".to_owned()))?;
        let target_addr = if let Some(ip) = parse_ip_literal(&host) { TargetAddr::Ip(ip) } else { TargetAddr::Domain(host.to_owned()) };
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

pub fn tune_relay_for_target(mut opts: RelayOptions, port: u16, destination: &str, _s4: bool, _http: bool) -> TunedRelay {
    let dest_lower = destination.to_lowercase();
    let group_key = route_destination_key(&dest_lower);

    // 1. Check for a learned preferred stage for this destination or its group
    let learned_stage = {
        let map = DEST_PREFERRED_STAGE.get_or_init(dashmap::DashMap::new);
        map.get(&dest_lower).or_else(|| map.get(group_key)).map(|v| *v)
    };

    if let Some(stage) = learned_stage {
        if stage >= 2 && port == 443 {
            opts.fragment_client_hello = true;
            opts.fragment_size_min = 500; // Keep handshake intact for ByeDPI
            opts.fragment_size_max = 1000; 
            opts.fragment_sleep_ms = 0;
        }
        return TunedRelay { 
            options: opts, 
            stage, 
            source: StageSelectionSource::Classifier 
        };
    }

    // 2. Fallback to domain-based hardcoded rules
    let is_censored = dest_lower.contains("soundcloud") || dest_lower.contains("instagram") || dest_lower.contains("facebook") || dest_lower.contains("fbcdn");
    
    let stage = if is_censored && port == 443 {
        // For highly censored media platforms, ensure the first packet is large enough for ByeDPI to see SNI
        opts.fragment_client_hello = true;
        opts.fragment_size_min = 500; 
        opts.fragment_size_max = 1000; 
        opts.fragment_sleep_ms = 0; 
        2 // Start at stage 2
    } else {
        1
    };

    TunedRelay { 
        options: opts, 
        stage, 
        source: if is_censored { StageSelectionSource::DomainMatch } else { StageSelectionSource::Default } 
    }
}
