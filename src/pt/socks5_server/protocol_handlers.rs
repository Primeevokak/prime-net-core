use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::EngineConfig;
use crate::error::{EngineError, Result};
use crate::pt::{DynOutbound, TargetAddr, TargetEndpoint};

use crate::pt::socks5_server::relay_and_io_helpers::*;
use crate::pt::socks5_server::route_connection::*;
use crate::pt::socks5_server::route_scoring::*;
use crate::pt::socks5_server::*;

#[allow(clippy::too_many_arguments)]
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
    const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
    let mut buf = Vec::with_capacity(2048);
    buf.extend_from_slice(&first_two);
    let mut tmp = [0u8; 512];
    let header_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if find_http_header_end(&buf).is_some() {
            break;
        }
        if buf.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(EngineError::InvalidInput(
                "HTTP header too large".to_owned(),
            ));
        }
        let n = match tokio::time::timeout_at(header_deadline, tcp.read(&mut tmp)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(EngineError::Io(e)),
            Err(_) => {
                return Err(EngineError::Internal(
                    "HTTP header read timed out".to_owned(),
                ))
            }
        };
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let header_end = find_http_header_end(&buf)
        .ok_or_else(|| EngineError::InvalidInput("malformed HTTP header".to_owned()))?;
    let header_bytes = &buf[..header_end];
    let request = String::from_utf8_lossy(header_bytes);
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| EngineError::InvalidInput("empty HTTP request".to_owned()))?;
    let mut parts = first_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| EngineError::InvalidInput("invalid HTTP method".to_owned()))?;
    let target = parts
        .next()
        .ok_or_else(|| EngineError::InvalidInput("invalid HTTP target".to_owned()))?;

    if method == "CONNECT" {
        let (host, port) = split_host_port_for_connect(target)
            .ok_or_else(|| EngineError::InvalidInput("invalid HTTP CONNECT target".to_owned()))?;
        let target_addr = if let Some(ip) = parse_ip_literal(&host) {
            TargetAddr::Ip(ip)
        } else {
            TargetAddr::Domain(host.to_owned())
        };
        let target_endpoint = TargetEndpoint {
            addr: target_addr,
            port,
        };
        let target_label = target_endpoint.to_string();
        let _candidates = select_route_candidates(
            &relay_opts,
            &target_endpoint.addr,
            target_endpoint.port,
            &target_label,
            &cfg,
        );

        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Wait for the client to send the first payload (e.g. TLS Client Hello) after we told it the connection is established.
        let mut p = [0u8; 4096];
        let icd =
            match tokio::time::timeout(std::time::Duration::from_millis(5000), tcp.read(&mut p))
                .await
            {
                Ok(Ok(n)) if n > 0 => Some(p[..n].to_vec()),
                _ => None,
            };

        handle_socks5_request_with_target(
            conn_id,
            tcp,
            peer,
            &client,
            &target_endpoint,
            outbound,
            cfg,
            relay_opts,
            icd,
        )
        .await
    } else {
        // Only CONNECT is supported; return a proper error so the client knows why
        let _ = tcp
            .write_all(
                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
        Ok(())
    }
}

/// Returns `true` if `dest_lower` (which may include a port, e.g. `"cdn1.sndcdn.com:443"`)
/// matches any suffix entry in `cfg.evasion.aggressive_fragment_domains`.
fn matches_aggressive_fragment(dest_lower: &str, cfg: &EngineConfig) -> bool {
    let host = dest_lower.split(':').next().unwrap_or(dest_lower);
    cfg.evasion
        .aggressive_fragment_domains
        .iter()
        .any(|suffix| {
            let s = suffix.trim().trim_start_matches('.');
            if s.is_empty() {
                return false;
            }
            host == s || host.ends_with(&format!(".{s}"))
        })
}

pub fn tune_relay_for_target(
    mut opts: RelayOptions,
    port: u16,
    destination: &str,
    _s4: bool,
    _http: bool,
    cfg: &EngineConfig,
) -> TunedRelay {
    let dest_lower = destination.to_lowercase();
    let group_key = route_destination_key(&dest_lower);

    // 1. Check for a learned preferred stage for this destination or its group
    let learned_stage = {
        let map = &routing_state().dest_preferred_stage;
        map.get(&dest_lower)
            .or_else(|| map.get(group_key))
            .map(|v| *v)
    };

    if let Some(stage) = learned_stage {
        if stage >= 2 && port == 443 {
            opts.fragment_client_hello = true;
            opts.fragment_size_min = 40;
            opts.fragment_size_max = 128;
            opts.fragment_sleep_ms = 5;
        }
        return TunedRelay {
            options: opts,
            stage,
            source: StageSelectionSource::Classifier,
        };
    }

    // 2. Fallback: aggressive_fragment_domains from config
    let is_censored = matches_aggressive_fragment(&dest_lower, cfg);

    let stage = if is_censored && port == 443 {
        // For highly censored platforms, use small chunks for Direct mode
        opts.fragment_client_hello = true;
        opts.fragment_size_min = 40;
        opts.fragment_size_max = 128;
        opts.fragment_sleep_ms = 5;
        2 // Start at stage 2
    } else {
        1
    };

    TunedRelay {
        options: opts,
        stage,
        source: if is_censored {
            StageSelectionSource::DomainMatch
        } else {
            StageSelectionSource::Default
        },
    }
}

#[cfg(test)]
mod aggressive_fragment_tests {
    use super::*;
    use crate::config::EngineConfig;

    #[test]
    fn aggressive_fragment_suffix_match() {
        let mut cfg = EngineConfig::default();
        cfg.evasion.aggressive_fragment_domains = vec!["sndcdn.com".to_owned()];
        assert!(matches_aggressive_fragment("cdn1.sndcdn.com:443", &cfg));
        assert!(matches_aggressive_fragment("sndcdn.com:443", &cfg));
        assert!(!matches_aggressive_fragment("example.com:443", &cfg));
        // Substring without suffix must not match
        assert!(!matches_aggressive_fragment("notsndcdn.com:443", &cfg));
    }

    #[test]
    fn aggressive_fragment_empty_list_no_match() {
        let mut cfg = EngineConfig::default();
        cfg.evasion.aggressive_fragment_domains = vec![];
        assert!(!matches_aggressive_fragment("soundcloud.com:443", &cfg));
    }
}
