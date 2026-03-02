use super::*;

pub async fn relay_bidirectional(
    client: &mut TcpStream,
    upstream: &mut BoxStream,
    relay_opts: RelayOptions,
    initial_client_to_upstream: Vec<u8>,
    initial_upstream_to_client: Vec<u8>,
    client_data_already_sent: bool,
) -> std::io::Result<(u64, u64)> {
    let initial_u2c_len = initial_upstream_to_client.len() as u64;
    let initial_c2u_len = if client_data_already_sent {
        0
    } else {
        initial_client_to_upstream.len() as u64
    };

    if !client_data_already_sent && !initial_client_to_upstream.is_empty() {
        warn!(target: "socks5.relay", bytes = initial_client_to_upstream.len(), "injecting initial client data into upstream");
        if relay_opts.fragment_client_hello && is_tls_client_hello(&initial_client_to_upstream) {
            let _ =
                fragment_and_send_tls_hello(&initial_client_to_upstream, upstream, &relay_opts)
                    .await?;
        } else {
            upstream.write_all(&initial_client_to_upstream).await?;
        }
        upstream.flush().await?;
    }
    if !initial_upstream_to_client.is_empty() {
        warn!(target: "socks5.relay", bytes = initial_upstream_to_client.len(), "injecting initial upstream data into client");
        client.write_all(&initial_upstream_to_client).await?;
        client.flush().await?;
    }

    let (c2u, u2c) = tokio::io::copy_bidirectional(client, upstream).await?;
    info!(target: "socks5.relay", c2u, u2c, "relay session finished");
    Ok((c2u + initial_c2u_len, u2c + initial_u2c_len))
}

pub async fn relay_bidirectional_with_first_byte_timeout(
    client: &mut TcpStream,
    upstream: &mut BoxStream,
    relay_opts: RelayOptions,
    initial_client_to_upstream: Vec<u8>,
    initial_upstream_to_client: Vec<u8>,
    client_data_already_sent: bool,
    timeout_duration: std::time::Duration,
) -> std::io::Result<(u64, u64)> {
    let initial_u2c_len = initial_upstream_to_client.len() as u64;
    let initial_c2u_len = if client_data_already_sent {
        0
    } else {
        initial_client_to_upstream.len() as u64
    };

    if !client_data_already_sent && !initial_client_to_upstream.is_empty() {
        info!(target: "socks5.relay", bytes = initial_client_to_upstream.len(), "injecting initial client data into upstream (timeout mode)");
        if relay_opts.fragment_client_hello && is_tls_client_hello(&initial_client_to_upstream) {
            let _ =
                fragment_and_send_tls_hello(&initial_client_to_upstream, upstream, &relay_opts)
                    .await?;
        } else {
            upstream.write_all(&initial_client_to_upstream).await?;
        }
        upstream.flush().await?;
    }
    if initial_u2c_len > 0 {
        info!(target: "socks5.relay", bytes = initial_u2c_len, "injecting initial upstream data into client (timeout mode)");
        client.write_all(&initial_upstream_to_client).await?;
        client.flush().await?;
    }

    if initial_u2c_len == 0 {
        let mut first_byte = [0u8; 1];
        match tokio::time::timeout(timeout_duration, upstream.read(&mut first_byte)).await {
            Ok(Ok(0)) => return Ok((initial_c2u_len, 0)),
            Ok(Ok(n)) => {
                info!(target: "socks5.relay", "first byte received from upstream");
                client.write_all(&first_byte[..n]).await?;
                client.flush().await?;
                let (c2u, u2c) = tokio::io::copy_bidirectional(client, upstream).await?;
                return Ok((c2u + initial_c2u_len, u2c + n as u64));
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "first byte timeout"));
            }
        }
    }

    let (c2u, u2c) = tokio::io::copy_bidirectional(client, upstream).await?;
    Ok((c2u + initial_c2u_len, u2c + initial_u2c_len))
}

pub(super) fn is_tls_client_hello(data: &[u8]) -> bool {
    data.len() >= 5 && data[0] == 0x16 && data[1] == 0x03 && (data[2] == 0x01 || data[2] == 0x03)
}

pub(super) async fn fragment_and_send_tls_hello(
    data: &[u8],
    upstream_w: &mut (impl AsyncWriteExt + Unpin),
    opts: &RelayOptions,
) -> std::io::Result<u64> {
    let mut sent = 0u64;
    let mut pos = 0usize;

    let first_size = if opts.randomize_fragment_size {
        rand::thread_rng().gen_range(opts.fragment_size_min..=opts.fragment_size_max)
    } else {
        opts.fragment_size_min
    }
    .min(data.len());

    upstream_w.write_all(&data[..first_size]).await?;
    sent += first_size as u64;
    pos += first_size;

    if opts.fragment_sleep_ms > 0 {
        tokio::time::sleep(Duration::from_millis(opts.fragment_sleep_ms)).await;
    }

    while pos < data.len() && pos < opts.fragment_budget_bytes {
        let remaining = data.len() - pos;
        let chunk_size = if opts.randomize_fragment_size {
            rand::thread_rng().gen_range(opts.fragment_size_min..=opts.fragment_size_max)
        } else {
            opts.fragment_size_max
        }
        .min(remaining);

        upstream_w.write_all(&data[pos..pos + chunk_size]).await?;
        sent += chunk_size as u64;
        pos += chunk_size;

        if opts.fragment_sleep_ms > 0 {
            tokio::time::sleep(Duration::from_millis(opts.fragment_sleep_ms)).await;
        }
    }

    if pos < data.len() {
        upstream_w.write_all(&data[pos..]).await?;
        sent += (data.len() - pos) as u64;
    }
    upstream_w.flush().await?;

    Ok(sent)
}

pub fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

pub fn split_host_port_for_connect(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse::<u16>().ok()?;
        if host.is_empty() {
            return None;
        }
        return Some((host.to_owned(), port));
    }

    let (host, port_str) = s.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    if host.is_empty() {
        return None;
    }

    // Best-effort support for unbracketed IPv6 literals in legacy configs/log-derived
    // keys: "2001:db8::1:443" -> ("2001:db8::1", 443).
    if host.contains(':') {
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Some((host.to_owned(), port));
        }
        return None;
    }

    Some((host.to_owned(), port))
}

pub fn split_host_port_with_default(s: &str, default_port: u16) -> Option<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    if s.starts_with('[') {
        if let Some(end_idx) = s.find(']') {
            let host = &s[1..end_idx];
            if host.is_empty() {
                return None;
            }
            let rest = &s[end_idx + 1..];
            if rest.is_empty() {
                return Some((host.to_owned(), default_port));
            }
            if let Some(port_str) = rest.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some((host.to_owned(), port));
                }
                return None; // Invalid port string after bracket
            }
        }
        return None;
    }

    if let Some(pos) = s.rfind(':') {
        let host = &s[..pos];
        let port_str = &s[pos + 1..];

        // Check if the part after colon is actually a port number
        if let Ok(port) = port_str.parse::<u16>() {
            if host.is_empty() {
                return None;
            }
            return Some((host.to_owned(), port));
        }

        // If there's a colon but the suffix isn't a numeric port,
        // it might be an unbracketed IPv6 or just garbage.
        // The tests expect None for "example.com:notaport"
        if host.contains('.') || host.is_empty() {
            return None;
        }
    }

    if s.is_empty() {
        None
    } else {
        Some((s.to_owned(), default_port))
    }
}

#[derive(Debug, Clone)]
pub struct HttpForwardTarget {
    pub host: String,
    pub port: u16,
    pub request_uri: String,
}

pub fn parse_http_forward_target(uri: &str, headers: &str) -> Option<HttpForwardTarget> {
    if let Some(rest) = uri.strip_prefix("http://") {
        let (host_port, path) = if let Some(slash_pos) = rest.find('/') {
            (&rest[..slash_pos], &rest[slash_pos..])
        } else {
            (rest, "/")
        };
        let (host, port) = split_host_port_with_default(host_port, 80)?;
        return Some(HttpForwardTarget {
            host,
            port,
            request_uri: path.to_owned(),
        });
    }

    let mut found_host = None;
    for line in headers.lines() {
        if line.to_ascii_lowercase().starts_with("host:") {
            let host_val = line[5..].trim();
            found_host = split_host_port_with_default(host_val, 80);
            break;
        }
    }

    if let Some((host, port)) = found_host {
        // Validation: if URI is just a path, we must have found a host header
        return Some(HttpForwardTarget {
            host,
            port,
            request_uri: uri.to_owned(),
        });
    }

    None
}

#[derive(Debug, Clone, Copy)]
pub struct HttpRequestLine<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub version: &'a str,
}

pub fn parse_http_request_line(line: &str) -> Option<HttpRequestLine<'_>> {
    let line = line.trim_matches(|c| c == '\r' || c == '\n');
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if method.is_empty()
        || target.is_empty()
        || !method.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-')
        || !version.starts_with("HTTP/")
        || target.as_bytes().contains(&0)
    {
        return None;
    }
    Some(HttpRequestLine {
        method,
        target,
        version,
    })
}

pub fn rewrite_http_forward_head(headers: &str, target: &HttpForwardTarget) -> String {
    let mut lines: Vec<String> = Vec::new();
    let first_line = headers.lines().next().unwrap_or("");
    if let Some(parsed) = parse_http_request_line(first_line) {
        lines.push(format!(
            "{} {} {}",
            parsed.method, target.request_uri, parsed.version
        ));
    } else {
        lines.push(first_line.to_owned());
    }

    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:")
            || lower.starts_with("proxy-connection:")
            || lower.starts_with("connection: close")
        {
            continue;
        }
        lines.push(line.to_owned());
    }
    let host_value = if target.port == 80 {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    lines.push(format!("Host: {host_value}"));
    lines.push("Connection: close".to_owned());
    lines.push("".to_owned());
    lines.push("".to_owned());
    lines.join("\r\n")
}

pub fn route_capability_slot_mut(
    caps: &mut RouteCapabilities,
    kind: RouteKind,
    family: RouteIpFamily,
) -> Option<&mut u64> {
    match (kind, family) {
        (RouteKind::Direct, RouteIpFamily::V4) => Some(&mut caps.direct_v4_weak_until_unix),
        (RouteKind::Direct, RouteIpFamily::V6) => Some(&mut caps.direct_v6_weak_until_unix),
        (RouteKind::Bypass, RouteIpFamily::V4) => Some(&mut caps.bypass_v4_weak_until_unix),
        (RouteKind::Bypass, RouteIpFamily::V6) => Some(&mut caps.bypass_v6_weak_until_unix),
        (_, RouteIpFamily::Any) => None,
    }
}

pub fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse().ok()
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn format_target(addr: &TargetAddr, port: u16) -> String {
    format!("{addr}:{port}")
}

pub async fn read_cstring(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    max_len: usize,
) -> std::io::Result<String> {
    let mut buf = Vec::new();
    for _ in 0..max_len {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b).await?;
        if b[0] == 0 {
            break;
        }
        buf.push(b[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub fn should_skip_empty_session_scoring(c2u: u64, u2c: u64) -> bool {
    c2u == 0 && u2c == 0
}

pub fn should_mark_empty_bypass_session_as_soft_failure(
    candidate: &RouteCandidate,
    port: u16,
) -> bool {
    if port != 443 || candidate.kind != RouteKind::Bypass {
        return false;
    }
    matches!(
        candidate.source,
        "builtin" | "learned-domain" | "learned-ip"
    )
}

pub fn should_mark_bypass_profile_failure(port: u16, c2u: u64, u2c: u64, min_c2u: u64) -> bool {
    port == 443 && u2c <= 7 && c2u >= min_c2u
}

pub fn should_mark_bypass_zero_reply_soft(port: u16, c2u: u64, u2c: u64, lifetime: u64) -> bool {
    port == 443 && u2c <= 7 && c2u >= 256 && lifetime >= 2000
}

const SOFT_ZERO_REPLY_DISCONNECT_MIN_LIFETIME_MS: u64 = 3_000;

pub fn should_penalize_disconnect_as_soft_zero_reply(
    route_key: &str,
    candidate: &RouteCandidate,
    lifetime_ms: u64,
    cfg: &EngineConfig,
) -> bool {
    if candidate.kind != RouteKind::Bypass {
        return false;
    }
    if lifetime_ms < SOFT_ZERO_REPLY_DISCONNECT_MIN_LIFETIME_MS {
        return false;
    }
    matches!(
        host_service_bucket(
            crate::pt::socks5_server::route_connection::route_destination_key(route_key),
            cfg
        )
        .as_str(),
        "meta-group:youtube" | "meta-group:discord" | "meta-group:google"
    )
}

pub fn record_bypass_profile_success(destination: &str, idx: u8, cfg: &EngineConfig) {
    let key = bypass_profile_key(destination, cfg);
    let service_key = bypass_profile_legacy_service_key(destination, cfg);
    let meta_key = bypass_profile_meta_service_key(destination, cfg);
    if let Some(map) = DEST_BYPASS_PROFILE_IDX.get() {
        if let Some(mut entry) = map.get_mut(&key) {
            *entry = idx;
        }
        if service_key != key {
            if let Some(mut entry) = map.get_mut(&service_key) {
                *entry = idx;
            }
        }
        if let Some(meta_key) = meta_key.as_ref() {
            if meta_key != &key && meta_key != &service_key {
                if let Some(mut entry) = map.get_mut(meta_key) {
                    *entry = idx;
                }
            }
        }
    }
    if let Some(map) = DEST_BYPASS_PROFILE_FAILURES.get() {
        if let Some(mut entry) = map.get_mut(&key) {
            *entry = entry.saturating_sub(1);
        }
        if service_key != key {
            if let Some(mut entry) = map.get_mut(&service_key) {
                *entry = entry.saturating_sub(1);
            }
        }
        if let Some(meta_key) = meta_key.as_ref() {
            if meta_key != &key && meta_key != &service_key {
                if let Some(mut entry) = map.get_mut(meta_key) {
                    *entry = entry.saturating_sub(1);
                }
            }
        }
    }
}

pub fn should_mark_route_soft_zero_reply(port: u16, c2u: u64, u2c: u64) -> bool {
    port == 443 && u2c <= 7 && c2u >= 256
}
