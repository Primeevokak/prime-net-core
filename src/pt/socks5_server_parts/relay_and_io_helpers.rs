use super::*;

pub async fn relay_bidirectional(
    client: &mut TcpStream,
    upstream: &mut BoxStream,
    relay_opts: RelayOptions,
) -> std::io::Result<(u64, u64)> {
    if relay_opts.tcp_window_trick {
        let _ = apply_tcp_window_size(client, relay_opts.tcp_window_size.into());
    }

    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut upstream_r, mut upstream_w) = tokio::io::split(upstream);

    let upstream_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream_seen_c2u = upstream_seen.clone();

    let c2u = async {
        let mut total = 0u64;
        if relay_opts.fragment_client_hello {
            let mut first_buf = vec![0u8; relay_opts.fragment_budget_bytes.max(1024)];
            let n = client_r.read(&mut first_buf).await?;
            if n > 0 {
                let data = &first_buf[..n];
                if is_tls_client_hello(data) {
                    total += fragment_and_send_tls_hello(data, &mut upstream_w, &relay_opts).await?;
                } else {
                    upstream_w.write_all(data).await?;
                    total += n as u64;
                }
                upstream_seen_c2u.store(true, Ordering::SeqCst);
            }
        }
        
        let mut buf = vec![0u8; 16384];
        loop {
            let n = client_r.read(&mut buf).await?;
            if n == 0 { break; }
            upstream_w.write_all(&buf[..n]).await?;
            total += n as u64;
            upstream_seen_c2u.store(true, Ordering::SeqCst);
        }
        Ok::<u64, std::io::Error>(total)
    };

    let u2c = async {
        let mut total = 0u64;
        let mut buf = vec![0u8; 16384];
        loop {
            let n = upstream_r.read(&mut buf).await?;
            if n == 0 { break; }
            client_w.write_all(&buf[..n]).await?;
            total += n as u64;
        }
        Ok::<u64, std::io::Error>(total)
    };

    tokio::try_join!(c2u, u2c)
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
    }.min(data.len());

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
        }.min(remaining);

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

    Ok(sent)
}

pub fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i+1] == b'\n' && buf[i+2] == b'\r' && buf[i+3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

pub fn split_host_port_for_connect(s: &str) -> Option<(String, u16)> {
    if let Some(pos) = s.rfind(':') {
        let host = &s[..pos];
        let port_str = &s[pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            let host_clean = host.trim_start_matches('[').trim_end_matches(']');
            if host_clean.is_empty() { return None; }
            return Some((host_clean.to_owned(), port));
        }
    }
    None
}

pub fn split_host_port_with_default(s: &str, default_port: u16) -> Option<(String, u16)> {
    let s = s.trim();
    if s.is_empty() { return None; }
    
    if s.starts_with('[') {
        if let Some(end_idx) = s.find(']') {
            let host = &s[1..end_idx];
            if host.is_empty() { return None; }
            let rest = &s[end_idx+1..];
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
            if host.is_empty() { return None; }
            return Some((host.to_owned(), port));
        }
        
        // If there's a colon but the suffix isn't a numeric port, 
        // it might be an unbracketed IPv6 or just garbage.
        // The tests expect None for "example.com:notaport"
        if host.contains('.') || host.is_empty() {
            return None; 
        }
    }
    
    if s.is_empty() { None } else { Some((s.to_owned(), default_port)) }
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
        return Some(HttpForwardTarget { host, port, request_uri: path.to_owned() });
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
        return Some(HttpForwardTarget { host, port, request_uri: uri.to_owned() });
    }

    None
}

pub fn rewrite_http_forward_head(headers: &str, target: &HttpForwardTarget) -> String {
    let mut lines: Vec<String> = Vec::new();
    let first_line = headers.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 3 {
        lines.push(format!("{} {} {}", parts[0], target.request_uri, parts[2]));
    } else {
        lines.push(first_line.to_owned());
    }

    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") || lower.starts_with("proxy-connection:") || lower.starts_with("connection: close") {
            continue;
        }
        lines.push(line.to_owned());
    }
    lines.push(format!("Host: {}", target.host));
    lines.push("Connection: close".to_owned());
    lines.push("".to_owned());
    lines.push("".to_owned());
    lines.join("\r\n")
}

pub fn is_expected_disconnect(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted)
}

pub(super) fn apply_tcp_window_size(stream: &TcpStream, size: u32) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        let socket = stream.as_raw_socket();
        unsafe {
            let res = windows_sys::Win32::Networking::WinSock::setsockopt(
                socket as _,
                windows_sys::Win32::Networking::WinSock::SOL_SOCKET as _,
                windows_sys::Win32::Networking::WinSock::SO_RCVBUF as _,
                &size as *const _ as *const _,
                std::mem::size_of::<u32>() as _,
            );
            if res == -1 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    let _ = stream;
    let _ = size;
    Ok(())
}

pub async fn handle_socks5_udp_associate(
    _conn_id: u64,
    _client_tcp: &mut TcpStream,
    _listen_addr: SocketAddr,
    _relay_opts: RelayOptions,
) -> Result<()> {
    Err(EngineError::Internal("UDP Associate not fully implemented in this module".to_owned()))
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

pub fn should_mark_empty_bypass_session_as_soft_failure(candidate: &RouteCandidate, port: u16) -> bool {
    if port != 443 || candidate.kind != RouteKind::Bypass {
        return false;
    }
    matches!(candidate.source, "builtin" | "learned-domain" | "learned-ip")
}

pub fn should_mark_bypass_profile_failure(port: u16, c2u: u64, u2c: u64, min_c2u: u64) -> bool {
    port == 443 && u2c == 0 && c2u >= min_c2u
}

pub fn should_mark_bypass_zero_reply_soft(port: u16, c2u: u64, u2c: u64, lifetime: u64) -> bool {
    port == 443 && u2c == 0 && c2u >= 256 && lifetime >= 2000
}

pub fn record_bypass_profile_success(destination: &str, idx: u8) {
    let key = bypass_profile_key(destination);
    let service_key = bypass_profile_legacy_service_key(destination);
    let meta_key = bypass_profile_meta_service_key(destination);
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
    port == 443 && u2c == 0 && c2u >= 256
}
