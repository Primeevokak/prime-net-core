async fn relay_bidirectional(
    client: &mut TcpStream,
    upstream: &mut BoxStream,
    relay_opts: RelayOptions,
) -> std::io::Result<(u64, u64)> {
    if relay_opts.tcp_window_trick {
        let _ = apply_tcp_window_size(client, 4096); // Increased from 512
    } else if relay_opts.tcp_window_size > 0 {
        let _ = apply_tcp_window_size(client, relay_opts.tcp_window_size);
    }

    if !relay_opts.fragment_client_hello {
        return tokio::io::copy_bidirectional(client, upstream).await;
    }

    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut upstream_r, mut upstream_w) = tokio::io::split(upstream);

    let upstream_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream_seen_c2u = upstream_seen.clone();

    let c2u_opts = relay_opts.clone();
    let c2u = async move {
        let mut total = 0u64;
        let mut budget = c2u_opts.fragment_budget_bytes;
        let started = tokio::time::Instant::now();
        let mut buf = [0u8; 16 * 1024];
        let mut maybe_tls = None;

        loop {
            let n = client_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;

            if maybe_tls.is_none() {
                let is_ch = is_tls_client_hello(&buf[..n]);
                if is_ch {
                    // Apply SNI-based evasion before any fragmentation
                    apply_sni_evasion(&mut buf[..n], &c2u_opts);
                }
                maybe_tls = Some(is_ch);
            }

            let current_buf = &buf[..n];

            let elapsed = started.elapsed();
            let responded = upstream_seen_c2u.load(Ordering::Relaxed);
            let use_fragmentation = maybe_tls.unwrap_or(false)
                && budget > 0
                && elapsed <= Duration::from_secs(3)
                && !responded;

            if use_fragmentation {
                let mut p = 0;
                let sni_info = if c2u_opts.split_at_sni { find_sni_info(current_buf) } else { None };

                if let Some((off, len)) = sni_info {
                    // Effective SNI split: Type (2) | Len (2) | Data (N)
                    // Minimal sleeps for maximum speed.
                    if off > 0 && off < n {
                        upstream_w.write_all(&current_buf[..off]).await?;
                        p = off;
                        sleep_with_jitter(Duration::from_millis(2)).await;
                    }
                    
                    let end = (off + len).min(n);
                    if len >= 4 && p + 4 <= n {
                        // 1. SNI Extension Type (2 bytes)
                        upstream_w.write_all(&current_buf[p..p+2]).await?;
                        p += 2;
                        sleep_with_jitter(Duration::from_millis(1)).await;
                        
                        // 2. SNI Extension Length (2 bytes)
                        upstream_w.write_all(&current_buf[p..p+2]).await?;
                        p += 2;
                        sleep_with_jitter(Duration::from_millis(1)).await;
                        
                        // 3. SNI Extension Data
                        upstream_w.write_all(&current_buf[p..end]).await?;
                        p = end;
                    } else if p < end {
                        upstream_w.write_all(&current_buf[p..end]).await?;
                        p = end;
                    }
                    
                    if p < n {
                        sleep_with_jitter(Duration::from_millis(1)).await;
                    }
                } else if !c2u_opts.client_hello_split_offsets.is_empty() {
                    // Respect explicit split offsets
                    let mut offsets = c2u_opts.client_hello_split_offsets.clone();
                    offsets.sort_unstable();
                    for offset in offsets {
                        if offset > p && offset < n {
                            upstream_w.write_all(&current_buf[p..offset]).await?;
                            p = offset;
                            sleep_with_jitter(Duration::from_millis(c2u_opts.fragment_sleep_ms.max(1))).await;
                        }
                    }
                }

                // Fragment the rest of the buffer safely
                while p < n {
                    let remaining = n - p;
                    let max_chunk = c2u_opts.fragment_size_max.min(remaining);
                    let min_chunk = c2u_opts.fragment_size_min.min(max_chunk).max(1);
                    
                    let chunk_size = if c2u_opts.randomize_fragment_size && max_chunk > min_chunk {
                        rand::thread_rng().gen_range(min_chunk..=max_chunk)
                    } else {
                        max_chunk
                    };

                    let end = p + chunk_size;
                    // Final safety check to prevent panic at all costs
                    let actual_end = end.min(n);
                    if p < actual_end {
                        upstream_w.write_all(&current_buf[p..actual_end]).await?;
                        p = actual_end;
                        
                        if p < n { 
                            let sleep_ms = c2u_opts.fragment_sleep_ms.max(2);
                            sleep_with_jitter(Duration::from_millis(sleep_ms)).await; 
                        }
                    } else {
                        break;
                    }
                }
                budget = budget.saturating_sub(n);
            } else {
                upstream_w.write_all(current_buf).await?;
            }
        }
        upstream_w.shutdown().await?;
        Ok::<u64, std::io::Error>(total)
    };

    let u2c = async move {
        let mut total = 0u64;
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = upstream_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            upstream_seen.store(true, Ordering::Relaxed);
            total += n as u64;
            client_w.write_all(&buf[..n]).await?;
        }
        client_w.shutdown().await?;
        Ok::<u64, std::io::Error>(total)
    };

    let (res_c2u, res_u2c) = tokio::join!(c2u, u2c);
    Ok((res_c2u?, res_u2c?))
}

fn apply_tcp_window_size(stream: &TcpStream, size: u32) -> std::io::Result<()> {
    use socket2::SockRef;
    let socket = SockRef::from(stream);
    let _ = socket.set_recv_buffer_size(size as usize);
    let _ = socket.set_send_buffer_size(size as usize);
    Ok(())
}

fn is_tls_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 5 && buf[0] == 0x16 && buf[1] == 0x03
}

fn find_sni_info(buf: &[u8]) -> Option<(usize, usize)> {
    if !is_tls_client_hello(buf) || buf.len() < 43 {
        return None;
    }
    let mut pos = 43;
    if pos >= buf.len() { return None; }
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > buf.len() { return None; }
    let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos+1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos >= buf.len() { return None; }
    let compression_methods_len = buf[pos] as usize;
    pos += 1 + compression_methods_len;
    if pos + 2 > buf.len() { return None; }
    let extensions_len = u16::from_be_bytes([buf[pos], buf[pos+1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;
    while pos + 4 <= buf.len() && pos < extensions_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos+1]]);
        let ext_len = u16::from_be_bytes([buf[pos+2], buf[pos+3]]) as usize;
        if ext_type == 0x0000 {
            return Some((pos, 4 + ext_len)); 
        }
        pos += 4 + ext_len;
    }
    None
}

fn apply_sni_evasion(buf: &mut [u8], opts: &RelayOptions) {
    if !opts.sni_case_toggle && !opts.sni_spoofing {
        return;
    }
    if let Some((off, _len)) = find_sni_info(buf) {
        // SNI Extension structure:
        // Type(2) | Len(2) | ListLen(2) | NameType(1) | NameLen(2) | Name(N)
        let name_len_pos = off + 7;
        if name_len_pos + 2 > buf.len() {
            return;
        }
        let name_len = u16::from_be_bytes([buf[name_len_pos], buf[name_len_pos + 1]]) as usize;
        let name_start = off + 9;
        let name_end = name_start + name_len;
        if name_end > buf.len() {
            return;
        }

        if opts.sni_case_toggle {
            for i in name_start..name_end {
                let c = buf[i];
                if c.is_ascii_alphabetic() {
                    // Toggle case of some characters. 
                    // This is generally safe as DNS names are case-insensitive.
                    if i % 2 == 0 {
                        buf[i] = if c.is_ascii_lowercase() {
                            c.to_ascii_uppercase()
                        } else {
                            c.to_ascii_lowercase()
                        };
                    }
                }
            }
        }
        
        if opts.sni_spoofing {
            // If spoofing is requested but we don't have a target domain, 
            // we can apply a different trick, like slightly modifying the SNI extension
            // in a way that remains valid but looks different to DPI.
            // For now, case-toggle already provides good evasion.
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_socks5_udp_associate(
    _conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    _client: String,
    request_addr: TargetAddr,
    request_port: u16,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    let bind = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let udp = UdpSocket::bind(bind).await?;
    let udp_bind = udp.local_addr()?;
    let reply = build_socks5_bind_reply(0x00, udp_bind);
    tcp.write_all(&reply).await?;

    let mut client_udp_addr = match request_addr {
        TargetAddr::Ip(ip) if request_port != 0 => Some(SocketAddr::new(ip, request_port)),
        _ => None,
    };

    let mut tcp_probe = [0u8; 1];
    let mut udp_buf = vec![0u8; 65535];
    let mut remote_to_key: HashMap<SocketAddr, String> = HashMap::new();
    let mut policies: HashMap<String, UdpDestinationPolicy> = HashMap::new();

    loop {
        tokio::select! {
            res = tcp.read(&mut tcp_probe) => {
                if let Ok(0) | Err(_) = res { break; }
            }
            res = udp.recv_from(&mut udp_buf) => {
                let Ok((n, src)) = res else { continue; };
                if is_client_udp_packet(src, peer, client_udp_addr) {
                    if client_udp_addr.is_none() { client_udp_addr = Some(src); }
                    let Some((target_addr, target_port, payload_offset)) = parse_socks5_udp_request(&udp_buf[..n]) else { continue; };
                    let mut payload = udp_buf[payload_offset..n].to_vec();
                    if let Some((min, max)) = relay_opts.udp_padding_range {
                        if n < 1200 {
                            let pad_len = rand::thread_rng().gen_range(min..=max);
                            payload.extend((0..pad_len).map(|_| rand::random::<u8>()));
                        }
                    }
                    let key = format_target(&target_addr, target_port);
                    let policy = policies.entry(key.clone()).or_default();
                    if now_unix_secs() < policy.disabled_until_unix {
                        continue;
                    }
                    
                    // QUIC Blocking: 
                    // Force fallback to TCP by dropping UDP 443 packets.
                    // This allows our TCP-based DPI bypass logic to work.
                    if target_port == 443 && relay_opts.block_quic {
                        continue;
                    }

                    let target = match resolve_udp_target_addr(&target_addr, target_port).await {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if policy.sent == 0 {
                        // Larger junk packet for better UDP evasion
                        let mut junk = vec![0u8; 128];
                        rand::thread_rng().fill(&mut junk[..]);
                        let _ = udp.send_to(&junk, target).await;
                    }
                    if udp.send_to(&payload, target).await.is_ok() {
                        policy.sent = policy.sent.saturating_add(1);
                        remote_to_key.insert(target, key.clone());
                    }
                } else if let Some(client_addr) = client_udp_addr {
                    if let Some(key) = remote_to_key.get(&src) {
                        let policy = policies.entry(key.clone()).or_default();
                        policy.recv = policy.recv.saturating_add(1);
                        policy.disabled_until_unix = 0;
                    }
                    let response = build_socks5_udp_response(src, &udp_buf[..n]);
                    let _ = udp.send_to(&response, client_addr).await;
                }
            }
        }
    }
    if !silent_drop { let _ = tcp.shutdown().await; }
    Ok(())
}

fn build_socks5_bind_reply(rep: u8, bind: SocketAddr) -> Vec<u8> {
    let mut out = vec![0x05, rep, 0x00];
    match bind {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out
}

fn build_socks5_udp_response(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00];
    match source {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

async fn read_socks_target_addr(tcp: &mut TcpStream, atyp: u8) -> Result<TargetAddr> {
    match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            tcp.read_exact(&mut b).await?;
            Ok(TargetAddr::Ip(std::net::IpAddr::V4(b.into())))
        }
        0x03 => {
            let mut lb = [0u8; 1];
            tcp.read_exact(&mut lb).await?;
            let mut b = vec![0u8; lb[0] as usize];
            tcp.read_exact(&mut b).await?;
            Ok(TargetAddr::Domain(String::from_utf8_lossy(&b).to_string()))
        }
        0x04 => {
            let mut b = [0u8; 16];
            tcp.read_exact(&mut b).await?;
            Ok(TargetAddr::Ip(std::net::IpAddr::V6(b.into())))
        }
        _ => Err(EngineError::InvalidInput("invalid atyp".to_owned())),
    }
}

async fn resolve_udp_target_addr(addr: &TargetAddr, port: u16) -> std::io::Result<SocketAddr> {
    match addr {
        TargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, port)),
        TargetAddr::Domain(host) => {
            let mut addrs = lookup_host((host.as_str(), port)).await?;
            addrs.next().ok_or_else(|| std::io::Error::other("resolve failed"))
        }
    }
}

fn is_client_udp_packet(src: SocketAddr, peer: SocketAddr, hint: Option<SocketAddr>) -> bool {
    src.ip() == peer.ip() && hint.is_none_or(|h| src.port() == h.port())
}

fn parse_socks5_udp_request(packet: &[u8]) -> Option<(TargetAddr, u16, usize)> {
    if packet.len() < 10 || packet[0..3] != [0,0,0] { return None; }
    let mut idx = 4;
    let addr = match packet[3] {
        0x01 => { let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(packet[idx], packet[idx+1], packet[idx+2], packet[idx+3])); idx += 4; TargetAddr::Ip(ip) }
        0x03 => { let len = packet[idx] as usize; idx += 1; let host = String::from_utf8_lossy(&packet[idx..idx+len]).to_string(); idx += len; TargetAddr::Domain(host) }
        0x04 => { let mut b = [0u8; 16]; b.copy_from_slice(&packet[idx..idx+16]); idx += 16; TargetAddr::Ip(std::net::IpAddr::V6(b.into())) }
        _ => return None,
    };
    let port = u16::from_be_bytes([packet[idx], packet[idx+1]]);
    Some((addr, port, idx + 2))
}

fn format_target(addr: &TargetAddr, port: u16) -> String {
    match addr {
        TargetAddr::Ip(ip) => format!("{ip}:{port}"),
        TargetAddr::Domain(host) => format!("{host}:{port}"),
    }
}

async fn resolve_client_label(peer: SocketAddr, listen: SocketAddr) -> String {
    use crate::platform::{resolve_process_id_by_connection, resolve_process_name_by_pid};
    if let Some(pid) = resolve_process_id_by_connection(peer, listen) {
        if let Some(name) = resolve_process_name_by_pid(pid) {
            return format!("{name} (pid {pid})");
        }
    }
    format!("unknown ({peer})")
}

fn is_expected_disconnect(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
    )
}

async fn sleep_with_jitter(base: Duration) {
    if base.is_zero() { return; }
    let ms = base.as_millis() as u64;
    let jitter = rand::thread_rng().gen_range(0..=(ms / 4).max(1));
    tokio::time::sleep(Duration::from_millis(ms + jitter)).await;
}

fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn split_host_port_for_connect(target: &str) -> Option<(String, u16)> {
    let t = target.trim();
    if t.is_empty() { return None; }
    if t.starts_with('[') {
        let end = t.find(']')?;
        let host = t[1..end].trim();
        if host.is_empty() { return None; }
        let rest = t.get(end + 1..)?;
        let port = rest.strip_prefix(':')?.trim().parse::<u16>().ok()?;
        return Some((host.to_owned(), port));
    }
    let (host, port) = t.rsplit_once(':')?;
    let host = host.trim();
    if host.is_empty() { return None; }
    let port = port.trim().parse::<u16>().ok()?;
    Some((host.to_owned(), port))
}

fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    let h = host.trim();
    if h.starts_with('[') && h.ends_with(']') {
        return h[1..h.len() - 1].parse().ok();
    }
    h.parse::<std::net::IpAddr>().ok()
}

struct HttpForwardTarget {
    host: String,
    port: u16,
    request_uri: String,
}

fn parse_http_forward_target(target: &str, request_head: &str) -> Option<HttpForwardTarget> {
    let target = target.trim();
    if let Ok(url) = url::Url::parse(target) {
        if !url.scheme().eq_ignore_ascii_case("http") { return None; }
        let raw_host = url.host_str()?.to_owned();
        let host = if raw_host.starts_with('[') && raw_host.ends_with(']') {
            raw_host[1..raw_host.len()-1].to_owned()
        } else {
            raw_host
        };
        let port = url.port_or_known_default().unwrap_or(80);
        let mut request_uri = url.path().to_owned();
        if let Some(q) = url.query() { request_uri.push('?'); request_uri.push_str(q); }
        return Some(HttpForwardTarget { host, port, request_uri });
    }
    if target.starts_with('/') {
        let host_header = extract_header_value(request_head, "Host")?;
        let (host, port) = split_host_port_with_default(&host_header, 80)?;
        return Some(HttpForwardTarget { host, port, request_uri: target.to_owned() });
    }
    None
}

fn rewrite_http_forward_head(method: &str, version: &str, uri: &str, head: &str, host: &str, port: u16) -> String {
    let mut out = format!("{method} {uri} {version}\r\n");
    for line in head.lines().skip(1) {
        if line.to_lowercase().starts_with("host:") { continue; }
        out.push_str(line); out.push_str("\r\n");
    }
    out.push_str(&format!("Host: {host}:{port}\r\n\r\n"));
    out
}

fn extract_header_value(head: &str, name: &str) -> Option<String> {
    for line in head.lines().skip(1) {
        if line.to_lowercase().starts_with(&format!("{}:", name.to_lowercase())) {
            return Some(line.split_once(':')?.1.trim().to_owned());
        }
    }
    None
}

async fn read_cstring(tcp: &mut TcpStream, limit: usize) -> Result<String> {
    let mut data = Vec::new();
    let mut b = [0u8; 1];
    loop {
        tcp.read_exact(&mut b).await?;
        if b[0] == 0 { break; }
        data.push(b[0]);
        if data.len() > limit { return Err(EngineError::InvalidInput("too long".to_owned())); }
    }
    Ok(String::from_utf8_lossy(&data).to_string())
}

fn split_host_port_with_default(target: &str, default_port: u16) -> Option<(String, u16)> {
    let t = target.trim();
    if t.is_empty() { return None; }
    if let Some((host, port)) = split_host_port_for_connect(t) {
        return Some((host, port));
    }
    if t.starts_with('[') && t.ends_with(']') {
        let host = t[1..t.len()-1].trim();
        if host.is_empty() { return None; }
        return Some((host.to_owned(), default_port));
    }
    if !t.contains(':') {
        return Some((t.to_owned(), default_port));
    }
    None
}

