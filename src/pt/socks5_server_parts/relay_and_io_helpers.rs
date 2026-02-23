async fn relay_bidirectional(
    client: &mut TcpStream,
    upstream: &mut BoxStream,
    relay_opts: RelayOptions,
) -> std::io::Result<(u64, u64)> {
    if relay_opts.tcp_window_trick {
        // TCP Zero-Window Trick: Start with a tiny window to confuse DPI.
        // 64 bytes is a safe minimum for Windows to avoid os error 10022.
        let _ = apply_tcp_window_size(client, 64);
    } else if relay_opts.tcp_window_size > 0 {
        let _ = apply_tcp_window_size(client, relay_opts.tcp_window_size);
    }

    if !relay_opts.fragment_client_hello {
        return tokio::io::copy_bidirectional(client, upstream).await;
    }

    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut upstream_r, upstream_w) = tokio::io::split(upstream);

    let upstream_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream_seen_c2u = upstream_seen.clone();

    // Auto-MTU: If we are in aggressive stage, cap write sizes early to avoid PMTU issues.
    let is_aggressive = relay_opts.fragment_size_max <= 8;

    let c2u = async move {
        let mut total = 0u64;
        let mut budget = relay_opts.fragment_budget_bytes;
        let started = tokio::time::Instant::now();
        let mut buf = [0u8; 16 * 1024];
        let mut maybe_tls = None;
        let mut client_hello_sent = false;

        let fragment_cfg = FragmentConfig {
            first_write_max: 64, // Keep first write small for DPI bypass
            first_write_plan: if relay_opts.client_hello_split_offsets.is_empty() {
                None
            } else {
                Some(offsets_to_plan(&relay_opts.client_hello_split_offsets))
            },
            fragment_size_min: relay_opts.fragment_size_min.max(1),
            fragment_size_max: relay_opts.fragment_size_max.max(1),
            sleep_ms: relay_opts.fragment_sleep_ms,
            jitter_ms: if relay_opts.randomize_fragment_size && relay_opts.fragment_sleep_ms == 0 {
                Some((0, 3))
            } else {
                None
            },
            randomize_fragment_size: relay_opts.randomize_fragment_size,
            split_at_sni: relay_opts.split_at_sni,
        };
        let (mut frag_upstream_w, frag_handle) =
            FragmentingIo::new(upstream_w, fragment_cfg.clone());

        loop {
            let n = client_r.read(&mut buf).await?;
            if n == 0 {
                frag_upstream_w.shutdown().await?;
                break;
            }
            total += n as u64;

            if maybe_tls.is_none() {
                let is_ch = is_tls_client_hello(&buf[..n]);
                maybe_tls = Some(is_ch);
                if is_ch {
                    client_hello_sent = true;
                    // Inject fake SNI only if explicitly enabled (can break some services)
                    if relay_opts.sni_spoofing {
                        let _ = send_fake_sni_probe(&mut frag_upstream_w, 2).await;
                    }
                } else {
                    frag_handle.disable();
                }
            }

            // Фрагментируем только в раннем окне handshake или до первых байтов от upstream.
            let elapsed = started.elapsed();
            let within_handshake_window = elapsed <= Duration::from_secs(3);
            let upstream_has_responded = upstream_seen_c2u.load(Ordering::Relaxed);

            // Passive Fingerprinting: Detect silent drops.
            // If ClientHello was sent but no response within 3s window, abort with specific error.
            if client_hello_sent && !upstream_has_responded && elapsed > Duration::from_secs(3) {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "silent drop detected (no response to ClientHello)"));
            }

            let use_fragmentation = maybe_tls.unwrap_or(false)
                && budget > 0
                && within_handshake_window
                && !upstream_has_responded;

            if use_fragmentation {
                let to_fragment = n.min(budget);
                frag_upstream_w.write_all(&buf[..to_fragment]).await?;
                if to_fragment < n {
                    frag_handle.disable();
                    frag_upstream_w.write_all(&buf[to_fragment..n]).await?;
                }
                budget -= to_fragment;
                if budget == 0 {
                    frag_handle.disable();
                }
            } else {
                frag_handle.disable();
                // Auto-MTU hint: use smaller writes if we suspect MTU issues.
                if is_aggressive && n > 1300 {
                     let mut p = 0;
                     while p < n {
                         let chunk = (n - p).min(1200);
                         frag_upstream_w.write_all(&buf[p..p+chunk]).await?;
                         p += chunk;
                     }
                } else {
                    frag_upstream_w.write_all(&buf[..n]).await?;
                }
            }
        }
        Ok::<u64, std::io::Error>(total)
    };

    let u2c = async {
        let mut total = 0u64;
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = upstream_r.read(&mut buf).await?;
            if n == 0 {
                client_w.shutdown().await?;
                break;
            }
            upstream_seen.store(true, Ordering::Relaxed);
            total += n as u64;
            client_w.write_all(&buf[..n]).await?;
        }
        Ok::<u64, std::io::Error>(total)
    };

    let (bytes_client_to_upstream, bytes_upstream_to_client) = tokio::try_join!(c2u, u2c)?;
    Ok((bytes_client_to_upstream, bytes_upstream_to_client))
}

fn apply_tcp_window_size(stream: &TcpStream, size: u32) -> std::io::Result<()> {
    use socket2::SockRef;
    let socket = SockRef::from(stream);
    let _ = socket.set_recv_buffer_size(size as usize);
    let _ = socket.set_send_buffer_size(size as usize);
    Ok(())
}

fn offsets_to_plan(offsets: &[usize]) -> Vec<usize> {
    offsets
        .iter()
        .copied()
        .scan(0usize, |prev, off| {
            if off > *prev {
                let out = off - *prev;
                *prev = off;
                Some(Some(out))
            } else {
                Some(None)
            }
        })
        .flatten()
        .collect()
}

fn is_tls_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 3 && buf[0] == 0x16 && buf[1] == 0x03
}

async fn send_fake_sni_probe<W>(upstream: &mut W, _ttl: u8) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use crate::anticensorship::tls_randomizer::generate_fake_client_hello;

    let fake_ch = generate_fake_client_hello();
    let _ = upstream.write_all(&fake_ch).await;
    let _ = upstream.flush().await;
    tokio::time::sleep(Duration::from_millis(15)).await;
    Ok(())
}


async fn read_cstring(tcp: &mut TcpStream, limit: usize) -> Result<String> {
    let mut data = Vec::new();
    let mut b = [0u8; 1];
    loop {
        tcp.read_exact(&mut b).await?;
        if b[0] == 0 {
            break;
        }
        data.push(b[0]);
        if data.len() > limit {
            return Err(EngineError::InvalidInput(
                "SOCKS string too long".to_owned(),
            ));
        }
    }
    String::from_utf8(data)
        .map_err(|_| EngineError::InvalidInput("SOCKS string is not UTF-8".to_owned()))
}

async fn read_socks_target_addr(tcp: &mut TcpStream, atyp: u8) -> Result<TargetAddr> {
    match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            tcp.read_exact(&mut b).await?;
            Ok(TargetAddr::Ip(std::net::IpAddr::V4(
                std::net::Ipv4Addr::from(b),
            )))
        }
        0x03 => {
            let mut lb = [0u8; 1];
            tcp.read_exact(&mut lb).await?;
            let len = lb[0] as usize;
            let mut b = vec![0u8; len];
            tcp.read_exact(&mut b).await?;
            let s = String::from_utf8(b).map_err(|_| {
                EngineError::InvalidInput("SOCKS5 domain is not valid UTF-8".to_owned())
            })?;
            Ok(TargetAddr::Domain(s))
        }
        0x04 => {
            let mut b = [0u8; 16];
            tcp.read_exact(&mut b).await?;
            Ok(TargetAddr::Ip(std::net::IpAddr::V6(
                std::net::Ipv6Addr::from(b),
            )))
        }
        other => Err(EngineError::InvalidInput(format!(
            "SOCKS5 invalid ATYP 0x{other:02x}"
        ))),
    }
}

async fn handle_socks5_udp_associate(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    client: String,
    request_addr: TargetAddr,
    request_port: u16,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let udp = UdpSocket::bind(bind).await?;
    let udp_bind = udp.local_addr()?;
    let reply = build_socks5_bind_reply(0x00, udp_bind);
    tcp.write_all(&reply).await?;

    let mut client_udp_addr = match request_addr {
        TargetAddr::Ip(ip) if request_port != 0 => Some(SocketAddr::new(ip, request_port)),
        _ => None,
    };
    info!(
        target: "socks5",
        conn_id,
        peer = %peer,
        client = %client,
        udp_bind = %udp_bind,
        client_udp_hint = ?client_udp_addr,
        "SOCKS5 UDP relay active"
    );

    let mut tcp_probe = [0u8; 1];
    let mut udp_buf = vec![0u8; 65535];
    let mut remote_to_key: HashMap<SocketAddr, String> = HashMap::new();
    let mut policies: HashMap<String, UdpDestinationPolicy> = HashMap::new();

    loop {
        tokio::select! {
            res = tcp.read(&mut tcp_probe) => {
                match res {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            res = udp.recv_from(&mut udp_buf) => {
                let Ok((n, src)) = res else { continue; };
                if is_client_udp_packet(src, peer, client_udp_addr) {
                    if client_udp_addr.is_none() {
                        client_udp_addr = Some(src);
                    }
                    let Some((target_addr, target_port, payload_offset)) = parse_socks5_udp_request(&udp_buf[..n]) else {
                        continue;
                    };
                    let mut payload = udp_buf[payload_offset..n].to_vec();

                    // Add noise padding for QUIC/UDP to bypass protocol analysis.
                    if let Some((min, max)) = relay_opts.udp_padding_range {
                        if n < 1200 { // Only pad small control/handshake packets
                            let pad_len = rand::thread_rng().gen_range(min..=max);
                            payload.extend((0..pad_len).map(|_| rand::random::<u8>()));
                        }
                    }

                    let key = format_target(&target_addr, target_port);
                    let now = now_unix_secs();
                    let policy = policies.entry(key.clone()).or_default();
                    if now < policy.disabled_until_unix {
                        continue;
                    }
                    let target = match resolve_udp_target_addr(&target_addr, target_port).await {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(target: "socks5.udp", conn_id, destination = %key, error = %e, "UDP target resolve failed");
                            continue;
                        }
                    };

                    // UDP Desync: Send a small garbage packet before the first real packet to confuse DPI.
                    // Only apply to port 443 (QUIC) to avoid breaking sensitive protocols like Discord Voice or Games.
                    if policy.sent == 0 && target_port == 443 {
                        let junk: [u8; 8] = rand::random();
                        let _ = udp.send_to(&junk, target).await;
                    }

                    if udp.send_to(&payload, target).await.is_ok() {
                        policy.sent = policy.sent.saturating_add(1);
                        remote_to_key.insert(target, key.clone());
                        if policy.sent >= UDP_POLICY_DISABLE_THRESHOLD && policy.recv == 0 {
                            policy.disabled_until_unix = now.saturating_add(UDP_POLICY_DISABLE_SECS);
                            warn!(
                                target: "socks5.udp",
                                conn_id,
                                destination = %key,
                                disable_secs = UDP_POLICY_DISABLE_SECS,
                                "UDP policy: no replies detected, temporarily disabling UDP to accelerate TCP fallback"
                            );
                        }
                    }
                    continue;
                }

                let Some(client_addr) = client_udp_addr else { continue; };
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

    if !silent_drop {
        let _ = tcp.shutdown().await;
    }
    info!(target: "socks5", conn_id, peer = %peer, client = %client, "SOCKS5 UDP ASSOCIATE closed");
    Ok(())
}

fn is_client_udp_packet(
    src: SocketAddr,
    peer: SocketAddr,
    client_udp_addr: Option<SocketAddr>,
) -> bool {
    if src.ip() != peer.ip() {
        return false;
    }
    if let Some(addr) = client_udp_addr {
        return src.port() == addr.port();
    }
    true
}

fn parse_socks5_udp_request(packet: &[u8]) -> Option<(TargetAddr, u16, usize)> {
    if packet.len() < 10 {
        return None;
    }
    if packet[0] != 0 || packet[1] != 0 {
        return None;
    }
    // В этом реле фрагментация не поддерживается.
    if packet[2] != 0 {
        return None;
    }
    let atyp = packet[3];
    let mut idx = 4usize;
    let addr = match atyp {
        0x01 => {
            if idx + 4 > packet.len() {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(
                packet[idx],
                packet[idx + 1],
                packet[idx + 2],
                packet[idx + 3],
            );
            idx += 4;
            TargetAddr::Ip(std::net::IpAddr::V4(ip))
        }
        0x03 => {
            if idx + 1 > packet.len() {
                return None;
            }
            let len = packet[idx] as usize;
            idx += 1;
            if idx + len > packet.len() {
                return None;
            }
            let host = std::str::from_utf8(&packet[idx..idx + len])
                .ok()?
                .to_owned();
            idx += len;
            TargetAddr::Domain(host)
        }
        0x04 => {
            if idx + 16 > packet.len() {
                return None;
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&packet[idx..idx + 16]);
            idx += 16;
            TargetAddr::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)))
        }
        _ => return None,
    };
    if idx + 2 > packet.len() {
        return None;
    }
    let port = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
    idx += 2;
    Some((addr, port, idx))
}

async fn resolve_udp_target_addr(addr: &TargetAddr, port: u16) -> std::io::Result<SocketAddr> {
    match addr {
        TargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, port)),
        TargetAddr::Domain(host) => {
            let mut addrs = lookup_host((host.as_str(), port)).await?;
            addrs
                .next()
                .ok_or_else(|| std::io::Error::other("UDP resolve produced no addresses"))
        }
    }
}

fn build_socks5_bind_reply(rep: u8, bind: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.push(0x05);
    out.push(rep);
    out.push(0x00);
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
    let mut out = Vec::with_capacity(payload.len() + 22);
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
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

fn split_host_port_for_connect(target: &str) -> Option<(String, u16)> {
    let t = target.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with('[') {
        let end = t.find(']')?;
        let host = t[1..end].trim();
        if host.is_empty() {
            return None;
        }
        let rest = t.get(end + 1..)?.trim();
        let port = rest.strip_prefix(':')?.trim().parse::<u16>().ok()?;
        return Some((host.to_owned(), port));
    }
    let (host, port) = t.rsplit_once(':')?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let port = port.trim().parse::<u16>().ok()?;
    Some((host.to_owned(), port))
}

fn normalize_host_literal(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = trimmed[1..trimmed.len() - 1].trim();
        if !inner.is_empty() {
            return inner.to_owned();
        }
    }
    trimmed.to_owned()
}

fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    let normalized = normalize_host_literal(host);
    normalized.parse::<std::net::IpAddr>().ok()
}

#[derive(Debug)]
struct HttpForwardTarget {
    host: String,
    port: u16,
    request_uri: String,
}

fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn parse_http_forward_target(target: &str, request_head: &str) -> Option<HttpForwardTarget> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }

    if let Ok(url) = url::Url::parse(target) {
        if !url.scheme().eq_ignore_ascii_case("http") {
            return None;
        }
        let host = normalize_host_literal(url.host_str()?);
        let port = url.port_or_known_default().unwrap_or(80);
        let mut request_uri = url.path().to_owned();
        if request_uri.is_empty() {
            request_uri = "/".to_owned();
        }
        if let Some(q) = url.query() {
            request_uri.push('?');
            request_uri.push_str(q);
        }
        return Some(HttpForwardTarget {
            host,
            port,
            request_uri,
        });
    }

    if target.starts_with('/') || target == "*" {
        let host_header = extract_header_value(request_head, "Host")?;
        let (host, port) = split_host_port_with_default(&host_header, 80)?;
        return Some(HttpForwardTarget {
            host: normalize_host_literal(&host),
            port,
            request_uri: target.to_owned(),
        });
    }

    None
}

fn rewrite_http_forward_head(
    method: &str,
    version: &str,
    request_uri: &str,
    request_head: &str,
    host: &str,
    port: u16,
) -> String {
    let mut out = String::new();
    out.push_str(method);
    out.push(' ');
    out.push_str(request_uri);
    out.push(' ');
    out.push_str(version);
    out.push_str("\r\n");

    let mut saw_host = false;
    for line in request_head.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name_trimmed = name.trim();
        if name_trimmed.eq_ignore_ascii_case("Proxy-Connection") {
            continue;
        }
        if name_trimmed.eq_ignore_ascii_case("Host") {
            saw_host = true;
            out.push_str("Host: ");
            out.push_str(&format_host_header(host, port));
            out.push_str("\r\n");
            continue;
        }
        out.push_str(name_trimmed);
        out.push(':');
        out.push_str(value);
        out.push_str("\r\n");
    }
    if !saw_host {
        out.push_str("Host: ");
        out.push_str(&format_host_header(host, port));
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

fn extract_header_value(request_head: &str, header_name: &str) -> Option<String> {
    for line in request_head.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(header_name) {
            return Some(value.trim().to_owned());
        }
    }
    None
}

fn split_host_port_with_default(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = authority[1..end].trim().to_owned();
        if host.is_empty() {
            return None;
        }
        let rest = authority.get(end + 1..).unwrap_or_default().trim();
        if rest.is_empty() {
            return Some((host, default_port));
        }
        let port = rest.strip_prefix(':')?.trim().parse::<u16>().ok()?;
        return Some((host, port));
    }

    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let host = host.trim();
        if host.is_empty() {
            return None;
        }
        if !host.contains(':') {
            let port = port_str.trim().parse::<u16>().ok()?;
            return Some((host.to_owned(), port));
        }
        return None;
    }

    Some((authority.to_owned(), default_port))
}

fn format_host_header(host: &str, port: u16) -> String {
    let host_rendered = if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == 80 {
        host_rendered
    } else {
        format!("{host_rendered}:{port}")
    }
}

fn format_target(addr: &TargetAddr, port: u16) -> String {
    match addr {
        TargetAddr::Ip(ip) => format!("{ip}:{port}"),
        TargetAddr::Domain(host) => format!("{host}:{port}"),
    }
}

fn is_expected_disconnect(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
    )
}

async fn resolve_client_label(peer: SocketAddr, listen_addr: SocketAddr) -> String {
    use crate::platform::{resolve_process_id_by_connection, resolve_process_name_by_pid};

    if let Some(pid) = resolve_process_id_by_connection(peer, listen_addr) {
        if let Some(name) = resolve_process_name_by_pid(pid) {
            return format!("{name} (pid {pid})");
        }
        return format!("pid {pid} ({peer})");
    }
    format!("unknown-app ({peer})")
}


