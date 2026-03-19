#[cfg(feature = "websocket")]
async fn read_frame(
    rd: &mut tokio::io::ReadHalf<DynStream>,
    max_message_size: usize,
) -> Result<Frame> {
    use tokio::io::AsyncReadExt;

    let mut h = [0u8; 2];
    rd.read_exact(&mut h)
        .await
        .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
    let fin = (h[0] & 0x80) != 0;
    let rsv1 = (h[0] & 0x40) != 0;
    let rsv2 = (h[0] & 0x20) != 0;
    let rsv3 = (h[0] & 0x10) != 0;

    if rsv2 || rsv3 {
        return Err(EngineError::Internal(
            "reserved bits (RSV2/RSV3) set in websocket frame without negotiation".to_owned(),
        ));
    }

    let opcode = OpCode::from_u8(h[0] & 0x0f)
        .ok_or_else(|| EngineError::Internal("unknown websocket opcode".to_owned()))?;

    let masked = (h[1] & 0x80) != 0;
    let mut len = (h[1] & 0x7f) as u64;

    if opcode.is_control() {
        if !fin {
            return Err(EngineError::Internal(
                "fragmented websocket control frame (fin=0)".to_owned(),
            ));
        }
        if rsv1 {
            return Err(EngineError::Internal(
                "RSV1 bit set on websocket control frame".to_owned(),
            ));
        }
        if len > 125 {
            return Err(EngineError::Internal(
                "websocket control frame too large (>125 bytes)".to_owned(),
            ));
        }
    }

    if len == 126 {
        let mut b = [0u8; 2];
        rd.read_exact(&mut b)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
        len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8];
        rd.read_exact(&mut b)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
        len = u64::from_be_bytes(b);
    }

    if len as usize > max_message_size {
        return Err(EngineError::Internal(
            "websocket frame too large".to_owned(),
        ));
    }

    let mask = if masked {
        let mut m = [0u8; 4];
        rd.read_exact(&mut m)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
        Some(m)
    } else {
        None
    };

    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        rd.read_exact(&mut payload)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
    }

    if let Some(mask) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }

    Ok(Frame {
        fin,
        rsv1,
        opcode,
        payload,
    })
}

#[cfg(feature = "websocket")]
async fn write_frame(wr: &mut tokio::io::WriteHalf<DynStream>, frame: &Frame) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut header = Vec::with_capacity(14);
    let mut b0 = frame.opcode as u8;
    if frame.fin {
        b0 |= 0x80;
    }
    if frame.rsv1 {
        b0 |= 0x40;
    }
    header.push(b0);

    // Client frames must be masked.
    let mask_bit = 0x80;
    let len = frame.payload.len() as u64;
    if len <= 125 {
        header.push(mask_bit | (len as u8));
    } else if len <= u16::MAX as u64 {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&len.to_be_bytes());
    }

    let mut mask = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mask);
    header.extend_from_slice(&mask);

    wr.write_all(&header)
        .await
        .map_err(|e| EngineError::Internal(format!("websocket write failed: {e}")))?;

    if !frame.payload.is_empty() {
        let mut masked = frame.payload.clone();
        for (i, b) in masked.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        wr.write_all(&masked)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket write failed: {e}")))?;
    }

    wr.flush()
        .await
        .map_err(|e| EngineError::Internal(format!("websocket flush failed: {e}")))?;
    Ok(())
}

#[cfg(feature = "websocket")]
struct HandshakeResult {
    deflate: bool,
}

#[cfg(feature = "websocket")]
async fn handshake(
    stream: &mut DynStream,
    url: &Url,
    host: &str,
    cfg: &WsConfig,
) -> Result<HandshakeResult> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let key = generate_ws_key();
    let accept_expected = websocket_accept(&key);

    let port = url.port_or_known_default().unwrap_or(80);
    let default_port = match url.scheme().to_ascii_lowercase().as_str() {
        "ws" => 80,
        "wss" => 443,
        _ => port,
    };
    let mut path = url.path().to_owned();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    if path.is_empty() {
        path = "/".to_owned();
    }

    let mut req = String::new();
    req.push_str(&format!("GET {path} HTTP/1.1\r\n"));

    let host_override = cfg
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone());
    let mut host_header = host_override.unwrap_or_else(|| host.to_owned());
    if port != default_port && !host_header.contains(':') {
        host_header = format!("{host_header}:{port}");
    }
    req.push_str(&format!("Host: {host_header}\r\n"));

    req.push_str("Upgrade: websocket\r\n");
    req.push_str("Connection: Upgrade\r\n");
    req.push_str("Sec-WebSocket-Version: 13\r\n");
    req.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    if cfg.permessage_deflate {
        req.push_str("Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n");
    }
    for (k, v) in &cfg.headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| EngineError::Internal(format!("websocket handshake write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| EngineError::Internal(format!("websocket handshake flush failed: {e}")))?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    // 15-second hard cap: a server that never sends \r\n\r\n would block forever otherwise.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let n = tokio::time::timeout_at(deadline, stream.read(&mut tmp))
            .await
            .map_err(|_| EngineError::Internal("websocket handshake timed out (15 s)".to_owned()))?
            .map_err(|e| EngineError::Internal(format!("websocket handshake read failed: {e}")))?;
        if n == 0 {
            return Err(EngineError::Internal("websocket handshake: EOF".to_owned()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 32 * 1024 {
            return Err(EngineError::Internal(
                "websocket handshake: response too large".to_owned(),
            ));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let (head, _rest) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| EngineError::Internal("websocket handshake: bad response".to_owned()))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| EngineError::Internal("websocket handshake: missing status".to_owned()))?;
    if !status.contains(" 101 ") {
        return Err(EngineError::Internal(format!(
            "websocket handshake failed: {status}"
        )));
    }

    let mut accept = None;
    let mut extensions = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_owned();
            if k == "sec-websocket-accept" {
                accept = Some(v);
            } else if k == "sec-websocket-extensions" {
                extensions = Some(v);
            }
        }
    }

    let Some(accept) = accept else {
        return Err(EngineError::Internal(
            "websocket handshake: missing sec-websocket-accept".to_owned(),
        ));
    };
    if accept.trim() != accept_expected {
        return Err(EngineError::Internal(
            "websocket handshake: invalid sec-websocket-accept".to_owned(),
        ));
    }

    let deflate = cfg.permessage_deflate
        && extensions
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("permessage-deflate");

    Ok(HandshakeResult { deflate })
}

#[cfg(feature = "websocket")]
fn generate_ws_key() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(feature = "websocket")]
fn websocket_accept(key_b64: &str) -> String {
    use sha1::{Digest, Sha1};
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(key_b64.as_bytes());
    hasher.update(GUID.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(digest)
}

#[cfg(feature = "websocket")]
async fn connect_transport(
    url: &Url,
    resolver_chain: &ResolverChain,
    engine_config: Option<&EngineConfig>,
) -> Result<(DynStream, String)> {
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url
        .host_str()
        .ok_or_else(|| EngineError::InvalidInput("missing host".to_owned()))?
        .to_owned();
    let port = url.port_or_known_default().ok_or_else(|| {
        EngineError::InvalidInput(format!("unknown default port for scheme {}", url.scheme()))
    })?;

    let tcp = if let Some(cfg) = engine_config {
        if let Some(proxy) = &cfg.proxy {
            match proxy.kind {
                crate::config::ProxyKind::Socks5 => {
                    crate::core::proxy_helper::connect_via_socks5(
                        &proxy.address,
                        &host,
                        port,
                        resolver_chain,
                    )
                    .await?
                }
                _ => {
                    // Other proxy types (HTTP) are not yet supported for manual WebSocket upgrade.
                    return Err(EngineError::Config(
                        "WebSockets only support SOCKS5 proxy in the current build".to_owned(),
                    ));
                }
            }
        } else {
            let addr: SocketAddr = match host.parse::<IpAddr>() {
                Ok(ip) => SocketAddr::new(ip, port),
                Err(_) => {
                    let ips = resolver_chain.resolve(&host).await?;
                    let ip = *ips.first().ok_or_else(|| {
                        EngineError::Internal("dns resolve produced no addresses".to_owned())
                    })?;
                    SocketAddr::new(ip, port)
                }
            };
            tokio::time::timeout(
                Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            .map_err(|_| EngineError::Internal("tcp connect timed out after 10s".to_owned()))?
            .map_err(|e| EngineError::Internal(format!("tcp connect failed: {e}")))?
        }
    } else {
        let addr: SocketAddr = match host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, port),
            Err(_) => {
                let ips = resolver_chain.resolve(&host).await?;
                let ip = *ips.first().ok_or_else(|| {
                    EngineError::Internal("dns resolve produced no addresses".to_owned())
                })?;
                SocketAddr::new(ip, port)
            }
        };
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| EngineError::Internal("tcp connect timed out after 10s".to_owned()))?
        .map_err(|e| EngineError::Internal(format!("tcp connect failed: {e}")))?
    };

    tcp.set_nodelay(true).ok();

    let stream: DynStream = if let Some(cfg) = engine_config {
        let strategy = match &cfg.evasion.strategy {
            Some(crate::config::EvasionStrategy::Auto) => {
                if !cfg.evasion.client_hello_split_offsets.is_empty() {
                    Some(crate::config::EvasionStrategy::Desync)
                } else {
                    Some(crate::config::EvasionStrategy::Fragment)
                }
            }
            other => other.clone(),
        };

        if let Some(s) = strategy {
            let mut f_cfg = match s {
                crate::config::EvasionStrategy::Desync => {
                    let mut sizes: Vec<usize> = Vec::new();
                    let mut prev = 0usize;
                    for &off in &cfg.evasion.client_hello_split_offsets {
                        if off > prev {
                            sizes.push(off - prev);
                            prev = off;
                        }
                    }
                    if sizes.len() < 3 {
                        sizes = vec![1, 1, 1];
                    }
                    crate::evasion::FragmentConfig {
                        first_write_max: 64,
                        first_write_plan: Some(sizes),
                        fragment_size_min: cfg.evasion.fragment_size_min.max(1),
                        fragment_size_max: cfg.evasion.fragment_size_max.max(1),
                        sleep_ms: cfg.evasion.fragment_sleep_ms,
                        randomize_fragment_size: cfg.evasion.randomize_fragment_size,
                        split_at_sni: cfg.evasion.split_at_sni,
                        ..crate::evasion::FragmentConfig::default()
                    }
                }
                _ => crate::evasion::FragmentConfig {
                    first_write_max: 64,
                    fragment_size_min: cfg.evasion.fragment_size_min.max(1),
                    fragment_size_max: cfg.evasion.fragment_size_max.max(1),
                    sleep_ms: cfg.evasion.fragment_sleep_ms,
                    randomize_fragment_size: cfg.evasion.randomize_fragment_size,
                    ..crate::evasion::FragmentConfig::default()
                },
            };

            if cfg.evasion.traffic_shaping_enabled {
                f_cfg.jitter_ms = Some((
                    cfg.evasion.timing_jitter_ms_min,
                    cfg.evasion.timing_jitter_ms_max,
                ));
                f_cfg.randomize_fragment_size = true;
            }

            let (io, handle) = crate::evasion::FragmentingIo::new(tcp, f_cfg);
            // WebSocket implementation here doesn't have a clean "post-handshake" hook for IO,
            // but we can wrap it and rely on the fact that FragmentingIo only fragments first writes by default.
            // Actually, for WebSockets, the handshake IS the first write.
            // We should keep fragmentation for the handshake, and then it becomes less critical.

            match scheme.as_str() {
                "ws" => Box::new(io),
                "wss" => {
                    let tls = tls_connect_with_config(io, &host, cfg).await?;
                    handle.disable(); // disable fragmentation after TLS handshake for better performance
                    Box::new(tls)
                }
                _ => {
                    return Err(EngineError::InvalidInput(
                        "only ws:// and wss:// URLs are supported".to_owned(),
                    ))
                }
            }
        } else {
            match scheme.as_str() {
                "ws" => Box::new(tcp),
                "wss" => Box::new(tls_connect(tcp, &host).await?),
                _ => {
                    return Err(EngineError::InvalidInput(
                        "only ws:// and wss:// URLs are supported".to_owned(),
                    ))
                }
            }
        }
    } else {
        match scheme.as_str() {
            "ws" => Box::new(tcp),
            "wss" => Box::new(tls_connect(tcp, &host).await?),
            _ => {
                return Err(EngineError::InvalidInput(
                    "only ws:// and wss:// URLs are supported".to_owned(),
                ))
            }
        }
    };

    Ok((stream, host))
}

#[cfg(feature = "websocket")]
async fn tls_connect_with_config<T>(
    io: T,
    host: &str,
    cfg: &EngineConfig,
) -> Result<tokio_rustls::client::TlsStream<T>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use rustls::pki_types::ServerName;

    // Use our enhanced TLS config builder to support custom roots, fingerpringing, etc.
    // Note: ECH is NOT supported here as it requires complex async setup that we'd need to pull from PrimeHttpClient.
    // For WebSockets, we stick to custom fingerprints and fragments.
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = crate::core::http_client::select_crypto_provider(cfg);
    let mut tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| EngineError::Internal(format!("failed to set protocol versions: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Force http/1.1 for WebSocket upgrade.
    tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    if let Some(v) = cfg.evasion.tls_record_max_fragment_size {
        tls_cfg.max_fragment_size = Some(v);
    }

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_cfg));
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| EngineError::InvalidInput("invalid tls server name".to_owned()))?;
    connector
        .connect(server_name, io)
        .await
        .map_err(|e| EngineError::Internal(format!("tls connect failed: {e}")))
}

#[cfg(feature = "websocket")]
async fn tls_connect(
    tcp: tokio::net::TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    use rustls::pki_types::ServerName;

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| EngineError::InvalidInput("invalid tls server name".to_owned()))?;
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| EngineError::Internal(format!("tls connect failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "websocket")]
    async fn read_exact_prefetched(
        sock: &mut tokio::net::TcpStream,
        prefetched: &mut Vec<u8>,
        dst: &mut [u8],
    ) -> std::io::Result<()> {
        let take = prefetched.len().min(dst.len());
        if take > 0 {
            dst[..take].copy_from_slice(&prefetched[..take]);
            prefetched.drain(..take);
        }
        if take < dst.len() {
            tokio::io::AsyncReadExt::read_exact(sock, &mut dst[take..]).await?;
        }
        Ok(())
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    #[cfg_attr(
        windows,
        ignore = "flaky on Windows under parallel test load (sporadic reconnect race)"
    )]
    async fn websocket_handshake_and_echo_frames_over_tcp() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let cfg = crate::config::EngineConfig::default();
        let resolver = std::sync::Arc::new(
            crate::anticensorship::ResolverChain::from_config(&cfg.anticensorship)
                .expect("build resolver chain"),
        );

        // Minimal RFC6455 server: does handshake, echoes single-frame masked client messages back unmasked.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut req_buf = Vec::with_capacity(4096);
            loop {
                let mut chunk = [0u8; 1024];
                let n = sock.read(&mut chunk).await.expect("read");
                if n == 0 {
                    panic!("unexpected EOF before websocket headers");
                }
                req_buf.extend_from_slice(&chunk[..n]);
                if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if req_buf.len() > 16 * 1024 {
                    panic!("websocket headers too large");
                }
            }
            let headers_end = req_buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("headers end")
                + 4;
            let mut prefetched = req_buf[headers_end..].to_vec();
            req_buf.truncate(headers_end);
            let req = String::from_utf8_lossy(&req_buf);
            let key_line = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
                .expect("key");
            let key = key_line.split(':').nth(1).unwrap().trim();
            let accept = websocket_accept(key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            sock.write_all(resp.as_bytes()).await.expect("write");

            // Echo loop: supports one text frame then close.
            // Read first two bytes.
            let mut h = [0u8; 2];
            read_exact_prefetched(&mut sock, &mut prefetched, &mut h)
                .await
                .expect("read h");
            let masked = (h[1] & 0x80) != 0;
            let mut len = (h[1] & 0x7f) as usize;
            assert!(masked);
            if len == 126 {
                let mut b = [0u8; 2];
                read_exact_prefetched(&mut sock, &mut prefetched, &mut b)
                    .await
                    .expect("len");
                len = u16::from_be_bytes(b) as usize;
            }
            let mut mask = [0u8; 4];
            read_exact_prefetched(&mut sock, &mut prefetched, &mut mask)
                .await
                .expect("mask");
            let mut payload = vec![0u8; len];
            read_exact_prefetched(&mut sock, &mut prefetched, &mut payload)
                .await
                .expect("payload");
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }

            // Write unmasked echo as a server.
            let mut out = Vec::new();
            out.push(0x81); // FIN + TEXT
            out.push(payload.len() as u8);
            out.extend_from_slice(&payload);
            sock.write_all(&out).await.expect("echo");

            // Keep the socket open until the client initiates close().
            // This avoids a race where client receive() may observe close before text echo.
            let mut close_req = [0u8; 2];
            let _ =
                tokio::time::timeout(Duration::from_secs(2), sock.read_exact(&mut close_req)).await;
            let _ = sock.write_all(&[0x88, 0x00]).await;
            let _ = sock.shutdown().await;
        });

        let mut client = WebSocketClient::new(
            WsConfig {
                permessage_deflate: false,
                engine_config: Some(cfg),
                ..WsConfig::default()
            },
            resolver,
        );
        client
            .connect(&format!("ws://{addr}/echo"))
            .await
            .expect("connect");
        client
            .send(WsMessage::Text("hello".to_owned()))
            .await
            .expect("send");
        let msg = client.receive().await.expect("receive");
        match msg {
            WsMessage::Text(v) => assert_eq!(v, "hello"),
            other => panic!("unexpected: {other:?}"),
        }

        let _ = client.close().await;
        let _ = server.await;
    }
}
