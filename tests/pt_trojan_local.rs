use std::sync::Arc;

use prime_net_engine_core::anticensorship::ResolverChain;
use prime_net_engine_core::config::{AntiCensorshipConfig, EngineConfig, TrojanPtConfig};
use prime_net_engine_core::pt::socks5_server::start_socks5_server;
use prime_net_engine_core::pt::trojan::TrojanOutbound;
use prime_net_engine_core::pt::DynOutbound;
use prime_net_engine_core::Result;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

fn sha224_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha224::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

async fn start_plain_http_server() -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tcp.read(&mut buf).await;
                let _ = tcp
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
                let _ = tcp.shutdown().await;
            });
        }
    });

    Ok(addr)
}

async fn start_trojan_server(password: &str) -> Result<std::net::SocketAddr> {
    use tokio_rustls::TlsAcceptor;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|e| prime_net_engine_core::EngineError::Internal(e.to_string()))?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let chain = vec![rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec(),
    )];

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| {
            prime_net_engine_core::EngineError::Internal("server tls versions".to_owned())
        })?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| prime_net_engine_core::EngineError::Internal(e.to_string()))?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let expected = sha224_hex(password.as_bytes());

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let expected = expected.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };

                // Read password line.
                let mut line = Vec::new();
                if read_until_crlf(&mut tls, &mut line).await.is_err() {
                    return;
                }
                let Ok(got) = std::str::from_utf8(&line) else {
                    return;
                };
                if got.trim_end_matches("\r\n") != expected {
                    // Silent drop.
                    let _ = tls.shutdown().await;
                    return;
                }

                // Read trojan request line (binary, ends with CRLF).
                let mut req = Vec::new();
                if read_until_crlf(&mut tls, &mut req).await.is_err() {
                    return;
                }
                if req.len() < 4 {
                    let _ = tls.shutdown().await;
                    return;
                }
                let cmd = req[0];
                if cmd != 0x01 {
                    let _ = tls.shutdown().await;
                    return;
                }
                let atyp = req[1];
                let (host, port) = match atyp {
                    0x01 => {
                        if req.len() < 2 + 4 + 2 {
                            return;
                        }
                        let ip = std::net::Ipv4Addr::new(req[2], req[3], req[4], req[5]);
                        let port = u16::from_be_bytes([req[6], req[7]]);
                        (ip.to_string(), port)
                    }
                    0x03 => {
                        let len = req[2] as usize;
                        if req.len() < 3 + len + 2 {
                            return;
                        }
                        let host = String::from_utf8_lossy(&req[3..3 + len]).to_string();
                        let port = u16::from_be_bytes([req[3 + len], req[4 + len]]);
                        (host, port)
                    }
                    0x04 => {
                        if req.len() < 2 + 16 + 2 {
                            return;
                        }
                        let mut b = [0u8; 16];
                        b.copy_from_slice(&req[2..18]);
                        let ip = std::net::Ipv6Addr::from(b);
                        let port = u16::from_be_bytes([req[18], req[19]]);
                        (ip.to_string(), port)
                    }
                    _ => return,
                };

                let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)).await else {
                    let _ = tls.shutdown().await;
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
            });
        }
    });

    Ok(addr)
}

async fn read_until_crlf<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    out: &mut Vec<u8>,
) -> std::io::Result<()> {
    out.clear();
    let mut b = [0u8; 1];
    loop {
        s.read_exact(&mut b).await?;
        out.push(b[0]);
        if out.len() >= 2 && out[out.len() - 2] == b'\r' && out[out.len() - 1] == b'\n' {
            return Ok(());
        }
        if out.len() > 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }
    }
}

async fn socks5_connect(proxy: std::net::SocketAddr, host: &str, port: u16) -> Result<TcpStream> {
    let mut tcp = TcpStream::connect(proxy).await?;
    tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    tcp.read_exact(&mut resp).await?;
    assert_eq!(resp, [0x05, 0x00]);

    let mut req = Vec::new();
    req.push(0x05);
    req.push(0x01);
    req.push(0x00);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let b = host.as_bytes();
        req.push(0x03);
        req.push(b.len() as u8);
        req.extend_from_slice(b);
    }
    req.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&req).await?;

    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await?;
    assert_eq!(hdr[0], 0x05);
    assert_eq!(hdr[1], 0x00);

    match hdr[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            tcp.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut lb = [0u8; 1];
            tcp.read_exact(&mut lb).await?;
            let mut b = vec![0u8; (lb[0] as usize) + 2];
            tcp.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            tcp.read_exact(&mut b).await?;
        }
        _ => panic!("bad atyp"),
    }

    Ok(tcp)
}

#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "flaky on Windows under parallel test load (sporadic early EOF)"
)]
async fn trojan_outbound_via_local_socks5_can_proxy_http() -> Result<()> {
    let password = "secret";
    let http_addr = start_plain_http_server().await?;
    let trojan_addr = start_trojan_server(password).await?;

    let resolver = Arc::new(ResolverChain::from_config(&AntiCensorshipConfig::default())?);

    let outbound: DynOutbound = Arc::new(TrojanOutbound::new(
        resolver,
        TrojanPtConfig {
            server: trojan_addr.to_string(),
            password: password.to_owned(),
            sni: Some("localhost".to_owned()),
            alpn_protocols: vec!["http/1.1".to_owned()],
            insecure_skip_verify: true,
        },
    ));

    let socks = start_socks5_server(
        "127.0.0.1:0".parse().unwrap(),
        outbound,
        Arc::new(EngineConfig::default()),
        true,
        prime_net_engine_core::pt::socks5_server::RelayOptions::default(),
    )
    .await?;
    let mut tunneled = socks5_connect(
        socks.listen_addr(),
        &http_addr.ip().to_string(),
        http_addr.port(),
    )
    .await?;

    tunneled
        .write_all(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
        .await?;
    let mut buf = Vec::new();
    timeout(Duration::from_secs(2), async {
        let mut tmp = [0u8; 256];
        let mut expected_total = None;
        loop {
            let n = tunneled.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if expected_total.is_none() {
                if let Some(headers_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let body_offset = headers_end + 4;
                    let headers = String::from_utf8_lossy(&buf[..body_offset]);
                    let content_len = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("Content-Length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    expected_total = Some(body_offset + content_len);
                }
            }
            if expected_total.is_some_and(|total| buf.len() >= total) {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "response timeout"))??;

    let s = String::from_utf8_lossy(&buf);
    assert!(s.contains("200 OK"));
    assert!(s.contains("\r\n\r\nok"));
    Ok(())
}
