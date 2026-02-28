use std::time::Duration;
use tokio::net::TcpStream;
use url::Url;

use crate::anticensorship::ResolverChain;
use crate::error::{EngineError, Result};

pub fn normalize_proxy_host_port(
    s: &str,
) -> Result<(String, u16, Option<String>, Option<String>)> {
    let s = s.trim();
    if s.is_empty() {
        return Err(EngineError::Config("proxy.address is empty".to_owned()));
    }

    if s.contains("://") {
        let url = Url::parse(s)?;
        let user = if !url.username().is_empty() {
            Some(url.username().to_owned())
        } else {
            None
        };
        let pass = url.password().map(|v| v.to_owned());
        let host = url
            .host_str()
            .ok_or_else(|| EngineError::Config("proxy.address URL missing host".to_owned()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| EngineError::Config("proxy.address URL missing port".to_owned()))?;
        return Ok((host.to_owned(), port, user, pass));
    }

    if let Some((h, p)) = s.rsplit_once(':') {
        let mut host = h.trim().to_owned();
        if host.starts_with('[') {
            if !host.ends_with(']') {
                return Err(EngineError::Config(
                    "proxy.address IPv6 must be in the form '[::1]:port'".to_owned(),
                ));
            }
            host = host[1..host.len() - 1].to_owned();
        } else if host.contains(':') {
            return Err(EngineError::Config(
                "proxy.address IPv6 must be in the form '[::1]:port'".to_owned(),
            ));
        }
        if host.is_empty() {
            return Err(EngineError::Config("proxy.address missing host".to_owned()));
        }

        let (user, pass, host) = if let Some((ui, h2)) = host.rsplit_once('@') {
            let ui = ui.trim();
            let h2 = h2.trim();
            if ui.is_empty() || h2.is_empty() {
                return Err(EngineError::Config(
                    "proxy.address has invalid credentials syntax".to_owned(),
                ));
            }
            let (u, p) = ui.split_once(':').unwrap_or((ui, ""));
            (Some(u.to_owned()), Some(p.to_owned()), h2.to_owned())
        } else {
            (None, None, host)
        };

        let p = p
            .parse::<u16>()
            .map_err(|_| EngineError::Config("proxy.address has invalid port".to_owned()))?;
        return Ok((host, p, user, pass));
    }

    Err(EngineError::Config(
        "proxy.address must be 'host:port' (or a URL)".to_owned(),
    ))
}

pub fn is_loopback_proxy_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

pub async fn connect_via_socks5(
    proxy_addr: &str,
    host: &str,
    port: u16,
    resolver_chain: &ResolverChain,
) -> Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (proxy_host, proxy_port, proxy_user, proxy_pass) = normalize_proxy_host_port(proxy_addr)?;

    let proxy_targets: Vec<std::net::SocketAddr> =
        if let Ok(ip) = proxy_host.parse::<std::net::IpAddr>() {
            vec![std::net::SocketAddr::new(ip, proxy_port)]
        } else {
            let ips = resolver_chain.resolve(&proxy_host).await?;
            ips.into_iter()
                .map(|ip| std::net::SocketAddr::new(ip, proxy_port))
                .collect()
        };

    let mut last_connect_err: Option<std::io::Error> = None;
    let mut tcp_opt = None;
    for addr in proxy_targets {
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                tcp_opt = Some(stream);
                break;
            }
            Ok(Err(e)) => last_connect_err = Some(e),
            Err(_) => {
                last_connect_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "SOCKS5 upstream connect timeout",
                ));
            }
        }
    }
    let mut tcp = if let Some(stream) = tcp_opt {
        stream
    } else {
        return Err(last_connect_err
            .map(EngineError::from)
            .unwrap_or_else(|| {
                EngineError::Internal("failed to resolve/connect SOCKS5 proxy".to_owned())
            }));
    };
    let _ = tcp.set_nodelay(true);

    let has_creds = proxy_user.is_some();

    // Greeting: VER=5, NMETHODS, METHODS=[USERPASS?, NOAUTH]
    if has_creds {
        tcp.write_all(&[0x05, 0x02, 0x02, 0x00]).await?;
    } else {
        tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut resp = [0u8; 2];
    tcp.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(EngineError::Internal(
            "SOCKS5 invalid reply version".to_owned(),
        ));
    }
    match resp[1] {
        0x00 => {} // NOAUTH
        0x02 => {
            // RFC1929 username/password auth.
            let user = proxy_user.unwrap_or_default();
            let pass = proxy_pass.unwrap_or_default();
            let ub = user.as_bytes();
            let pb = pass.as_bytes();
            if ub.len() > 255 || pb.len() > 255 {
                return Err(EngineError::InvalidInput(
                    "SOCKS5 username/password is too long".to_owned(),
                ));
            }
            let mut auth = Vec::with_capacity(3 + ub.len() + pb.len());
            auth.push(0x01); // auth version
            auth.push(ub.len() as u8);
            auth.extend_from_slice(ub);
            auth.push(pb.len() as u8);
            auth.extend_from_slice(pb);
            tcp.write_all(&auth).await?;

            let mut aresp = [0u8; 2];
            tcp.read_exact(&mut aresp).await?;
            if aresp[0] != 0x01 || aresp[1] != 0x00 {
                return Err(EngineError::Internal(
                    "SOCKS5 username/password auth failed".to_owned(),
                ));
            }
        }
        0xFF => {
            return Err(EngineError::Internal(
                "SOCKS5 proxy has no acceptable auth methods".to_owned(),
            ));
        }
        other => {
            return Err(EngineError::Internal(format!(
                "SOCKS5 proxy selected unsupported auth method 0x{other:02x}"
            )));
        }
    }

    // CONNECT request.
    let mut req = Vec::with_capacity(4 + 1 + host.len() + 2);
    req.push(0x05); // VER
    req.push(0x01); // CMD=CONNECT
    req.push(0x00); // RSV

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
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(EngineError::InvalidInput(
                "SOCKS5 host is too long".to_owned(),
            ));
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&port.to_be_bytes());

    tcp.write_all(&req).await?;

    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(EngineError::Internal(
            "SOCKS5 invalid reply version".to_owned(),
        ));
    }
    if hdr[1] != 0x00 {
        return Err(EngineError::Internal(format!(
            "SOCKS5 connect failed (REP=0x{:02x})",
            hdr[1]
        )));
    }

    match hdr[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            tcp.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut lenb = [0u8; 1];
            tcp.read_exact(&mut lenb).await?;
            let len = lenb[0] as usize;
            let mut b = vec![0u8; len + 2];
            tcp.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            tcp.read_exact(&mut b).await?;
        }
        other => {
            return Err(EngineError::Internal(format!(
                "SOCKS5 invalid reply address type 0x{other:02x}"
            )));
        }
    }

    Ok(tcp)
}
