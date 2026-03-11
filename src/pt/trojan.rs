use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::anticensorship::ResolverChain;
use crate::config::TrojanPtConfig;
use crate::error::{EngineError, Result};

use super::{BoxStream, OutboundConnector, TargetAddr, TargetEndpoint};

#[derive(Debug, Clone)]
pub struct TrojanOutbound {
    resolver: Arc<ResolverChain>,
    cfg: TrojanPtConfig,
}

impl TrojanOutbound {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);
    const IO_TIMEOUT: Duration = Duration::from_secs(10);

    pub fn new(resolver: Arc<ResolverChain>, cfg: TrojanPtConfig) -> Self {
        Self { resolver, cfg }
    }

    async fn connect_impl(&self, target: TargetEndpoint) -> Result<BoxStream> {
        let target_label = match &target.addr {
            TargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
            TargetAddr::Domain(host) => format!("{host}:{}", target.port),
        };
        let (server_host, server_port) = split_host_port(&self.cfg.server)?;

        let server_addrs: Vec<std::net::SocketAddr> = if let Ok(ip) =
            server_host.parse::<std::net::IpAddr>()
        {
            vec![std::net::SocketAddr::new(ip, server_port)]
        } else {
            let ips = self.resolver.resolve(&server_host).await?;
            if ips.is_empty() {
                return Err(EngineError::Internal(format!(
                    "dns resolver returned no IPs for '{}'",
                    server_host
                )));
            }
            let out: Vec<std::net::SocketAddr> = ips
                .into_iter()
                .map(|ip| std::net::SocketAddr::new(ip, server_port))
                .collect();
            info!(target: "outbound.trojan", server_host = %server_host, resolved_count = out.len(), server_port, "Trojan server resolved");
            out
        };

        let mut last_err: Option<EngineError> = None;
        let mut tcp_opt = None;
        for server_addr in server_addrs {
            info!(target: "outbound.trojan", server = %server_addr, destination = %target_label, "Trojan outbound TCP connect");
            match timeout(Self::CONNECT_TIMEOUT, TcpStream::connect(server_addr)).await {
                Ok(Ok(tcp)) => {
                    tcp_opt = Some((server_addr, tcp));
                    break;
                }
                Ok(Err(e)) => {
                    warn!(target: "outbound.trojan", server = %server_addr, destination = %target_label, error = %e, "Trojan outbound TCP connect failed");
                    last_err = Some(EngineError::from(e));
                }
                Err(_) => {
                    warn!(target: "outbound.trojan", server = %server_addr, destination = %target_label, timeout_ms = Self::CONNECT_TIMEOUT.as_millis(), "Trojan outbound TCP connect timeout");
                    last_err = Some(EngineError::Internal("trojan connect timeout".to_owned()));
                }
            }
        }
        let (server_addr, tcp) = tcp_opt.ok_or_else(|| {
            last_err.unwrap_or_else(|| {
                EngineError::Internal("trojan connect failed for all resolved IPs".to_owned())
            })
        })?;
        let _ = tcp.set_nodelay(true);

        let tls_cfg = build_trojan_rustls_client_config(&self.cfg)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));

        let sni = self.cfg.sni.clone().unwrap_or_else(|| server_host.clone());

        let server_name = if let Ok(ip) = sni.parse::<std::net::IpAddr>() {
            rustls::pki_types::ServerName::IpAddress(ip.into())
        } else {
            rustls::pki_types::ServerName::try_from(sni.clone())
                .map_err(|_| EngineError::InvalidInput(format!("invalid SNI '{sni}'")))?
        };

        let mut tls = timeout(Self::HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .map_err(|_| EngineError::Internal("trojan TLS handshake timeout".to_owned()))?
            .map_err(|e| {
            warn!(target: "outbound.trojan", server = %server_addr, destination = %target_label, error = %e, "Trojan TLS handshake failed");
            e
        })?;
        info!(target: "outbound.trojan", server = %server_addr, destination = %target_label, "Trojan TLS connected");

        // Trojan header: SHA224(password) hex + CRLF + SOCKS5 request + CRLF
        // To mitigate replay attacks, we can append a 32-bit timestamp (seconds) if the server supports it.
        // Standard Trojan doesn't, but enhanced versions do. We'll include it as an optional suffix.
        let pass = sha224_hex(self.cfg.password.as_bytes());

        timeout(Self::IO_TIMEOUT, tls.write_all(pass.as_bytes()))
            .await
            .map_err(|_| EngineError::Internal("trojan write timeout".to_owned()))??;
        timeout(Self::IO_TIMEOUT, tls.write_all(b"\r\n"))
            .await
            .map_err(|_| EngineError::Internal("trojan write timeout".to_owned()))??;

        let req = build_trojan_connect_request(target)?;
        // NOTE: Appending custom metadata here (like a timestamp for replay protection)
        // will break compatibility with standard Trojan servers.
        // Standard servers expect CRLF immediately after the SOCKS5 request.

        timeout(Self::IO_TIMEOUT, tls.write_all(&req))
            .await
            .map_err(|_| EngineError::Internal("trojan write timeout".to_owned()))??;
        timeout(Self::IO_TIMEOUT, tls.write_all(b"\r\n"))
            .await
            .map_err(|_| EngineError::Internal("trojan write timeout".to_owned()))??;
        timeout(Self::IO_TIMEOUT, tls.flush())
            .await
            .map_err(|_| EngineError::Internal("trojan flush timeout".to_owned()))??;

        info!(target: "outbound.trojan", server = %server_addr, destination = %target_label, "Trojan CONNECT request sent");
        Ok(Box::new(tls))
    }
}

impl OutboundConnector for TrojanOutbound {
    fn connect<'a>(
        &'a self,
        target: TargetEndpoint,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<BoxStream>> + Send + 'a>> {
        Box::pin(async move { self.connect_impl(target).await })
    }
}

fn sha224_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha224::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push(nibble_to_hex((b >> 4) & 0x0f));
        out.push(nibble_to_hex(b & 0x0f));
    }
    out
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '0',
    }
}

fn build_trojan_connect_request(target: TargetEndpoint) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(0x01); // CONNECT

    match target.addr {
        TargetAddr::Ip(std::net::IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
        TargetAddr::Domain(d) => {
            let b = d.as_bytes();
            if b.len() > 255 {
                return Err(EngineError::InvalidInput(
                    "trojan domain is too long".to_owned(),
                ));
            }
            out.push(0x03);
            out.push(b.len() as u8);
            out.extend_from_slice(b);
        }
    }

    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return Err(EngineError::Config("pt.trojan.server is empty".to_owned()));
    }

    // [v6]:port
    if s.starts_with('[') {
        let Some(end) = s.find(']') else {
            return Err(EngineError::Config(
                "invalid pt.trojan.server (missing ']')".to_owned(),
            ));
        };
        let host = s[1..end].trim();
        if host.is_empty() {
            return Err(EngineError::Config(
                "invalid pt.trojan.server (host is empty)".to_owned(),
            ));
        }
        let rest = &s[end + 1..];
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| {
                EngineError::Config("invalid pt.trojan.server (missing port)".to_owned())
            })?
            .trim()
            .parse::<u16>()
            .map_err(|_| EngineError::Config("invalid pt.trojan.server port".to_owned()))?;
        return Ok((host.to_owned(), port));
    }

    let Some((host, port)) = s.rsplit_once(':') else {
        return Err(EngineError::Config(
            "pt.trojan.server must be 'host:port'".to_owned(),
        ));
    };
    let host = host.trim();
    if host.is_empty() {
        return Err(EngineError::Config(
            "invalid pt.trojan.server (host is empty)".to_owned(),
        ));
    }
    let port = port
        .trim()
        .parse::<u16>()
        .map_err(|_| EngineError::Config("invalid pt.trojan.server port".to_owned()))?;
    Ok((host.to_owned(), port))
}

fn build_trojan_rustls_client_config(cfg: &TrojanPtConfig) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let versions: Vec<&'static rustls::SupportedProtocolVersion> =
        vec![&rustls::version::TLS13, &rustls::version::TLS12];

    let provider = rustls::crypto::CryptoProvider::get_default()
        .map(|arc| (**arc).clone())
        .unwrap_or_else(rustls::crypto::aws_lc_rs::default_provider);

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .map_err(|_| EngineError::Config("invalid TLS protocol versions".to_owned()))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut alpn = Vec::new();
    for p in &cfg.alpn_protocols {
        let p = p.trim();
        if !p.is_empty() {
            alpn.push(p.as_bytes().to_vec());
        }
    }
    if alpn.is_empty() {
        alpn.push(b"h2".to_vec());
        alpn.push(b"http/1.1".to_vec());
    }
    tls.alpn_protocols = alpn;

    fn is_dev_mode() -> bool {
        std::env::var("PRIME_NET_DEV").is_ok()
    }

    if cfg.insecure_skip_verify {
        if is_dev_mode() {
            tracing::warn!("Trojan PT TLS verification is DISABLED (insecure_skip_verify=true). This allows MITM attacks and should ONLY be used for local testing/debugging.");
            tls.dangerous()
                .set_certificate_verifier(Arc::new(crate::tls::InsecureSkipVerify));
        } else {
            tracing::error!("insecure_skip_verify=true ignored in production mode. Set PRIME_NET_DEV=1 to enable for local testing.");
        }
    }

    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha224_hex_matches_length() {
        let h = sha224_hex(b"password");
        assert_eq!(h.len(), 56);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn trojan_request_domain_encodes() {
        let req = build_trojan_connect_request(TargetEndpoint {
            addr: TargetAddr::Domain("example.com".to_owned()),
            port: 443,
        })
        .unwrap();
        assert_eq!(req[0], 0x01);
        assert_eq!(req[1], 0x03);
        assert_eq!(req[2] as usize, "example.com".len());
        assert_eq!(&req[3..3 + "example.com".len()], b"example.com");
    }

    #[test]
    fn split_host_port_rejects_empty_host() {
        let err = split_host_port(":443").expect_err("empty host must fail");
        assert!(format!("{err}").contains("host is empty"));
    }

    #[test]
    fn split_host_port_rejects_empty_bracket_host() {
        let err = split_host_port("[]:443").expect_err("empty bracketed host must fail");
        assert!(format!("{err}").contains("host is empty"));
    }
}
