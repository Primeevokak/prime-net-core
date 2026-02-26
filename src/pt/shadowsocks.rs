use std::pin::Pin;
use std::sync::Arc;

use crate::anticensorship::ResolverChain;
use crate::config::ShadowsocksPtConfig;
use crate::error::{EngineError, Result};
use tracing::{info, warn};

use super::{BoxStream, OutboundConnector, TargetAddr, TargetEndpoint};

#[derive(Debug, Clone)]
pub struct ShadowsocksOutbound {
    resolver: Arc<ResolverChain>,
    context: shadowsocks::context::SharedContext,
    server_host: String,
    server_port: u16,
    password: String,
    method: shadowsocks::crypto::CipherKind,
}

impl ShadowsocksOutbound {
    pub async fn new(resolver: Arc<ResolverChain>, cfg: ShadowsocksPtConfig) -> Result<Self> {
        let (host, port) = split_host_port(&cfg.server)?;

        // Validate method early
        let method = cfg
            .method
            .parse::<shadowsocks::crypto::CipherKind>()
            .map_err(|_| {
                EngineError::Config("pt.shadowsocks.method is invalid/unsupported".to_owned())
            })?;

        let context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Local);

        Ok(Self {
            resolver,
            context,
            server_host: host,
            server_port: port,
            password: cfg.password,
            method,
        })
    }

    async fn connect_impl(&self, target: TargetEndpoint) -> Result<BoxStream> {
        let target_label = match &target.addr {
            TargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
            TargetAddr::Domain(host) => format!("{host}:{}", target.port),
        };

        // Resolve server address for every connection to handle DNS changes/load balancing
        let server_addr = if let Ok(ip) = self.server_host.parse::<std::net::IpAddr>() {
            std::net::SocketAddr::new(ip, self.server_port)
        } else {
            let ips = self.resolver.resolve(&self.server_host).await?;
            let ip = *ips.first().ok_or_else(|| {
                EngineError::Internal(format!(
                    "dns resolver returned no IPs for '{}'",
                    self.server_host
                ))
            })?;
            info!(target: "outbound.shadowsocks", server_host = %self.server_host, resolved_ip = %ip, server_port = self.server_port, "Shadowsocks server resolved");
            std::net::SocketAddr::new(ip, self.server_port)
        };

        let mut server_cfg = shadowsocks::config::ServerConfig::new(
            shadowsocks::config::ServerAddr::from(server_addr),
            self.password.clone(),
            self.method,
        )
        .map_err(|e| EngineError::Config(format!("pt.shadowsocks config error: {e}")))?;
        server_cfg.set_mode(shadowsocks::config::Mode::TcpOnly);

        let server_endpoint = server_addr.to_string();

        let addr = match target.addr {
            TargetAddr::Ip(ip) => {
                let sa = std::net::SocketAddr::new(ip, target.port);
                shadowsocks::relay::socks5::Address::from(sa)
            }
            TargetAddr::Domain(d) => shadowsocks::relay::socks5::Address::from((d, target.port)),
        };

        info!(target: "outbound.shadowsocks", server = %server_endpoint, destination = %target_label, "Shadowsocks outbound connect");
        let s = shadowsocks::relay::tcprelay::proxy_stream::client::ProxyClientStream::<
            shadowsocks::net::tcp::TcpStream,
        >::connect(self.context.clone(), &server_cfg, addr).await.map_err(|e| {
            warn!(target: "outbound.shadowsocks", server = %server_endpoint, destination = %target_label, error = %e, "Shadowsocks outbound connect failed");
            e
        })?;

        info!(target: "outbound.shadowsocks", server = %server_endpoint, destination = %target_label, "Shadowsocks outbound connected");
        Ok(Box::new(s))
    }
}

impl OutboundConnector for ShadowsocksOutbound {
    fn connect<'a>(
        &'a self,
        target: TargetEndpoint,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<BoxStream>> + Send + 'a>> {
        Box::pin(async move { self.connect_impl(target).await })
    }
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return Err(EngineError::Config(
            "pt.shadowsocks.server is empty".to_owned(),
        ));
    }

    if s.starts_with('[') {
        let Some(end) = s.find(']') else {
            return Err(EngineError::Config(
                "invalid pt.shadowsocks.server (missing ']')".to_owned(),
            ));
        };
        let host = s[1..end].trim();
        if host.is_empty() {
            return Err(EngineError::Config(
                "invalid pt.shadowsocks.server (host is empty)".to_owned(),
            ));
        }
        let rest = &s[end + 1..];
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| {
                EngineError::Config("invalid pt.shadowsocks.server (missing port)".to_owned())
            })?
            .trim()
            .parse::<u16>()
            .map_err(|_| EngineError::Config("invalid pt.shadowsocks.server port".to_owned()))?;
        return Ok((host.to_owned(), port));
    }

    let Some((host, port)) = s.rsplit_once(':') else {
        return Err(EngineError::Config(
            "pt.shadowsocks.server must be 'host:port'".to_owned(),
        ));
    };
    let host = host.trim();
    if host.is_empty() {
        return Err(EngineError::Config(
            "invalid pt.shadowsocks.server (host is empty)".to_owned(),
        ));
    }
    let port = port
        .trim()
        .parse::<u16>()
        .map_err(|_| EngineError::Config("invalid pt.shadowsocks.server port".to_owned()))?;
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_rejects_empty_host() {
        let err = split_host_port(":8388").expect_err("empty host must fail");
        assert!(format!("{err}").contains("host is empty"));
    }

    #[test]
    fn split_host_port_rejects_empty_bracket_host() {
        let err = split_host_port("[]:8388").expect_err("empty bracketed host must fail");
        assert!(format!("{err}").contains("host is empty"));
    }
}
