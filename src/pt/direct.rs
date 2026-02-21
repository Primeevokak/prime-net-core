use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::anticensorship::ResolverChain;
use crate::error::{EngineError, Result};
use crate::platform::ttl::set_socket_ttl_low;

use super::{BoxStream, OutboundConnector, TargetAddr, TargetEndpoint};

#[derive(Debug, Clone)]
pub struct DirectOutbound {
    resolver: Arc<ResolverChain>,
    first_packet_ttl: u8,
    upstream_socks5: Option<SocketAddr>,
}

impl DirectOutbound {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
    const MAX_DOMAIN_IP_ATTEMPTS: usize = 8;

    pub fn new(resolver: Arc<ResolverChain>) -> Self {
        Self {
            resolver,
            first_packet_ttl: 0,
            upstream_socks5: None,
        }
    }

    pub fn with_first_packet_ttl(mut self, ttl: u8) -> Self {
        self.first_packet_ttl = ttl;
        self
    }

    pub fn with_upstream_socks5(mut self, upstream: Option<SocketAddr>) -> Self {
        self.upstream_socks5 = upstream;
        self
    }

    async fn connect_impl(&self, target: TargetEndpoint) -> Result<BoxStream> {
        let target_label = match &target.addr {
            TargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
            TargetAddr::Domain(host) => format!("{host}:{}", target.port),
        };
        if let Some(proxy_addr) = self.upstream_socks5 {
            return self
                .connect_via_socks5_with_timeout(&target_label, &target, proxy_addr)
                .await;
        }

        match target.addr {
            TargetAddr::Ip(ip) => {
                let addr = std::net::SocketAddr::new(ip, target.port);
                self.connect_addr_with_timeout(&target_label, addr).await
            }
            TargetAddr::Domain(host) => {
                let mut ips = self.resolver.resolve(&host).await?;
                if ips.is_empty() {
                    return Err(EngineError::Internal(format!(
                        "dns resolver returned no IPs for '{}'",
                        host
                    )));
                }

                // Prefer IPv4 first in this path because many desktop stacks and middleboxes
                // still handle IPv4 routes more reliably under interference.
                ips.sort_by_key(|ip| if ip.is_ipv4() { 0u8 } else { 1u8 });
                let attempts = ips.len().min(Self::MAX_DOMAIN_IP_ATTEMPTS);
                info!(
                    target: "outbound.direct",
                    host = %host,
                    port = target.port,
                    resolved_ips = attempts,
                    "DNS resolved for direct outbound"
                );

                let mut last_err: Option<EngineError> = None;
                for (idx, ip) in ips.into_iter().take(attempts).enumerate() {
                    let addr = std::net::SocketAddr::new(ip, target.port);
                    match self.connect_addr_with_timeout(&target_label, addr).await {
                        Ok(stream) => {
                            if idx > 0 {
                                info!(
                                    target: "outbound.direct",
                                    destination = %target_label,
                                    upstream = %addr,
                                    attempt = idx + 1,
                                    "Direct outbound connected after fallback"
                                );
                            }
                            return Ok(stream);
                        }
                        Err(e) => {
                            warn!(
                                target: "outbound.direct",
                                destination = %target_label,
                                upstream = %addr,
                                attempt = idx + 1,
                                error = %e,
                                "Direct outbound attempt failed"
                            );
                            last_err = Some(e);
                        }
                    }
                }

                Err(last_err.unwrap_or_else(|| {
                    EngineError::Internal(format!(
                        "no connect attempts were made for '{}'",
                        target_label
                    ))
                }))
            }
        }
    }

    async fn connect_addr_with_timeout(
        &self,
        target_label: &str,
        addr: std::net::SocketAddr,
    ) -> Result<BoxStream> {
        info!(target: "outbound.direct", destination = %target_label, upstream = %addr, "Direct outbound connect");
        let connect = tokio::time::timeout(Self::CONNECT_TIMEOUT, TcpStream::connect(addr)).await;
        let tcp = match connect {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                return Err(EngineError::Internal(format!(
                    "connect timeout after {}ms",
                    Self::CONNECT_TIMEOUT.as_millis()
                )))
            }
        };
        let _ = tcp.set_nodelay(true);
        let _ = set_socket_ttl_low(&tcp, self.first_packet_ttl);
        info!(target: "outbound.direct", destination = %target_label, upstream = %addr, "Direct outbound connected");
        Ok(Box::new(tcp))
    }

    async fn connect_via_socks5_with_timeout(
        &self,
        target_label: &str,
        target: &TargetEndpoint,
        proxy_addr: SocketAddr,
    ) -> Result<BoxStream> {
        info!(
            target: "outbound.direct",
            destination = %target_label,
            upstream_socks5 = %proxy_addr,
            "Direct outbound connect via upstream SOCKS5"
        );
        let connect =
            tokio::time::timeout(Self::CONNECT_TIMEOUT, TcpStream::connect(proxy_addr)).await;
        let mut tcp = match connect {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                return Err(EngineError::Internal(format!(
                    "upstream SOCKS5 connect timeout after {}ms",
                    Self::CONNECT_TIMEOUT.as_millis()
                )))
            }
        };
        let _ = tcp.set_nodelay(true);

        tcp.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method_reply = [0u8; 2];
        tcp.read_exact(&mut method_reply).await?;
        if method_reply[0] != 0x05 {
            return Err(EngineError::Internal(
                "upstream SOCKS5 invalid reply version".to_owned(),
            ));
        }
        if method_reply[1] != 0x00 {
            return Err(EngineError::Internal(format!(
                "upstream SOCKS5 no-auth method rejected (method=0x{:02x})",
                method_reply[1]
            )));
        }

        let mut req = Vec::with_capacity(4 + 256 + 2);
        req.push(0x05);
        req.push(0x01);
        req.push(0x00);
        match &target.addr {
            TargetAddr::Ip(std::net::IpAddr::V4(v4)) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            TargetAddr::Ip(std::net::IpAddr::V6(v6)) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
            TargetAddr::Domain(host) => {
                let host_bytes = host.as_bytes();
                if host_bytes.len() > 255 {
                    return Err(EngineError::InvalidInput(
                        "target host is too long for SOCKS5".to_owned(),
                    ));
                }
                req.push(0x03);
                req.push(host_bytes.len() as u8);
                req.extend_from_slice(host_bytes);
            }
        }
        req.extend_from_slice(&target.port.to_be_bytes());

        tcp.write_all(&req).await?;

        let mut connect_reply = [0u8; 4];
        tcp.read_exact(&mut connect_reply).await?;
        if connect_reply[0] != 0x05 {
            return Err(EngineError::Internal(
                "upstream SOCKS5 invalid connect reply version".to_owned(),
            ));
        }
        if connect_reply[1] != 0x00 {
            return Err(EngineError::Internal(format!(
                "upstream SOCKS5 connect failed (REP=0x{:02x})",
                connect_reply[1]
            )));
        }

        match connect_reply[3] {
            0x01 => {
                let mut b = [0u8; 4 + 2];
                tcp.read_exact(&mut b).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                tcp.read_exact(&mut len).await?;
                let mut b = vec![0u8; len[0] as usize + 2];
                tcp.read_exact(&mut b).await?;
            }
            0x04 => {
                let mut b = [0u8; 16 + 2];
                tcp.read_exact(&mut b).await?;
            }
            other => {
                return Err(EngineError::Internal(format!(
                    "upstream SOCKS5 invalid address type 0x{other:02x}"
                )))
            }
        }

        info!(
            target: "outbound.direct",
            destination = %target_label,
            upstream_socks5 = %proxy_addr,
            "Direct outbound connected via upstream SOCKS5"
        );
        Ok(Box::new(tcp))
    }
}

impl OutboundConnector for DirectOutbound {
    fn connect<'a>(
        &'a self,
        target: TargetEndpoint,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<BoxStream>> + Send + 'a>> {
        Box::pin(async move { self.connect_impl(target).await })
    }
}
