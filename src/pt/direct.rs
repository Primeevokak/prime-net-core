use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
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
    const HAPPY_EYEBALLS_FALLBACK_DELAY: Duration = Duration::from_millis(50);

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
        let target = normalize_target_endpoint(target);
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
                let resolved_ips = self.resolver.resolve(&host).await?;
                if resolved_ips.is_empty() {
                    return Err(EngineError::Internal(format!(
                        "dns resolver returned no IPs for '{}'",
                        host
                    )));
                }
                let (ips, dropped_sinkhole) = filter_sinkhole_ips(resolved_ips);
                if dropped_sinkhole > 0 {
                    warn!(
                        target: "outbound.direct",
                        host = %host,
                        dropped = dropped_sinkhole,
                        "Dropped unspecified DNS sinkhole IPs before connect"
                    );
                }
                if ips.is_empty() {
                    return Err(EngineError::InvalidInput(format!(
                        "dns resolver returned only unspecified/sinkhole IPs for '{}'",
                        host
                    )));
                }
                let deduped = dedup_ips_preserve_order(ips);
                let ordered = happy_eyeballs_order(deduped);
                let attempts = ordered.len().min(Self::MAX_DOMAIN_IP_ATTEMPTS);
                let has_v4 = ordered.iter().any(IpAddr::is_ipv4);
                let has_v6 = ordered.iter().any(IpAddr::is_ipv6);
                info!(
                    target: "outbound.direct",
                    host = %host,
                    port = target.port,
                    resolved_ips = attempts,
                    has_ipv4 = has_v4,
                    has_ipv6 = has_v6,
                    fallback_delay_ms = Self::HAPPY_EYEBALLS_FALLBACK_DELAY.as_millis(),
                    "DNS resolved for direct outbound (happy-eyeballs ordering)"
                );
                self.connect_domain_happy_eyeballs(&target_label, target.port, ordered, attempts)
                    .await
            }
        }
    }

    async fn connect_domain_happy_eyeballs(
        &self,
        target_label: &str,
        port: u16,
        ordered_ips: Vec<IpAddr>,
        attempts: usize,
    ) -> Result<BoxStream> {
        let mut set = JoinSet::new();
        for (idx, ip) in ordered_ips.into_iter().take(attempts).enumerate() {
            let this = self.clone();
            let label = target_label.to_owned();
            let addr = SocketAddr::new(ip, port);
            set.spawn(async move {
                if idx > 0 {
                    tokio::time::sleep(
                        DirectOutbound::HAPPY_EYEBALLS_FALLBACK_DELAY.saturating_mul(idx as u32),
                    )
                    .await;
                }
                let res = this.connect_addr_with_timeout(&label, addr).await;
                (idx, addr, res)
            });
        }

        let mut last_err: Option<EngineError> = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((idx, addr, Ok(stream))) => {
                    set.abort_all();
                    if idx > 0 {
                        info!(
                            target: "outbound.direct",
                            destination = %target_label,
                            upstream = %addr,
                            attempt = idx + 1,
                            "Direct outbound connected after happy-eyeballs fallback"
                        );
                    }
                    return Ok(stream);
                }
                Ok((idx, addr, Err(e))) => {
                    let is_unreachable = if let EngineError::Io(ref io_err) = e {
                        io_err.raw_os_error() == Some(10051)
                    } else {
                        false
                    };

                    warn!(
                        target: "outbound.direct",
                        destination = %target_label,
                        upstream = %addr,
                        attempt = idx + 1,
                        unreachable = is_unreachable,
                        error = %e,
                        "Direct outbound attempt failed"
                    );
                    
                    last_err = Some(e);
                    
                    if is_unreachable {
                        // If network is unreachable (os error 10051), 
                        // we should ideally trigger the next attempt immediately if not already running.
                        // For now, just continue the loop; join_next will pick up other tasks.
                    }
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "happy-eyeballs task join error: {e}"
                    )));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            EngineError::Internal(format!(
                "no happy-eyeballs connect attempts were made for '{}'",
                target_label
            ))
        }))
    }

    async fn connect_addr_with_timeout(
        &self,
        target_label: &str,
        addr: std::net::SocketAddr,
    ) -> Result<BoxStream> {
        if is_unspecified_ip(addr.ip()) {
            return Err(EngineError::InvalidInput(format!(
                "direct connect target is unspecified/sinkhole IP: {addr}"
            )));
        }
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

fn normalize_target_endpoint(target: TargetEndpoint) -> TargetEndpoint {
    match target.addr {
        TargetAddr::Ip(ip) => TargetEndpoint {
            addr: TargetAddr::Ip(ip),
            port: target.port,
        },
        TargetAddr::Domain(host) => {
            let normalized_host = normalize_host_literal(&host);
            if let Ok(ip) = normalized_host.parse::<std::net::IpAddr>() {
                TargetEndpoint {
                    addr: TargetAddr::Ip(ip),
                    port: target.port,
                }
            } else {
                TargetEndpoint {
                    addr: TargetAddr::Domain(normalized_host),
                    port: target.port,
                }
            }
        }
    }
}

fn happy_eyeballs_order(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();
    for ip in ips {
        match ip {
            IpAddr::V6(_) => v6.push(ip),
            IpAddr::V4(_) => v4.push(ip),
        }
    }
    if v6.is_empty() || v4.is_empty() {
        let mut out = v6;
        out.extend(v4);
        return out;
    }

    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let mut idx6 = 0usize;
    let mut idx4 = 0usize;
    loop {
        let mut progressed = false;
        if idx6 < v6.len() {
            out.push(v6[idx6]);
            idx6 += 1;
            progressed = true;
        }
        if idx4 < v4.len() {
            out.push(v4[idx4]);
            idx4 += 1;
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    out
}

fn filter_sinkhole_ips(ips: Vec<IpAddr>) -> (Vec<IpAddr>, usize) {
    let mut out = Vec::with_capacity(ips.len());
    let mut dropped = 0usize;
    for ip in ips {
        // Drop unspecified (0.0.0.0) and loopback (127.0.0.1) IPs.
        // Public domains should never resolve to these unless the DNS is poisoned.
        if ip.is_unspecified() || ip.is_loopback() {
            dropped += 1;
            continue;
        }
        out.push(ip);
    }
    (out, dropped)
}

fn dedup_ips_preserve_order(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut seen = HashSet::with_capacity(ips.len());
    let mut out = Vec::with_capacity(ips.len());
    for ip in ips {
        if seen.insert(ip) {
            out.push(ip);
        }
    }
    out
}

fn is_unspecified_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_eyeballs_order_interleaves_v6_and_v4() {
        let ips = vec![
            "2001:db8::1".parse().expect("v6"),
            "2001:db8::2".parse().expect("v6"),
            "1.1.1.1".parse().expect("v4"),
            "8.8.8.8".parse().expect("v4"),
        ];
        let ordered = happy_eyeballs_order(ips);
        assert_eq!(ordered[0].to_string(), "2001:db8::1");
        assert_eq!(ordered[1].to_string(), "1.1.1.1");
        assert_eq!(ordered[2].to_string(), "2001:db8::2");
        assert_eq!(ordered[3].to_string(), "8.8.8.8");
    }

    #[test]
    fn happy_eyeballs_order_keeps_single_family_as_is() {
        let ips = vec![
            "8.8.8.8".parse().expect("v4"),
            "1.1.1.1".parse().expect("v4"),
        ];
        let ordered = happy_eyeballs_order(ips);
        assert_eq!(ordered.len(), 2);
        assert!(ordered.iter().all(IpAddr::is_ipv4));
        assert_eq!(ordered[0].to_string(), "8.8.8.8");
        assert_eq!(ordered[1].to_string(), "1.1.1.1");
    }

    #[test]
    fn filter_sinkhole_ips_drops_unspecified_v4_and_v6() {
        let ips = vec![
            "0.0.0.0".parse().expect("v4-unspecified"),
            "1.1.1.1".parse().expect("v4"),
            "::".parse().expect("v6-unspecified"),
            "2001:4860:4860::8888".parse().expect("v6"),
        ];
        let (filtered, dropped) = filter_sinkhole_ips(ips);
        assert_eq!(dropped, 2);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].to_string(), "1.1.1.1");
        assert_eq!(filtered[1].to_string(), "2001:4860:4860::8888");
    }

    #[test]
    fn dedup_ips_preserve_order_removes_duplicates() {
        let ips = vec![
            "1.1.1.1".parse().expect("v4"),
            "2001:db8::1".parse().expect("v6"),
            "1.1.1.1".parse().expect("v4-dup"),
            "2001:db8::1".parse().expect("v6-dup"),
            "8.8.8.8".parse().expect("v4-second"),
        ];
        let deduped = dedup_ips_preserve_order(ips);
        assert_eq!(deduped.len(), 3);
        assert_eq!(deduped[0].to_string(), "1.1.1.1");
        assert_eq!(deduped[1].to_string(), "2001:db8::1");
        assert_eq!(deduped[2].to_string(), "8.8.8.8");
    }
}
