use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::anticensorship::ResolverChain;
use crate::error::{EngineError, Result};
use crate::platform::ttl::set_socket_ttl_low;

use super::{BoxStream, OutboundConnector, TargetAddr, TargetEndpoint};

#[derive(Debug, Clone)]
pub struct DirectOutbound {
    resolver: Arc<ResolverChain>,
    first_packet_ttl: u8,
    upstream_socks5: Option<SocketAddr>,
    /// When set, outgoing TCP sockets are bound to this local IP before connecting.
    ///
    /// Used in TUN mode to prevent outgoing relay connections from being re-captured
    /// by TUN routes: binding to the physical NIC IP forces the OS to route the
    /// socket through the physical interface, bypassing TUN routing rules.
    bypass_bind_ip: Option<std::net::IpAddr>,
}

impl DirectOutbound {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const MAX_DOMAIN_IP_ATTEMPTS: usize = 8;
    const HAPPY_EYEBALLS_FALLBACK_DELAY: Duration = Duration::from_millis(50);

    pub fn new(resolver: Arc<ResolverChain>) -> Self {
        Self {
            resolver,
            first_packet_ttl: 0,
            upstream_socks5: None,
            bypass_bind_ip: None,
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

    /// Bind outgoing sockets to this local IP to bypass TUN routing in VPN mode.
    pub fn with_bypass_bind_ip(mut self, ip: Option<std::net::IpAddr>) -> Self {
        self.bypass_bind_ip = ip;
        self
    }

    pub fn resolver(&self) -> Arc<ResolverChain> {
        self.resolver.clone()
    }

    /// Resolve `target` to a single [`SocketAddr`] for probing or raw-socket operations.
    ///
    /// Returns the first usable IP from DNS for domain targets, or the literal IP.
    pub async fn resolve_target_ip(&self, target: &TargetEndpoint) -> Result<SocketAddr> {
        let target = normalize_target_endpoint(target.clone());
        match target.addr {
            TargetAddr::Ip(ip) => Ok(SocketAddr::new(ip, target.port)),
            TargetAddr::Domain(ref host) => {
                let ips = self.resolver.resolve(host).await?;
                let (ips, _) = filter_sinkhole_ips(ips);
                ips.into_iter()
                    .next()
                    .map(|ip| SocketAddr::new(ip, target.port))
                    .ok_or_else(|| EngineError::Internal(format!("no usable IPs for '{}'", host)))
            }
        }
    }

    /// Connect to `target` and return a raw [`TcpStream`] without boxing.
    ///
    /// Used by Native bypass routes that need direct socket access for OOB byte
    /// injection.  Performs DNS resolution and tries up to 4 IPs in happy-eyeballs
    /// order before giving up.
    pub async fn connect_tcp_stream(&self, target: TargetEndpoint) -> Result<TcpStream> {
        let target = normalize_target_endpoint(target);
        match target.addr {
            TargetAddr::Ip(ip) => {
                let addr = SocketAddr::new(ip, target.port);
                self.connect_addr_tcp(addr).await
            }
            TargetAddr::Domain(ref host) => {
                let ips = self.resolver.resolve(host).await?;
                let (ips, _) = filter_sinkhole_ips(ips);
                if ips.is_empty() {
                    return Err(EngineError::Internal(format!(
                        "no usable IPs for '{}'",
                        host
                    )));
                }
                let ordered = happy_eyeballs_order(dedup_ips_preserve_order(ips));
                let mut last_err: Option<EngineError> = None;
                for ip in ordered.into_iter().take(4) {
                    let addr = SocketAddr::new(ip, target.port);
                    match self.connect_addr_tcp(addr).await {
                        Ok(tcp) => return Ok(tcp),
                        Err(e) => last_err = Some(e),
                    }
                }
                Err(last_err.unwrap_or_else(|| {
                    EngineError::Internal(format!("native connect failed for '{}'", host))
                }))
            }
        }
    }

    /// Connect to `addr` and return a raw [`TcpStream`] (no boxing, no happy-eyeballs).
    async fn connect_addr_tcp(&self, addr: SocketAddr) -> Result<TcpStream> {
        if is_unspecified_ip(addr.ip()) {
            return Err(EngineError::InvalidInput(format!(
                "native connect target is unspecified/sinkhole IP: {addr}"
            )));
        }
        let connect_fut = async {
            if let Some(local_ip) = self.bypass_bind_ip {
                // Bind to the physical NIC IP so the OS routes this socket through
                // the real interface, not the TUN device (prevents VPN routing loop).
                let socket = if addr.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()?
                } else {
                    tokio::net::TcpSocket::new_v6()?
                };
                socket.bind(SocketAddr::new(local_ip, 0))?;
                socket.connect(addr).await
            } else {
                TcpStream::connect(addr).await
            }
        };
        let tcp = match tokio::time::timeout(Self::CONNECT_TIMEOUT, connect_fut).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                return Err(EngineError::Internal(format!(
                    "native connect timeout after {}ms for {addr}",
                    Self::CONNECT_TIMEOUT.as_millis()
                )))
            }
        };
        let _ = tcp.set_nodelay(true);
        if should_apply_low_ttl(addr.ip(), self.first_packet_ttl) {
            let _ = set_socket_ttl_low(&tcp, self.first_packet_ttl);
        }
        Ok(tcp)
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
                debug!(
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
                        debug!(
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
                    let is_noise_probe = is_noise_probe_destination(target_label);
                    if is_noise_probe && is_unreachable {
                        debug!(
                            target: "outbound.direct",
                            destination = %target_label,
                            upstream = %addr,
                            attempt = idx + 1,
                            unreachable = is_unreachable,
                            error = %e,
                            "Direct outbound probe attempt failed (expected in IPv6-offline environments)"
                        );
                    } else if is_noise_probe {
                        debug!(
                            target: "outbound.direct",
                            destination = %target_label,
                            upstream = %addr,
                            attempt = idx + 1,
                            unreachable = is_unreachable,
                            error = %e,
                            "Direct outbound probe attempt failed"
                        );
                    } else {
                        warn!(
                            target: "outbound.direct",
                            destination = %target_label,
                            upstream = %addr,
                            attempt = idx + 1,
                            unreachable = is_unreachable,
                            error = %e,
                            "Direct outbound attempt failed"
                        );
                    }

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
        debug!(target: "outbound.direct", destination = %target_label, upstream = %addr, "Direct outbound connect");
        let connect_fut = async {
            if let Some(local_ip) = self.bypass_bind_ip {
                let socket = if addr.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()?
                } else {
                    tokio::net::TcpSocket::new_v6()?
                };
                socket.bind(SocketAddr::new(local_ip, 0))?;
                socket.connect(addr).await
            } else {
                TcpStream::connect(addr).await
            }
        };
        let connect = tokio::time::timeout(Self::CONNECT_TIMEOUT, connect_fut).await;
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
        if should_apply_low_ttl(addr.ip(), self.first_packet_ttl) {
            let _ = set_socket_ttl_low(&tcp, self.first_packet_ttl);
        }
        debug!(target: "outbound.direct", destination = %target_label, upstream = %addr, "Direct outbound connected");
        Ok(Box::new(tcp))
    }

    async fn connect_via_socks5_with_timeout(
        &self,
        target_label: &str,
        target: &TargetEndpoint,
        proxy_addr: SocketAddr,
    ) -> Result<BoxStream> {
        debug!(
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

        debug!(
            target: "outbound.direct",
            destination = %target_label,
            upstream_socks5 = %proxy_addr,
            "Direct outbound connected via upstream SOCKS5"
        );
        Ok(Box::new(tcp))
    }
}

fn is_noise_probe_destination(target_label: &str) -> bool {
    let host = target_label
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(target_label)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    host.contains("msftconnecttest")
        || host.contains("msftncsi")
        || host.contains("connectivitycheck")
        || host.contains("captive")
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

fn should_apply_low_ttl(ip: IpAddr, ttl: u8) -> bool {
    if ttl == 0 {
        return false;
    }
    if ttl >= 32 {
        // Non-aggressive TTL values are generally safe for all destinations.
        return true;
    }
    // Low TTL (<32) is for DPI evasion — only apply to public IPs where DPI
    // middleboxes operate.  Skip private/loopback/link-local where low TTL
    // would just break connectivity.
    match ip {
        IpAddr::V4(v4) => !(v4.is_private() || v4.is_loopback() || v4.is_link_local()),
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()),
    }
}

impl OutboundConnector for DirectOutbound {
    fn connect<'a>(
        &'a self,
        target: TargetEndpoint,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<BoxStream>> + Send + 'a>> {
        Box::pin(async move { self.connect_impl(target).await })
    }

    fn resolver(&self) -> Option<Arc<crate::anticensorship::ResolverChain>> {
        Some(self.resolver.clone())
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

    #[test]
    fn low_ttl_is_applied_to_public_ip_for_dpi_evasion() {
        let ip: IpAddr = "8.8.8.8".parse().expect("ip");
        assert!(should_apply_low_ttl(ip, 3));
    }

    #[test]
    fn low_ttl_is_not_applied_to_private_ip() {
        let ip: IpAddr = "192.168.1.10".parse().expect("ip");
        assert!(!should_apply_low_ttl(ip, 3));
    }

    #[test]
    fn non_aggressive_ttl_is_applied_even_for_public_ip() {
        let ip: IpAddr = "8.8.8.8".parse().expect("ip");
        assert!(should_apply_low_ttl(ip, 64));
    }
}
