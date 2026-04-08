use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::anticensorship::ResolverChain;
use crate::config::EngineConfig;
use crate::error::Result;
use crate::evasion::quic_initial::{
    parse_quic_initial_header, random_whitelisted_sni, send_fake_quic_initial,
};
use crate::pt::socks5_server::route_scoring::{
    is_censored_domain, is_quic_silent_drop_cached, record_quic_silent_drop,
};
use crate::pt::socks5_server::state_and_startup::RelayOptions;

/// IP TTL for fake QUIC Initial probes (should expire before reaching the server).
const FAKE_QUIC_TTL: u8 = 3;

/// Number of fake UDP packets to send before real Discord voice data.
const DISCORD_FAKE_COUNT: u8 = 6;

/// Check if a UDP port is in the Discord voice/STUN range.
fn is_discord_voice_port(port: u16) -> bool {
    (19294..=19344).contains(&port) || (50000..=50100).contains(&port)
}

pub async fn handle_udp_associate(
    conn_id: u64,
    mut tcp: TcpStream,
    _client_addr: SocketAddr,
    resolver: Arc<ResolverChain>,
    cfg: Arc<EngineConfig>,
    relay_opts: RelayOptions,
) -> Result<()> {
    // 1. Bind a local UDP socket for the relay
    let local_addr = tcp.local_addr()?;
    let udp_socket = UdpSocket::bind(SocketAddr::new(local_addr.ip(), 0)).await?;
    let udp_local_addr = udp_socket.local_addr()?;

    debug!(conn_id, "UDP relay bound to {}", udp_local_addr);

    // 2. Respond to the client with the UDP relay address
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    match udp_local_addr.ip() {
        IpAddr::V4(ip) => reply.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => {
            reply[3] = 0x04;
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&udp_local_addr.port().to_be_bytes());
    use tokio::io::AsyncWriteExt;
    tcp.write_all(&reply).await?;

    // 3. Start the UDP relay loop
    let (mut tcp_read, _tcp_write) = tcp.into_split();
    let udp_arc = Arc::new(udp_socket);

    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();

    let mut buf = vec![0u8; 65535];
    let mut client_source_addr: Option<SocketAddr> = None;
    let mut remote_to_target = HashMap::new();

    let mut tcp_buf = [0u8; 1];

    // QUIC silent-drop probe state (all owned by this task — no shared state, no race).
    // Key: "domain:443", Value: Instant when the probe packet was sent.
    let mut quic_pending: HashMap<String, tokio::time::Instant> = HashMap::new();
    // Maps resolved SocketAddr → list of pending cache keys.
    // Vec because multiple domains can resolve to the same IP (CDN/Cloudflare).
    let mut addr_to_domain: HashMap<SocketAddr, Vec<String>> = HashMap::new();
    let mut probe_check = tokio::time::interval(std::time::Duration::from_secs(1));
    // Idle timeout created once outside the loop so it tracks real elapsed idle time.
    let idle_timeout = tokio::time::sleep(std::time::Duration::from_secs(300));
    tokio::pin!(idle_timeout);

    loop {
        tokio::select! {
            // Monitor TCP connection for closure
            tcp_res = tcp_read.read(&mut tcp_buf) => {
                match tcp_res {
                    Ok(0) | Err(_) => {
                        debug!(conn_id, "SOCKS5 TCP connection closed, shutting down UDP relay");
                        break;
                    }
                    _ => {}
                }
            }
            // Relay packets
            udp_res = udp_recv.recv_from(&mut buf) => {
                match udp_res {
                    Ok((n, src)) => {
                        if client_source_addr.is_none() {
                            client_source_addr = Some(src);
                        }

                        if Some(src) == client_source_addr {
                            // Packet from client -> remote
                            match handle_client_to_remote(
                                conn_id,
                                &udp_send,
                                &buf[..n],
                                &resolver,
                                &cfg,
                                &relay_opts,
                                &mut quic_pending,
                                &mut addr_to_domain,
                            ).await {
                                Ok(Some(target_addr)) => {
                                    // Cap the map to prevent memory growth during long UDP sessions.
                                    if remote_to_target.len() < 1024 {
                                        remote_to_target.insert(target_addr, target_addr);
                                    }
                                }
                                Err(e) => {
                                    debug!(conn_id, error = %e, "UDP client->remote relay failed");
                                }
                                _ => {}
                            }
                        } else {
                            // Packet from remote -> client
                            if cfg.evasion.quic_probe_timeout_ms > 0 {
                                if let Some(keys) = addr_to_domain.remove(&src) {
                                    for domain_key in &keys {
                                        quic_pending.remove(domain_key);
                                    }
                                    debug!(
                                        conn_id,
                                        keys = ?keys,
                                        "QUIC probe resolved: response received, cleared {} pending probe(s)",
                                        keys.len()
                                    );
                                }
                            }
                            if let Some(target) = remote_to_target.get(&src) {
                                if let Some(client_addr) = client_source_addr {
                                    if let Err(e) = send_to_client(conn_id, &udp_send, client_addr, target, &buf[..n]).await {
                                        debug!(conn_id, error = %e, "UDP remote->client relay failed");
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            // Check for expired QUIC probes (silent-drop detection)
            _ = probe_check.tick(), if cfg.evasion.quic_probe_timeout_ms > 0 => {
                let timeout = std::time::Duration::from_millis(cfg.evasion.quic_probe_timeout_ms);
                let mut stale_keys: Vec<String> = Vec::new();
                quic_pending.retain(|key, started_at| {
                    if started_at.elapsed() > timeout {
                        debug!(conn_id, key = %key, "QUIC probe expired → silent drop");
                        record_quic_silent_drop(key);
                        stale_keys.push(key.clone());
                        false
                    } else {
                        true
                    }
                });
                addr_to_domain.retain(|_, keys| {
                    keys.retain(|k| !stale_keys.contains(k));
                    !keys.is_empty()
                });
            }
            _ = &mut idle_timeout => {
                debug!(conn_id, "UDP relay idle timeout");
                break;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_client_to_remote(
    conn_id: u64,
    socket: &UdpSocket,
    data: &[u8],
    resolver: &ResolverChain,
    cfg: &EngineConfig,
    relay_opts: &RelayOptions,
    quic_pending: &mut HashMap<String, tokio::time::Instant>,
    addr_to_domain: &mut HashMap<SocketAddr, Vec<String>>,
) -> std::io::Result<Option<SocketAddr>> {
    if data.len() < 4 {
        return Ok(None);
    }
    let frag = data[2];
    if frag != 0 {
        return Ok(None);
    }

    // Probe state owned by relay loop — registered AFTER successful send to avoid
    // false positives if send_to fails.
    let mut probe_hint: Option<(String, SocketAddr)> = None;

    let atyp = data[3];
    let (target_addr, header_len) = match atyp {
        0x01 => {
            if data.len() < 10 {
                return Ok(None);
            }
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            // Without a domain name we cannot determine whether the destination is
            // censored, so we let the packet through and accept a possible RST.
            (addr, 10)
        }
        0x03 => {
            let len = data[4] as usize;
            if data.len() < 5 + len + 2 {
                return Ok(None);
            }
            let domain = String::from_utf8_lossy(&data[5..5 + len]);
            let port = u16::from_be_bytes([data[5 + len], data[5 + len + 1]]);

            // For censored domains on port 443:
            // - With native evasion active: let the packet through; the QUIC
            //   Initial desync (fake Initial injection below) handles evasion.
            // - Without native evasion: hard-block so the client falls back to
            //   TCP where Bypass profiles handle it.
            if port == 443 && is_censored_domain(&domain, relay_opts, cfg) {
                if relay_opts.native_bypass.is_none() {
                    debug!(
                        conn_id,
                        "blocking QUIC to censored domain {} — no native bypass, forcing TCP fallback",
                        domain
                    );
                    return Ok(None);
                }
                debug!(
                    conn_id,
                    domain = %domain,
                    "censored domain with native bypass: applying QUIC Initial desync"
                );
            }

            let cache_key = format!("{domain}:443");
            if port == 443
                && cfg.evasion.quic_probe_timeout_ms > 0
                && is_quic_silent_drop_cached(&cache_key)
            {
                debug!(
                    conn_id,
                    domain = %domain,
                    "QUIC silent-drop cache hit: blocking UDP → TCP fallback"
                );
                return Ok(None);
            }

            // ANTI-LEAK: Use encrypted resolver instead of system lookup_host
            match resolver.resolve(&domain).await {
                Ok(ips) => {
                    if let Some(ip) = ips.first() {
                        let resolved_addr = SocketAddr::new(*ip, port);
                        if port == 443 && cfg.evasion.quic_probe_timeout_ms > 0 {
                            probe_hint = Some((cache_key, resolved_addr));
                        }
                        (resolved_addr, 5 + len + 2)
                    } else {
                        return Ok(None);
                    }
                }
                Err(e) => {
                    debug!(conn_id, domain = %domain, error = %e, "UDP relay DNS resolution failed");
                    return Ok(None);
                }
            }
        }
        0x04 => {
            if data.len() < 22 {
                return Ok(None);
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            let port = u16::from_be_bytes([data[20], data[21]]);
            let addr = SocketAddr::new(std::net::IpAddr::V6(ip_bytes.into()), port);
            // Same reasoning as IPv4: no domain available, pass through.
            (addr, 22)
        }
        _ => return Ok(None),
    };

    let payload = &data[header_len..];

    // Discord voice/STUN: inject fake UDP packets before the real data.
    // Discord uses ports 19294-19344 and 50000-50100 for voice.  DPI that
    // fingerprints Discord voice traffic by port range and packet structure
    // gets confused by the fakes.
    if is_discord_voice_port(target_addr.port()) && relay_opts.native_bypass.is_some() {
        let target = target_addr;
        let pkt_len = payload.len();
        // Pre-generate all fakes to avoid holding non-Send ThreadRng across await.
        let fakes: Vec<Vec<u8>> = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            (0..DISCORD_FAKE_COUNT)
                .map(|_| {
                    let mut fake = vec![0u8; pkt_len];
                    rng.fill(&mut fake[..]);
                    fake
                })
                .collect()
        };
        tokio::spawn(async move {
            for fake in &fakes {
                if let Ok(sock) = crate::evasion::quic_initial::bind_udp_for_target(target).await {
                    let _ = sock.set_ttl(3);
                    let _ = sock.send_to(fake, target).await;
                }
            }
        });
    }

    // QUIC Initial desync: for port-443 UDP, inject a fake Initial with a
    // decoy SNI before forwarding the real packet.  The fake uses the same DCID
    // so DPI derives the same keys and parses the fake's CRYPTO frame, recording
    // the decoy SNI.  The real packet follows immediately; DPI state is confused.
    // This replaces the hard block for censored domains with an active bypass.
    if target_addr.port() == 443 && relay_opts.native_bypass.is_some() {
        if let Some(hdr) = parse_quic_initial_header(payload) {
            // Inject multiple fake QUIC Initials with diverse whitelisted SNIs.
            // zapret sends 6-11 copies; we use the configured repeat count (default 8).
            let repeat = cfg.evasion.quic_fake_repeat_count.max(1);
            let target = target_addr;
            let dcid = hdr.dcid.clone();
            tokio::spawn(async move {
                for _ in 0..repeat {
                    let sni = random_whitelisted_sni();
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        send_fake_quic_initial(target, &dcid, sni, FAKE_QUIC_TTL),
                    )
                    .await;
                }
            });
        }
    }

    // Optional UDP padding for QUIC packets (defeats size-based DPI fingerprinting).
    let padding = cfg.evasion.quic_udp_padding_bytes;
    if target_addr.port() == 443 && padding > 0 {
        let mut padded = Vec::with_capacity(payload.len() + padding as usize);
        padded.extend_from_slice(payload);
        padded.resize(padded.len() + padding as usize, 0);
        socket.send_to(&padded, target_addr).await?;
    } else {
        socket.send_to(payload, target_addr).await?;
    }

    // Register the probe only after a successful send — avoids false silent-drop
    // classification if the local send itself fails.
    if let Some((key, resolved_addr)) = probe_hint {
        if !quic_pending.contains_key(&key) {
            quic_pending.insert(key.clone(), tokio::time::Instant::now());
            addr_to_domain.entry(resolved_addr).or_default().push(key);
        }
    }

    Ok(Some(target_addr))
}

async fn send_to_client(
    _conn_id: u64,
    socket: &UdpSocket,
    client_addr: SocketAddr,
    remote_addr: &SocketAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut reply = vec![0x00, 0x00, 0x00];
    match remote_addr.ip() {
        IpAddr::V4(ip) => {
            reply.push(0x01);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(0x04);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&remote_addr.port().to_be_bytes());
    reply.extend_from_slice(payload);

    socket.send_to(&reply, client_addr).await?;
    Ok(())
}

#[cfg(test)]
mod quic_silent_drop_tests {
    use crate::pt::socks5_server::route_scoring::{
        is_quic_silent_drop_cached, record_quic_silent_drop, QUIC_SILENT_DROP_TTL_SECS,
    };
    use crate::pt::socks5_server::{now_unix_secs, routing_state};

    #[test]
    fn quic_silent_drop_absent_returns_false() {
        let key = "absent-quic-test.invalid:443";
        routing_state().quic_silent_drop_cache.remove(key);
        assert!(!is_quic_silent_drop_cached(key));
    }

    #[test]
    fn quic_silent_drop_present_returns_true() {
        let key = "present-quic-test.invalid:443";
        record_quic_silent_drop(key);
        assert!(is_quic_silent_drop_cached(key));
        routing_state().quic_silent_drop_cache.remove(key);
    }

    #[test]
    fn quic_silent_drop_expired_returns_false() {
        let key = "expired-quic-test.invalid:443";
        routing_state().quic_silent_drop_cache.insert(
            key.to_owned(),
            now_unix_secs().saturating_sub(QUIC_SILENT_DROP_TTL_SECS + 1),
        );
        assert!(!is_quic_silent_drop_cached(key));
        routing_state().quic_silent_drop_cache.remove(key);
    }

    #[test]
    fn addr_to_domain_collision_both_keys_cleared_on_response() {
        // Simulates two domains resolving to the same IP.
        use std::collections::HashMap;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let shared_ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let mut addr_to_domain: HashMap<SocketAddr, Vec<String>> = HashMap::new();
        let mut quic_pending: HashMap<String, tokio::time::Instant> = HashMap::new();

        // Register two domains to the same IP
        let key1 = "domain-a.example:443".to_owned();
        let key2 = "domain-b.example:443".to_owned();

        quic_pending.insert(key1.clone(), tokio::time::Instant::now());
        addr_to_domain
            .entry(shared_ip)
            .or_default()
            .push(key1.clone());

        quic_pending.insert(key2.clone(), tokio::time::Instant::now());
        addr_to_domain
            .entry(shared_ip)
            .or_default()
            .push(key2.clone());

        assert_eq!(addr_to_domain[&shared_ip].len(), 2);

        // Simulate response from shared IP
        if let Some(keys) = addr_to_domain.remove(&shared_ip) {
            for k in &keys {
                quic_pending.remove(k);
            }
        }

        // Both probes must be cleared — no false silent drop for either domain
        assert!(
            quic_pending.is_empty(),
            "both probes must be cleared on response"
        );
        assert!(addr_to_domain.is_empty());
    }
}
