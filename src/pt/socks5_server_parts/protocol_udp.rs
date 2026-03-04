use std::net::{SocketAddr, IpAddr};
use tokio::net::{UdpSocket, TcpStream};
use tokio::io::AsyncReadExt;
use std::sync::Arc;
use tracing::debug;

use crate::error::Result;
use crate::anticensorship::ResolverChain;
use crate::pt::socks5_server::route_scoring::route_destination_key;

pub async fn handle_udp_associate(
    conn_id: u64,
    mut tcp: TcpStream,
    _client_addr: SocketAddr,
    resolver: Arc<ResolverChain>,
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
    let mut remote_to_target = std::collections::HashMap::new();

    let mut tcp_buf = [0u8; 1];

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
                            match handle_client_to_remote(conn_id, &udp_send, &buf[..n], &resolver).await {
                                Ok(Some(target_addr)) => {
                                    remote_to_target.insert(target_addr, target_addr);
                                }
                                Err(e) => {
                                    debug!(conn_id, error = %e, "UDP client->remote relay failed");
                                }
                                _ => {}
                            }
                        } else {
                            // Packet from remote -> client
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
            _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {
                debug!(conn_id, "UDP relay idle timeout");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_client_to_remote(
    conn_id: u64,
    socket: &UdpSocket,
    data: &[u8],
    resolver: &ResolverChain,
) -> std::io::Result<Option<SocketAddr>> {
    if data.len() < 4 { return Ok(None); }
    let frag = data[2];
    if frag != 0 { return Ok(None); } 

    let atyp = data[3];
    let (target_addr, header_len) = match atyp {
        0x01 => {
            if data.len() < 10 { return Ok(None); }
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            
            if port == 443 && is_likely_google_ip(addr.ip()) {
                debug!(conn_id, "blocking QUIC to IP {} for fallback", addr.ip());
                return Ok(None);
            }
            (addr, 10)
        }
        0x03 => {
            let len = data[4] as usize;
            if data.len() < 5 + len + 2 { return Ok(None); }
            let domain = String::from_utf8_lossy(&data[5..5 + len]);
            let port = u16::from_be_bytes([data[5 + len], data[5 + len + 1]]);
            
            if port == 443 {
                let key = route_destination_key(&domain);
                if key == "googlevideo.com" || key == "ytimg.com" || domain.contains("google") || domain.contains("youtube") {
                    debug!(conn_id, "blocking QUIC to domain {} for fallback", domain);
                    return Ok(None);
                }
            }

            // ANTI-LEAK: Use encrypted resolver instead of system lookup_host
            match resolver.resolve(&domain).await {
                Ok(ips) => {
                    if let Some(ip) = ips.first() {
                        (SocketAddr::new(*ip, port), 5 + len + 2)
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
            if data.len() < 22 { return Ok(None); }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            let port = u16::from_be_bytes([data[20], data[21]]);
            let addr = SocketAddr::new(std::net::IpAddr::V6(ip_bytes.into()), port);
            
            if port == 443 && is_likely_google_ip(addr.ip()) {
                debug!(conn_id, "blocking QUIC to IPv6 {} for fallback", addr.ip());
                return Ok(None);
            }
            (addr, 22)
        }
        _ => return Ok(None),
    };

    let payload = &data[header_len..];
    socket.send_to(payload, target_addr).await?;
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

fn is_likely_google_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 8 && octets[1] == 8 || 
            octets[0] == 142 && octets[1] == 250 ||
            octets[0] == 172 && octets[1] == 217 ||
            octets[0] == 216 && octets[1] == 58
        }
        _ => false,
    }
}