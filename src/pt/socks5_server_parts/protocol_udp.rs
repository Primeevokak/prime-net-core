use std::net::SocketAddr;
use tokio::net::{UdpSocket, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tracing::debug;

use crate::error::Result;

pub async fn handle_udp_associate(
    conn_id: u64,
    mut tcp: TcpStream,
    _client_addr: SocketAddr,
) -> Result<()> {
    // 1. Bind a local UDP socket for the relay
    // We bind to the same interface as the TCP connection
    let local_addr = tcp.local_addr()?;
    let udp_socket = UdpSocket::bind(SocketAddr::new(local_addr.ip(), 0)).await?;
    let udp_local_addr = udp_socket.local_addr()?;

    debug!(conn_id, "UDP relay bound to {}", udp_local_addr);

    // 2. Respond to the client with the UDP relay address
    // Reply format: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    match udp_local_addr.ip() {
        std::net::IpAddr::V4(ip) => reply.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(ip) => {
            reply[3] = 0x04; // ATYP IPv6
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&udp_local_addr.port().to_be_bytes());
    tcp.write_all(&reply).await?;

    // 3. Start the UDP relay loop
    // SOCKS5 spec: the UDP relay should stay active as long as the TCP connection is open.
    let (mut tcp_read, _tcp_write) = tcp.into_split();
    let udp_arc = Arc::new(udp_socket);
    
    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();

    // Task to monitor the TCP connection. If it closes, the UDP relay should stop.
    let tcp_monitor = tokio::spawn(async move {
        let mut buf = [0u8; 1];
        let _ = tcp_read.read(&mut buf).await;
        debug!(conn_id, "SOCKS5 TCP connection closed, shutting down UDP relay");
    });

    // Task to relay UDP packets from client to remote and vice-versa
    let relay_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let mut client_source_addr: Option<SocketAddr> = None;

        loop {
            tokio::select! {
                res = udp_recv.recv_from(&mut buf) => {
                    match res {
                        Ok((n, src)) => {
                            // First packet from client defines the client's UDP source address
                            if client_source_addr.is_none() {
                                client_source_addr = Some(src);
                            }

                            if Some(src) == client_source_addr {
                                // Packet from client -> remote
                                if let Err(e) = handle_client_to_remote(conn_id, &udp_send, &buf[..n]).await {
                                    debug!(conn_id, error = %e, "UDP client->remote relay failed");
                                }
                            } else {
                                // Packet from remote -> client
                                // We don't know which remote it is yet, the SOCKS5 UDP encapsulation 
                                // tells us where it's from.
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    // Timeout if no activity
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = tcp_monitor => {},
        _ = relay_task => {},
    }

    Ok(())
}

use crate::pt::socks5_server::route_scoring::route_destination_key;

async fn handle_client_to_remote(
    conn_id: u64,
    socket: &UdpSocket,
    data: &[u8],
) -> std::io::Result<()> {
    if data.len() < 4 { return Ok(()); }
    // SOCKS5 UDP Encapsulation: [RSV, FRAG, ATYP, DST.ADDR, DST.PORT, DATA]
    let frag = data[2];
    if frag != 0 { return Ok(()); } // We don't support fragmentation in this simple relay

    let atyp = data[3];
    let (target_addr, header_len) = match atyp {
        0x01 => {
            if data.len() < 10 { return Ok(()); }
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            
            // BLOCK QUIC (UDP 443) for Google/YouTube IPs
            if port == 443 && is_likely_google_ip(addr.ip()) {
                debug!(conn_id, "blocking QUIC to IP {} for fallback", addr.ip());
                return Ok(());
            }
            (addr, 10)
        }
        0x03 => {
            let len = data[4] as usize;
            if data.len() < 5 + len + 2 { return Ok(()); }
            let domain = String::from_utf8_lossy(&data[5..5 + len]);
            let port = u16::from_be_bytes([data[5 + len], data[5 + len + 1]]);
            
            // BLOCK QUIC (UDP 443) for YouTube domains
            if port == 443 {
                let key = route_destination_key(&domain);
                if key == "googlevideo.com" || key == "ytimg.com" || domain.contains("google") || domain.contains("youtube") {
                    debug!(conn_id, "blocking QUIC to domain {} for fallback", domain);
                    return Ok(());
                }
            }

            // Resolve domain for UDP relay
            match tokio::net::lookup_host(format!("{}:{}", domain, port)).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        (addr, 5 + len + 2)
                    } else {
                        return Ok(());
                    }
                }
                Err(_) => return Ok(()),
            }
        }
        0x04 => {
            if data.len() < 22 { return Ok(()); }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            let port = u16::from_be_bytes([data[20], data[21]]);
            let addr = SocketAddr::new(std::net::IpAddr::V6(ip_bytes.into()), port);
            
            if port == 443 && is_likely_google_ip(addr.ip()) {
                debug!(conn_id, "blocking QUIC to IPv6 {} for fallback", addr.ip());
                return Ok(());
            }
            (addr, 22)
        }
        _ => return Ok(()),
    };

    // --- UDP RELAY ---
    let payload = &data[header_len..];
    socket.send_to(payload, target_addr).await?;
    Ok(())
}

fn is_likely_google_ip(ip: std::net::IpAddr) -> bool {
    // Simple heuristic for common Google/YouTube ranges if resolution fails or for IP-only clients.
    // In a real scenario, this could be a subnet check.
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Google Public DNS / common ranges
            octets[0] == 8 && octets[1] == 8 || 
            octets[0] == 142 && octets[1] == 250 ||
            octets[0] == 172 && octets[1] == 217 ||
            octets[0] == 216 && octets[1] == 58
        }
        _ => false,
    }
}
