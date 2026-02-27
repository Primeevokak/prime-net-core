use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::Stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::error::{EngineError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpTargetAddr {
    Socket(SocketAddr),
    Domain { host: String, port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub addr: UdpTargetAddr,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UdpOverTcpConfig {
    /// Maximum datagram payload size accepted from the remote side (best-effort safety limit).
    pub max_datagram_size: usize,
}

impl Default for UdpOverTcpConfig {
    fn default() -> Self {
        Self {
            max_datagram_size: 64 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct UdpOverTcpTunnel {
    write_tx: mpsc::Sender<OutboundWrite>,
    rx: mpsc::Receiver<Result<UdpDatagram>>,
    stop_tx: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for UdpOverTcpTunnel {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

impl Stream for UdpOverTcpTunnel {
    type Item = Result<UdpDatagram>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.rx).poll_recv(cx)
    }
}

impl UdpOverTcpTunnel {
    const SEND_QUEUE_CAPACITY: usize = 512;
    const SEND_ACK_TIMEOUT: Duration = Duration::from_secs(10);

    /// Connects to a UDP relay that speaks the engine's simple UDP-over-TCP framing protocol.
    pub async fn connect(addr: SocketAddr, cfg: UdpOverTcpConfig) -> Result<Self> {
        let tcp = TcpStream::connect(addr).await?;
        let _ = tcp.set_nodelay(true);
        let (mut rd, mut wr) = tcp.into_split();

        let (tx, rx) = mpsc::channel::<Result<UdpDatagram>>(256);
        let (write_tx, mut write_rx) = mpsc::channel::<OutboundWrite>(Self::SEND_QUEUE_CAPACITY);
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop_rx => return,
                    maybe_msg = write_rx.recv() => {
                        let Some(msg) = maybe_msg else {
                            return;
                        };
                        let res = write_datagram(&mut wr, msg.addr, &msg.data).await;
                        let _ = msg.ack.send(res.map_err(EngineError::from));
                    }
                    read_res = read_datagram(&mut rd, cfg.max_datagram_size) => {
                        match read_res {
                            Ok(datagram) => {
                                if tx.send(Ok(datagram)).await.is_err() {
                                    return;
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(e)).await;
                                return;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            write_tx,
            rx,
            stop_tx: Some(stop_tx),
            join: Some(join),
        })
    }

    /// Sends a datagram to `addr` through the tunnel.
    pub async fn send_to(&self, addr: UdpTargetAddr, data: &[u8]) -> Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(EngineError::InvalidInput(
                "udp tunnel datagram exceeds 65535 bytes".to_owned(),
            ));
        }
        let (ack_tx, ack_rx) = oneshot::channel();
        let req = OutboundWrite {
            addr,
            data: data.to_vec(),
            ack: ack_tx,
        };
        self.write_tx.try_send(req).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => EngineError::Internal(
                "udp tunnel send queue is full; datagram dropped".to_owned(),
            ),
            mpsc::error::TrySendError::Closed(_) => {
                EngineError::Internal("udp tunnel is closed".to_owned())
            }
        })?;
        let ack = tokio::time::timeout(Self::SEND_ACK_TIMEOUT, ack_rx)
            .await
            .map_err(|_| EngineError::Internal("udp tunnel send timeout".to_owned()))?;
        ack.map_err(|_| EngineError::Internal("udp tunnel send worker stopped".to_owned()))?
    }
}

struct OutboundWrite {
    addr: UdpTargetAddr,
    data: Vec<u8>,
    ack: oneshot::Sender<Result<()>>,
}

async fn read_datagram(
    rd: &mut tokio::net::tcp::OwnedReadHalf,
    max_datagram_size: usize,
) -> Result<UdpDatagram> {
    let mut at = [0u8; 1];
    rd.read_exact(&mut at).await.map_err(EngineError::Io)?;
    let addr = match at[0] {
        0x01 => {
            let mut ip = [0u8; 4];
            rd.read_exact(&mut ip).await.map_err(EngineError::Io)?;
            let mut port = [0u8; 2];
            rd.read_exact(&mut port).await.map_err(EngineError::Io)?;
            UdpTargetAddr::Socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip)),
                u16::from_be_bytes(port),
            ))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            rd.read_exact(&mut ip).await.map_err(EngineError::Io)?;
            let mut port = [0u8; 2];
            rd.read_exact(&mut port).await.map_err(EngineError::Io)?;
            UdpTargetAddr::Socket(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                u16::from_be_bytes(port),
                0,
                0,
            )))
        }
        0x06 => {
            let mut ip = [0u8; 16];
            rd.read_exact(&mut ip).await.map_err(EngineError::Io)?;
            let mut port = [0u8; 2];
            rd.read_exact(&mut port).await.map_err(EngineError::Io)?;
            let mut scope_id = [0u8; 4];
            rd.read_exact(&mut scope_id).await.map_err(EngineError::Io)?;
            UdpTargetAddr::Socket(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                u16::from_be_bytes(port),
                0,
                u32::from_be_bytes(scope_id),
            )))
        }
        0x03 => {
            let mut len = [0u8; 1];
            rd.read_exact(&mut len).await.map_err(EngineError::Io)?;
            let len = len[0] as usize;
            let mut host = vec![0u8; len];
            rd.read_exact(&mut host).await.map_err(EngineError::Io)?;
            let host = String::from_utf8(host).map_err(|e| {
                EngineError::Internal(format!("udp tunnel domain decode failed: {e}"))
            })?;
            let mut port = [0u8; 2];
            rd.read_exact(&mut port).await.map_err(EngineError::Io)?;
            UdpTargetAddr::Domain {
                host,
                port: u16::from_be_bytes(port),
            }
        }
        other => {
            return Err(EngineError::Internal(format!(
                "udp tunnel invalid addr type 0x{other:02x}"
            )));
        }
    };

    let mut len = [0u8; 2];
    rd.read_exact(&mut len).await.map_err(EngineError::Io)?;
    let len = u16::from_be_bytes(len) as usize;
    if len > max_datagram_size {
        return Err(EngineError::Internal(format!(
            "udp tunnel datagram too large: {len} > {max_datagram_size}"
        )));
    }

    let mut data = vec![0u8; len];
    rd.read_exact(&mut data).await.map_err(EngineError::Io)?;
    Ok(UdpDatagram { addr, data })
}

async fn write_datagram(
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    addr: UdpTargetAddr,
    data: &[u8],
) -> std::io::Result<()> {
    match addr {
        UdpTargetAddr::Socket(sa) => match sa.ip() {
            IpAddr::V4(ip) => {
                wr.write_all(&[0x01]).await?;
                wr.write_all(&ip.octets()).await?;
                wr.write_all(&sa.port().to_be_bytes()).await?;
            }
            IpAddr::V6(ip) => {
                if let SocketAddr::V6(v6) = sa {
                    if v6.scope_id() != 0 {
                        wr.write_all(&[0x06]).await?;
                        wr.write_all(&ip.octets()).await?;
                        wr.write_all(&v6.port().to_be_bytes()).await?;
                        wr.write_all(&v6.scope_id().to_be_bytes()).await?;
                    } else {
                        wr.write_all(&[0x04]).await?;
                        wr.write_all(&ip.octets()).await?;
                        wr.write_all(&v6.port().to_be_bytes()).await?;
                    }
                } else {
                    wr.write_all(&[0x04]).await?;
                    wr.write_all(&ip.octets()).await?;
                    wr.write_all(&sa.port().to_be_bytes()).await?;
                }
            }
        },
        UdpTargetAddr::Domain { host, port } => {
            let host_b = host.as_bytes();
            if host_b.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "domain too long",
                ));
            }
            wr.write_all(&[0x03, host_b.len() as u8]).await?;
            wr.write_all(host_b).await?;
            wr.write_all(&port.to_be_bytes()).await?;
        }
    }

    wr.write_all(&(data.len() as u16).to_be_bytes()).await?;
    wr.write_all(data).await?;
    wr.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn send_to_fails_fast_when_queue_is_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let tunnel = UdpOverTcpTunnel::connect(addr, UdpOverTcpConfig::default())
            .await
            .expect("connect");
        drop(tunnel);
        let _ = server.await;
    }

    #[tokio::test]
    async fn send_to_returns_error_after_remote_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            drop(sock);
        });

        let tunnel = UdpOverTcpTunnel::connect(addr, UdpOverTcpConfig::default())
            .await
            .expect("connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let res = tunnel
            .send_to(
                UdpTargetAddr::Domain {
                    host: "example.com".to_owned(),
                    port: 443,
                },
                b"abc",
            )
            .await;
        assert!(res.is_err());
        let _ = server.await;
    }

    #[tokio::test]
    async fn read_datagram_domain_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            sock.write_all(&[0x03, 0x0b]).await.expect("atype+len");
            sock.write_all(b"example.com").await.expect("host");
            sock.write_all(&443u16.to_be_bytes()).await.expect("port");
            sock.write_all(&3u16.to_be_bytes()).await.expect("len");
            sock.write_all(b"abc").await.expect("payload");
        });

        let mut tunnel = UdpOverTcpTunnel::connect(addr, UdpOverTcpConfig::default())
            .await
            .expect("connect");
        let item = tunnel.next().await.expect("stream item").expect("ok datagram");
        match item.addr {
            UdpTargetAddr::Domain { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected domain addr"),
        }
        assert_eq!(item.data, b"abc");
        let _ = server.await;
    }

    #[tokio::test]
    async fn read_datagram_ipv6_scope_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let ip = Ipv6Addr::LOCALHOST.octets();
            sock.write_all(&[0x06]).await.expect("atype");
            sock.write_all(&ip).await.expect("ip");
            sock.write_all(&443u16.to_be_bytes()).await.expect("port");
            sock.write_all(&7u32.to_be_bytes()).await.expect("scope");
            sock.write_all(&3u16.to_be_bytes()).await.expect("len");
            sock.write_all(b"abc").await.expect("payload");
        });

        let mut tunnel = UdpOverTcpTunnel::connect(addr, UdpOverTcpConfig::default())
            .await
            .expect("connect");
        let item = tunnel.next().await.expect("stream item").expect("ok datagram");
        match item.addr {
            UdpTargetAddr::Socket(SocketAddr::V6(v6)) => {
                assert_eq!(*v6.ip(), Ipv6Addr::LOCALHOST);
                assert_eq!(v6.port(), 443);
                assert_eq!(v6.scope_id(), 7);
            }
            _ => panic!("expected ipv6 socket addr"),
        }
        assert_eq!(item.data, b"abc");
        let _ = server.await;
    }
}
