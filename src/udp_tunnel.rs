use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::Stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};

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
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    rx: mpsc::Receiver<Result<UdpDatagram>>,
    stop_tx: Option<oneshot::Sender<()>>,
    _join: tokio::task::JoinHandle<()>,
}

impl Drop for UdpOverTcpTunnel {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
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
    /// Connects to a UDP relay that speaks the engine's simple UDP-over-TCP framing protocol.
    pub async fn connect(addr: SocketAddr, cfg: UdpOverTcpConfig) -> Result<Self> {
        let tcp = TcpStream::connect(addr).await?;
        let _ = tcp.set_nodelay(true);
        let (mut rd, wr) = tcp.into_split();

        let (tx, rx) = mpsc::channel::<Result<UdpDatagram>>(256);
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

        let join = tokio::spawn(async move {
            loop {
                let mut at = [0u8; 1];
                let r = tokio::select! {
                    _ = &mut stop_rx => return,
                    r = rd.read_exact(&mut at) => r,
                };
                if let Err(e) = r {
                    let _ = tx.send(Err(EngineError::Io(e))).await;
                    return;
                }

                let addr = match at[0] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        if let Err(e) = rd.read_exact(&mut ip).await {
                            let _ = tx.send(Err(EngineError::Io(e))).await;
                            return;
                        }
                        let mut port = [0u8; 2];
                        if let Err(e) = rd.read_exact(&mut port).await {
                            let _ = tx.send(Err(EngineError::Io(e))).await;
                            return;
                        }
                        let sa = SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::from(ip)),
                            u16::from_be_bytes(port),
                        );
                        UdpTargetAddr::Socket(sa)
                    }
                    0x04 => {
                        let mut ip = [0u8; 16];
                        if let Err(e) = rd.read_exact(&mut ip).await {
                            let _ = tx.send(Err(EngineError::Io(e))).await;
                            return;
                        }
                        let mut port = [0u8; 2];
                        if let Err(e) = rd.read_exact(&mut port).await {
                            let _ = tx.send(Err(EngineError::Io(e))).await;
                            return;
                        }
                        let sa = SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(ip)),
                            u16::from_be_bytes(port),
                        );
                        UdpTargetAddr::Socket(sa)
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        if let Err(e) = rd.read_exact(&mut len).await {
                            let _ = tx.send(Err(EngineError::Io(e))).await;
                            return;
                        }
                        let len = len[0] as usize;
                        let mut host = vec![0u8; len];
                        if let Err(e) = rd.read_exact(&mut host).await {
                            let _ = tx.send(Err(EngineError::Io(e))).await;
                            return;
                        }
                        let host = match String::from_utf8(host) {
                            Ok(v) => v,
                            Err(e) => {
                                let _ = tx
                                    .send(Err(EngineError::Internal(format!(
                                        "udp tunnel domain decode failed: {e}"
                                    ))))
                                    .await;
                                return;
                            }
                        };
                        let mut port = [0u8; 2];
                        if let Err(e) = rd.read_exact(&mut port).await {
                            let _ = tx.send(Err(EngineError::Io(e))).await;
                            return;
                        }
                        UdpTargetAddr::Domain {
                            host,
                            port: u16::from_be_bytes(port),
                        }
                    }
                    other => {
                        let _ = tx
                            .send(Err(EngineError::Internal(format!(
                                "udp tunnel invalid addr type 0x{other:02x}"
                            ))))
                            .await;
                        return;
                    }
                };

                let mut len = [0u8; 2];
                if let Err(e) = rd.read_exact(&mut len).await {
                    let _ = tx.send(Err(EngineError::Io(e))).await;
                    return;
                }
                let len = u16::from_be_bytes(len) as usize;
                if len > cfg.max_datagram_size {
                    let _ = tx
                        .send(Err(EngineError::Internal(format!(
                            "udp tunnel datagram too large: {len} > {}",
                            cfg.max_datagram_size
                        ))))
                        .await;
                    return;
                }

                let mut data = vec![0u8; len];
                if let Err(e) = rd.read_exact(&mut data).await {
                    let _ = tx.send(Err(EngineError::Io(e))).await;
                    return;
                }

                if tx.send(Ok(UdpDatagram { addr, data })).await.is_err() {
                    return;
                }
            }
        });

        Ok(Self {
            writer: Arc::new(Mutex::new(wr)),
            rx,
            stop_tx: Some(stop_tx),
            _join: join,
        })
    }

    /// Sends a datagram to `addr` through the tunnel.
    pub async fn send_to(&self, addr: UdpTargetAddr, data: &[u8]) -> Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(EngineError::InvalidInput(
                "udp tunnel datagram exceeds 65535 bytes".to_owned(),
            ));
        }

        let mut w = self.writer.lock().await;
        match addr {
            UdpTargetAddr::Socket(sa) => match sa.ip() {
                IpAddr::V4(ip) => {
                    w.write_all(&[0x01]).await?;
                    w.write_all(&ip.octets()).await?;
                    w.write_all(&sa.port().to_be_bytes()).await?;
                }
                IpAddr::V6(ip) => {
                    w.write_all(&[0x04]).await?;
                    w.write_all(&ip.octets()).await?;
                    w.write_all(&sa.port().to_be_bytes()).await?;
                }
            },
            UdpTargetAddr::Domain { host, port } => {
                let host_b = host.as_bytes();
                if host_b.len() > 255 {
                    return Err(EngineError::InvalidInput(
                        "udp tunnel domain name too long".to_owned(),
                    ));
                }
                w.write_all(&[0x03, host_b.len() as u8]).await?;
                w.write_all(host_b).await?;
                w.write_all(&port.to_be_bytes()).await?;
            }
        }

        w.write_all(&(data.len() as u16).to_be_bytes()).await?;
        w.write_all(data).await?;
        w.flush().await?;
        Ok(())
    }
}
