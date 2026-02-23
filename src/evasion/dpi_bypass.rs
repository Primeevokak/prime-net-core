use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use rand::Rng;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy)]
pub enum BypassMethod {
    HttpFragmentation,
    TcpSegmentation,
    PacketReordering,
    TtlManipulation,
    FakeSni,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesyncStrategy {
    SplitHandshake { first_packet_size: usize },
    TcbDesync { fake_ttl: u8 },
    HttpFragmentation,
    FakePackets { ttl: u8, count: u8, data_size: usize },
}

#[derive(Debug, Error)]
pub enum DpiBypassError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid desync strategy: {0}")]
    InvalidStrategy(&'static str),
}

pub type Result<T> = std::result::Result<T, DpiBypassError>;

#[derive(Debug, Clone)]
pub struct DpiBypass {
    pub methods: Vec<BypassMethod>,
}

impl Default for DpiBypass {
    fn default() -> Self {
        Self {
            methods: vec![BypassMethod::HttpFragmentation],
        }
    }
}

impl DpiBypass {
    pub fn apply_fragmentation(&self, data: &[u8]) -> Vec<Vec<u8>> {
        chunk_for_strategy(data, DesyncStrategy::HttpFragmentation)
    }

    pub fn apply_strategy_fragmentation(
        &self,
        data: &[u8],
        strategy: DesyncStrategy,
    ) -> Vec<Vec<u8>> {
        chunk_for_strategy(data, strategy)
    }
}

pub trait DpiBypassExt {
    fn desync_connect(
        addr: SocketAddr,
        strategy: DesyncStrategy,
    ) -> Pin<Box<dyn Future<Output = Result<TcpStream>> + Send>>
    where
        Self: Sized;

    fn send_with_strategy<'a>(
        &'a mut self,
        data: &'a [u8],
        strategy: DesyncStrategy,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

impl DpiBypassExt for TcpStream {
    fn desync_connect(
        addr: SocketAddr,
        strategy: DesyncStrategy,
    ) -> Pin<Box<dyn Future<Output = Result<TcpStream>> + Send>> {
        Box::pin(async move {
            match strategy {
                DesyncStrategy::TcbDesync { fake_ttl } => {
                    let _ = send_tcb_desync_probe(addr, fake_ttl).await;
                }
                DesyncStrategy::FakePackets { ttl, count, data_size } => {
                    for _ in 0..count {
                        let _ = send_fake_payload_probe(addr, ttl, data_size).await;
                    }
                }
                _ => {}
            }
            Ok(TcpStream::connect(addr).await?)
        })
    }

    fn send_with_strategy<'a>(
        &'a mut self,
        data: &'a [u8],
        strategy: DesyncStrategy,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            match strategy {
                DesyncStrategy::SplitHandshake { first_packet_size } => {
                    if first_packet_size == 0 {
                        return Err(DpiBypassError::InvalidStrategy(
                            "first_packet_size must be greater than zero",
                        ));
                    }
                    write_split_prefix(self, data, first_packet_size, Duration::from_millis(20))
                        .await?;
                }
                DesyncStrategy::HttpFragmentation => {
                    write_http_fragmented(self, data).await?;
                }
                DesyncStrategy::TcbDesync { .. } | DesyncStrategy::FakePackets { .. } => {
                    // Transport desync is applied at connect phase; payload stays intact.
                    self.write_all(data).await?;
                }
            }
            self.flush().await?;
            Ok(())
        })
    }
}

async fn send_tcb_desync_probe(addr: SocketAddr, fake_ttl: u8) -> std::io::Result<()> {
    // Best-effort: short-lived low-TTL probe connection to influence DPI state.
    if let Ok(Ok(mut probe)) =
        tokio::time::timeout(Duration::from_millis(150), TcpStream::connect(addr)).await
    {
        let _ = probe.set_ttl(u32::from(fake_ttl.max(1)));
        let _ = probe.write_all(b"\0").await;
        let _ = probe.shutdown().await;
    }
    Ok(())
}

async fn send_fake_payload_probe(addr: SocketAddr, ttl: u8, data_size: usize) -> std::io::Result<()> {
    use rand::RngCore;
    if let Ok(Ok(mut probe)) =
        tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await
    {
        let _ = probe.set_ttl(u32::from(ttl.max(1)));
        let mut junk = vec![0u8; data_size.clamp(1, 1024)];
        rand::thread_rng().fill_bytes(&mut junk);
        let _ = probe.write_all(&junk).await;
        let _ = probe.shutdown().await;
    }
    Ok(())
}

async fn write_split_prefix(
    stream: &mut TcpStream,
    data: &[u8],
    first_packet_size: usize,
    delay: Duration,
) -> std::io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let cut = first_packet_size.min(data.len());
    stream.write_all(&data[..cut]).await?;
    if cut < data.len() {
        tokio::time::sleep(delay).await;
        stream.write_all(&data[cut..]).await?;
    }
    Ok(())
}

async fn write_http_fragmented(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .unwrap_or(data.len());

    let mut pos = 0usize;
    while pos < header_end {
        let remaining = header_end - pos;
        let chunk = remaining.min(rand::thread_rng().gen_range(8..=24));
        stream.write_all(&data[pos..pos + chunk]).await?;
        pos += chunk;
        if pos < header_end {
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
    }

    if header_end < data.len() {
        stream.write_all(&data[header_end..]).await?;
    }
    Ok(())
}

fn chunk_for_strategy(data: &[u8], strategy: DesyncStrategy) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return Vec::new();
    }

    match strategy {
        DesyncStrategy::SplitHandshake { first_packet_size } => {
            let cut = first_packet_size.max(1).min(data.len());
            let mut out = Vec::with_capacity(2);
            out.push(data[..cut].to_vec());
            if cut < data.len() {
                out.push(data[cut..].to_vec());
            }
            out
        }
        DesyncStrategy::HttpFragmentation => {
            let header_end = data
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|idx| idx + 4)
                .unwrap_or(data.len());

            let mut out = Vec::new();
            let mut pos = 0usize;
            while pos < header_end {
                let remaining = header_end - pos;
                let chunk = remaining.min(16);
                out.push(data[pos..pos + chunk].to_vec());
                pos += chunk;
            }
            if header_end < data.len() {
                out.push(data[header_end..].to_vec());
            }
            out
        }
        DesyncStrategy::TcbDesync { .. } | DesyncStrategy::FakePackets { .. } => vec![data.to_vec()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_handshake_only_splits_prefix() {
        let payload = vec![0x16; 128];
        let chunks = chunk_for_strategy(
            &payload,
            DesyncStrategy::SplitHandshake {
                first_packet_size: 19,
            },
        );

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 19);
        assert_eq!(chunks[1].len(), 109);
        assert_eq!(
            [chunks[0].as_slice(), chunks[1].as_slice()].concat(),
            payload
        );
    }

    #[test]
    fn http_fragmentation_targets_headers_not_body() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: X\r\n\r\nBODY".to_vec();
        let chunks = chunk_for_strategy(&payload, DesyncStrategy::HttpFragmentation);

        assert!(chunks.len() >= 2);
        assert_eq!(
            [chunks[0].as_slice(), chunks[1..].concat().as_slice()].concat(),
            payload
        );
        assert_eq!(chunks.last().expect("last chunk"), b"BODY");
    }

    #[test]
    fn tcb_desync_does_not_rewrite_payload() {
        let payload = b"\x16\x03\x01hello".to_vec();
        let chunks = chunk_for_strategy(&payload, DesyncStrategy::TcbDesync { fake_ttl: 2 });
        assert_eq!(chunks, vec![payload]);
    }
}
