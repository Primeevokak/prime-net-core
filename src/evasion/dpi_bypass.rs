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
    SplitHandshake {
        first_packet_size: usize,
    },
    TcbDesync {
        fake_ttl: u8,
    },
    HttpFragmentation,
    FakePackets {
        ttl: u8,
        count: u8,
        data_size: usize,
    },
    OobData {
        offset: usize,
    },
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
                DesyncStrategy::FakePackets {
                    ttl,
                    count,
                    data_size,
                } => {
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
                DesyncStrategy::OobData { offset } => {
                    write_oob_at(self, data, offset).await?;
                }
                DesyncStrategy::HttpFragmentation => {
                    write_http_fragmented(self, data).await?;
                }
                DesyncStrategy::TcbDesync { .. } | DesyncStrategy::FakePackets { .. } => {
                    self.write_all(data).await?;
                }
            }
            self.flush().await?;
            Ok(())
        })
    }
}

/// Send a single byte to `stream` with the OOB/URG flag set.
///
/// On Windows, uses `MSG_OOB` via `WinSock::send`.
/// On Unix (Linux, macOS), uses `libc::send` with `MSG_OOB`.
/// On other platforms, falls back to sending the byte normally (connection remains valid
/// but without the URG signal; OOB profiles should not be included on such platforms).
///
/// # Safety (Windows path)
/// `sock` is a valid Windows socket handle obtained from the live `TcpStream`.
///
/// # Safety (Unix path)
/// `fd` is a valid Unix file descriptor obtained from the live `TcpStream`.
pub(crate) async fn send_oob_byte(stream: &mut TcpStream, byte: u8) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{send, MSG_OOB, SOCKET};
        let sock = stream.as_raw_socket() as SOCKET;
        let buf = [byte];
        // SAFETY: sock is a valid Windows SOCKET for this live TcpStream.
        // buf is a valid 1-byte readable buffer that outlives the send() call.
        unsafe {
            let res = send(sock, buf.as_ptr(), 1, MSG_OOB);
            if res == -1 {
                // Fallback: send as a normal byte so the connection is not broken.
                stream.write_all(&buf).await?;
            }
        }
        Ok(())
    }
    #[cfg(all(unix, not(windows)))]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let buf = [byte];
        // SAFETY: fd is a valid file descriptor for this live TcpStream.
        // buf is a valid 1-byte readable buffer that outlives the send() call.
        unsafe {
            let res = libc::send(fd, buf.as_ptr() as *const libc::c_void, 1, libc::MSG_OOB);
            if res == -1 {
                // Fallback: send as a normal byte so the connection is not broken.
                stream.write_all(&buf).await?;
            }
        }
        Ok(())
    }
    #[cfg(not(any(windows, unix)))]
    stream.write_all(&[byte]).await
}

pub(crate) async fn write_oob_at(
    stream: &mut TcpStream,
    data: &[u8],
    offset: usize,
) -> std::io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let cut = offset.min(data.len().saturating_sub(1));

    if cut > 0 {
        stream.write_all(&data[..cut]).await?;
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{send, MSG_OOB, SOCKET};

        let sock = stream.as_raw_socket() as SOCKET;
        let byte_to_send = data[cut];
        // SAFETY: sock is valid for this TcpStream; byte_to_send is on the stack.
        unsafe {
            let res = send(sock, &byte_to_send as *const u8, 1, MSG_OOB);
            if res == -1 {
                stream.write_all(&[byte_to_send]).await?;
            }
        }
    }
    #[cfg(all(unix, not(windows)))]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let byte_to_send = data[cut];
        // SAFETY: fd is valid for this TcpStream; byte_to_send is on the stack.
        unsafe {
            let res = libc::send(
                fd,
                &byte_to_send as *const u8 as *const libc::c_void,
                1,
                libc::MSG_OOB,
            );
            if res == -1 {
                stream.write_all(&[byte_to_send]).await?;
            }
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        stream.write_all(&[data[cut]]).await?;
    }

    if cut + 1 < data.len() {
        stream.write_all(&data[cut + 1..]).await?;
    }
    Ok(())
}

/// Send a short-lived low-TTL probe to influence DPI TCP state.
///
/// Best-effort: errors are ignored by callers.
pub(crate) async fn send_tcb_desync_probe(addr: SocketAddr, fake_ttl: u8) -> std::io::Result<()> {
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

/// Send a low-TTL probe with random payload to desync DPI middlebox state.
///
/// Best-effort: errors are ignored by callers.
pub(crate) async fn send_fake_payload_probe(
    addr: SocketAddr,
    ttl: u8,
    data_size: usize,
) -> std::io::Result<()> {
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

/// Send a low-TTL probe containing a crafted TLS ClientHello with `fake_sni` to desync DPI.
///
/// Unlike [`send_fake_payload_probe`] (which sends random bytes), this probe sends a
/// structurally valid TLS 1.3 ClientHello.  DPI that reassembles TCP and parses TLS will
/// extract the fake SNI, create state for it, and then lose sync when the low TTL causes
/// the probe to expire before reaching the server.  The subsequent real ClientHello (on a
/// different TCP 4-tuple) arrives into a confused DPI state.
///
/// Best-effort: errors are ignored by callers.
pub(crate) async fn send_fake_sni_probe(
    addr: SocketAddr,
    ttl: u8,
    fake_sni: &str,
) -> std::io::Result<()> {
    let payload = build_fake_client_hello(fake_sni);
    if let Ok(Ok(mut probe)) =
        tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await
    {
        let _ = probe.set_ttl(u32::from(ttl.max(1)));
        let _ = probe.write_all(&payload).await;
        let _ = probe.shutdown().await;
    }
    Ok(())
}

/// Build a minimal but structurally valid TLS 1.3 ClientHello record for the given SNI.
///
/// The resulting bytes form a complete TLS record that DPI can parse as a real ClientHello.
/// Fields: version=TLS 1.2 compat, random=zeroed (probe only), one cipher suite
/// (TLS_AES_128_GCM_SHA256), null compression, and a single SNI extension.
fn build_fake_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len();

    // SNI extension data layout:
    //   server_name_list_len  (2 bytes)
    //   server_name_type      (1 byte  = 0x00 host_name)
    //   server_name_len       (2 bytes)
    //   server_name           (sni_len bytes)
    let sni_list_len = 3 + sni_len;
    let sni_ext_data_len = 2 + sni_list_len; // list_len field + list

    // Full extension wire encoding: type(2) + data_len(2) + data
    let sni_ext_wire_len = 4 + sni_ext_data_len;

    // ClientHello body (everything after the handshake type+length):
    //   client_version     2
    //   random            32
    //   session_id_len     1  (= 0)
    //   cipher_suites_len  2  (= 4, two ciphers × 2 bytes each)
    //   cipher_suites      4
    //   comp_methods_len   1  (= 1)
    //   comp_methods       1  (= 0x00)
    //   extensions_len     2
    //   extensions         sni_ext_wire_len
    let ch_body_len = 2 + 32 + 1 + 2 + 4 + 1 + 1 + 2 + sni_ext_wire_len;

    // Handshake message = type(1) + length(3) + body
    let hs_msg_len = 4 + ch_body_len;

    // TLS record = record_header(5) + handshake_message
    let mut buf = Vec::with_capacity(5 + hs_msg_len);

    // TLS record header
    buf.extend_from_slice(&[0x16, 0x03, 0x01]); // Handshake, TLS 1.0 wire version
    buf.extend_from_slice(&(hs_msg_len as u16).to_be_bytes());

    // Handshake header: ClientHello type = 0x01, length in 3 bytes
    buf.push(0x01);
    buf.extend_from_slice(&[
        (ch_body_len >> 16) as u8,
        (ch_body_len >> 8) as u8,
        ch_body_len as u8,
    ]);

    // client_version: TLS 1.2 (0x0303) for maximum DPI recognition
    buf.extend_from_slice(&[0x03, 0x03]);
    // random: 32 zero bytes (probe — not a real handshake)
    buf.extend_from_slice(&[0u8; 32]);
    // session_id: empty
    buf.push(0x00);
    // cipher_suites: TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384
    buf.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
    // compression_methods: null only
    buf.extend_from_slice(&[0x01, 0x00]);
    // extensions_len
    buf.extend_from_slice(&(sni_ext_wire_len as u16).to_be_bytes());

    // SNI extension
    buf.extend_from_slice(&[0x00, 0x00]); // extension type: server_name
    buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    buf.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    buf.push(0x00); // name_type: host_name
    buf.extend_from_slice(&(sni_len as u16).to_be_bytes());
    buf.extend_from_slice(sni_bytes);

    buf
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
        let chunk = remaining.min(rand::thread_rng().gen_range(8..=32));
        stream.write_all(&data[pos..pos + chunk]).await?;
        pos += chunk;
        if pos < header_end {
            let delay = rand::thread_rng().gen_range(5..=25);
            tokio::time::sleep(Duration::from_millis(delay)).await;
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
        DesyncStrategy::TcbDesync { .. }
        | DesyncStrategy::FakePackets { .. }
        | DesyncStrategy::OobData { .. } => vec![data.to_vec()],
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
