use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::Rng;

pub async fn relay_bidirectional(
    client: &mut TcpStream,
    upstream: &mut BoxStream,
    relay_opts: RelayOptions,
    initial_client_to_upstream: Vec<u8>,
    initial_upstream_to_client: Vec<u8>,
    client_data_already_sent: bool,
) -> std::io::Result<(u64, u64)> {
    let initial_u2c_len = initial_upstream_to_client.len() as u64;
    let initial_c2u_len = if client_data_already_sent {
        0
    } else {
        initial_client_to_upstream.len() as u64
    };

    if !client_data_already_sent && !initial_client_to_upstream.is_empty() {
        if relay_opts.fragment_client_hello && is_tls_client_hello(&initial_client_to_upstream) {
            let _ =
                fragment_and_send_tls_hello(&initial_client_to_upstream, upstream, &relay_opts)
                    .await?;
        } else {
            upstream.write_all(&initial_client_to_upstream).await?;
        }
        upstream.flush().await?;
    }

    if !initial_upstream_to_client.is_empty() {
        client.write_all(&initial_upstream_to_client).await?;
        client.flush().await?;
    }

    let (c2u, u2c) = tokio::io::copy_bidirectional(client, upstream).await?;
    
    Ok((c2u + initial_c2u_len, u2c + initial_u2c_len))
}

pub async fn relay_bidirectional_with_first_byte_timeout(
    client: &mut TcpStream,
    upstream: &mut BoxStream,
    relay_opts: RelayOptions,
    initial_client_to_upstream: Vec<u8>,
    initial_upstream_to_client: Vec<u8>,
    client_data_already_sent: bool,
    timeout_duration: std::time::Duration,
) -> std::io::Result<(u64, u64)> {
    let initial_u2c_len = initial_upstream_to_client.len() as u64;
    let initial_c2u_len = if client_data_already_sent {
        0
    } else {
        initial_client_to_upstream.len() as u64
    };

    if !client_data_already_sent && !initial_client_to_upstream.is_empty() {
        if relay_opts.fragment_client_hello && is_tls_client_hello(&initial_client_to_upstream) {
            let _ =
                fragment_and_send_tls_hello(&initial_client_to_upstream, upstream, &relay_opts)
                    .await?;
        } else {
            upstream.write_all(&initial_client_to_upstream).await?;
        }
        upstream.flush().await?;
    }

    if initial_u2c_len > 0 {
        client.write_all(&initial_upstream_to_client).await?;
        client.flush().await?;
    } else {
        let mut first_byte = [0u8; 1];
        match tokio::time::timeout(timeout_duration, upstream.read(&mut first_byte)).await {
            Ok(Ok(0)) => return Ok((initial_c2u_len, 0)),
            Ok(Ok(n)) => {
                client.write_all(&first_byte[..n]).await?;
                client.flush().await?;
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "first byte timeout"));
            }
        }
    }

    let (c2u, u2c) = tokio::io::copy_bidirectional(client, upstream).await?;
    Ok((c2u + initial_c2u_len, u2c + if initial_u2c_len > 0 { initial_u2c_len } else { 1 }))
}

pub(super) fn is_tls_client_hello(data: &[u8]) -> bool {
    data.len() >= 5 && data[0] == 0x16 && data[1] == 0x03 && (data[2] == 0x01 || data[2] == 0x03)
}

pub(super) async fn fragment_and_send_tls_hello(
    data: &[u8],
    upstream_w: &mut (impl AsyncWriteExt + Unpin),
    opts: &RelayOptions,
) -> std::io::Result<u64> {
    let mut sent = 0u64;
    let mut pos = 0usize;

    let first_size = if opts.randomize_fragment_size {
        rand::thread_rng().gen_range(opts.fragment_size_min..=opts.fragment_size_max)
    } else {
        opts.fragment_size_min
    }
    .min(data.len());

    upstream_w.write_all(&data[..first_size]).await?;
    sent += first_size as u64;
    pos += first_size;

    if opts.fragment_sleep_ms > 0 {
        tokio::time::sleep(Duration::from_millis(opts.fragment_sleep_ms)).await;
    }

    while pos < data.len() && pos < opts.fragment_budget_bytes {
        let remaining = data.len() - pos;
        let chunk_size = if opts.randomize_fragment_size {
            rand::thread_rng().gen_range(opts.fragment_size_min..=opts.fragment_size_max)
        } else {
            opts.fragment_size_max
        }
        .min(remaining);

        upstream_w.write_all(&data[pos..pos + chunk_size]).await?;
        sent += chunk_size as u64;
        pos += chunk_size;

        if opts.fragment_sleep_ms > 0 {
            tokio::time::sleep(Duration::from_millis(opts.fragment_sleep_ms)).await;
        }
    }

    if pos < data.len() {
        upstream_w.write_all(&data[pos..]).await?;
        sent += (data.len() - pos) as u64;
    }
    upstream_w.flush().await?;

    Ok(sent)
}

pub fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

pub fn classify_io_error(e: &std::io::Error) -> BlockingSignal {
    match e.kind() {
        std::io::ErrorKind::ConnectionReset => BlockingSignal::Reset,
        std::io::ErrorKind::TimedOut => BlockingSignal::Timeout,
        std::io::ErrorKind::BrokenPipe => BlockingSignal::BrokenPipe,
        std::io::ErrorKind::UnexpectedEof => BlockingSignal::EarlyClose,
        _ => BlockingSignal::Timeout,
    }
}

pub fn should_skip_empty_session_scoring(c2u: u64, u2c: u64) -> bool {
    c2u < 16 && u2c == 0
}

pub fn should_mark_suspicious_zero_reply(port: u16, c2u: u64, u2c: u64, min_c2u: u64) -> bool {
    port == 443 && u2c == 0 && c2u >= min_c2u
}

#[allow(dead_code)]
pub(super) fn registrable_domain_bucket(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let n = parts.len();
    let bucket = if parts[n - 1].len() == 2 && parts[n - 2].len() <= 3 && n >= 3 {
        format!("{}.{}.{}", parts[n - 3], parts[n - 2], parts[n - 1])
    } else {
        format!("{}.{}", parts[n - 2], parts[n - 1])
    };
    Some(bucket)
}
