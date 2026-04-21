use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

use crate::config::EngineConfig;
use crate::error::{EngineError, Result};
use crate::pt::socks5_server::protocol_handlers::*;
use crate::pt::socks5_server::relay_and_io_helpers::*;
use crate::pt::socks5_server::*;
use crate::pt::{DynOutbound, TargetAddr, TargetEndpoint};

#[allow(clippy::too_many_arguments)]
pub async fn handle_socks4(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    client: String,
    outbound: DynOutbound,
    cfg: Arc<EngineConfig>,
    cmd: u8,
    _silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    if cmd != 0x01 {
        return Err(EngineError::Internal("unsupported socks4 cmd".to_owned()));
    }
    let mut p_buf = [0u8; 2];
    tcp.read_exact(&mut p_buf).await?;
    let port = u16::from_be_bytes(p_buf);
    let mut ip_buf = [0u8; 4];
    tcp.read_exact(&mut ip_buf).await?;

    // Read user ID (and discard) — cap at 255 bytes to prevent unbounded reads
    const MAX_USER_ID_LEN: usize = 255;
    let mut read_count = 0usize;
    loop {
        if read_count >= MAX_USER_ID_LEN {
            return Err(EngineError::Internal(
                "SOCKS4 user ID exceeds 255 bytes".to_owned(),
            ));
        }
        let mut b = [0u8; 1];
        tcp.read_exact(&mut b).await?;
        read_count += 1;
        if b[0] == 0 {
            break;
        }
    }

    // SOCKS4a extension: when IP is 0.0.0.x (x != 0), a domain name follows
    // the user ID null terminator.
    let is_socks4a = ip_buf[0] == 0 && ip_buf[1] == 0 && ip_buf[2] == 0 && ip_buf[3] != 0;
    let target_addr = if is_socks4a {
        let mut domain_bytes = Vec::with_capacity(64);
        loop {
            if domain_bytes.len() >= MAX_USER_ID_LEN {
                return Err(EngineError::Internal(
                    "SOCKS4a domain name exceeds 255 bytes".to_owned(),
                ));
            }
            let mut b = [0u8; 1];
            tcp.read_exact(&mut b).await?;
            if b[0] == 0 {
                break;
            }
            domain_bytes.push(b[0]);
        }
        let domain = String::from_utf8(domain_bytes)
            .map_err(|_| EngineError::Internal("SOCKS4a domain is not valid UTF-8".to_owned()))?;
        TargetAddr::Domain(domain)
    } else {
        TargetAddr::Ip(std::net::IpAddr::V4(ip_buf.into()))
    };

    let mut out = outbound
        .connect(TargetEndpoint {
            addr: target_addr.clone(),
            port,
        })
        .await?;
    tcp.write_all(&[0x00, 0x5a, 0x00, 0x00, 0, 0, 0, 0]).await?;

    let tuned = tune_relay_for_target(
        relay_opts,
        port,
        &target_addr.to_string(),
        true,
        false,
        &cfg,
    );
    let (c2u, u2c) = relay_bidirectional(
        &mut tcp,
        &mut out,
        tuned.options,
        Vec::new(),
        Vec::new(),
        false,
    )
    .await?;

    info!(target: "socks5", conn_id, peer = %peer, client = %client, bytes_c2u = c2u, bytes_u2c = u2c, "SOCKS4 session finished");
    Ok(())
}
