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
    _cfg: Arc<EngineConfig>,
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
    let target_addr = TargetAddr::Ip(std::net::IpAddr::V4(ip_buf.into()));

    // Read user ID (and discard)
    loop {
        let mut b = [0u8; 1];
        tcp.read_exact(&mut b).await?;
        if b[0] == 0 {
            break;
        }
    }

    let mut out = outbound
        .connect(TargetEndpoint {
            addr: target_addr.clone(),
            port,
        })
        .await?;
    tcp.write_all(&[0x00, 0x5a, 0x00, 0x00, 0, 0, 0, 0]).await?;

    let tuned = tune_relay_for_target(relay_opts, port, &target_addr.to_string(), true, false);
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
