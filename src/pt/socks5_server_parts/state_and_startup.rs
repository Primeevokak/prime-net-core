use super::*;
use crate::config::EngineConfig;
use crate::error::{EngineError, Result};
use crate::pt::{TargetAddr, TargetEndpoint, DynOutbound};
use crate::anticensorship::ResolverChain;
use crate::pt::socks5_server::route_connection::handle_socks5_connection;
use crate::pt::socks5_server::telemetry_bus::init_telemetry_bus;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, debug, error};
use tokio::task::JoinSet;
use tokio::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);
pub static WARNED_SOCKS4_LIMITATIONS: AtomicBool = AtomicBool::new(false);
pub static WARNED_SOCKS4_AGGREGATION: AtomicBool = AtomicBool::new(false);

pub async fn start_socks5_server(
    listen_addr: SocketAddr,
    outbound: DynOutbound,
    cfg: Arc<EngineConfig>,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<Socks5ServerGuard> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let relay_opts = Arc::new(relay_opts);
    let listener = TcpListener::bind(listen_addr).await.map_err(EngineError::Io)?;
    let local_addr = listener.local_addr().map_err(EngineError::Io)?;

    init_telemetry_bus(cfg.clone());

    tokio::spawn(async move {
        info!(target: "socks5", listen_addr = %local_addr, "SOCKS5 server started");
        let mut join_set = JoinSet::new();
        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((tcp, peer)) => {
                            let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                            let outbound_handle = outbound.clone();
                            let cfg_handle = cfg.clone();
                            let relay_opts_val = (*relay_opts).clone();
                            join_set.spawn(async move {
                                if let Err(e) = handle_socks5_connection(conn_id, tcp, peer, "client", outbound_handle, cfg_handle, silent_drop, relay_opts_val).await {
                                    debug!(target: "socks5", conn_id, error = %e, "client session finished with error (expected during race/eof)");
                                }
                            });
                        }
                        Err(e) => { error!(target: "socks5", error = %e, "failed to accept connection"); }
                    }
                }
                _ = &mut shutdown_rx => { break; }
            }
        }
    });
    Ok(Socks5ServerGuard { shutdown_tx: Some(shutdown_tx), listen_addr: local_addr })
}

#[derive(Debug)]
pub struct Socks5ServerGuard { 
    pub(super) shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    pub(super) listen_addr: SocketAddr,
}

impl Socks5ServerGuard {
    pub fn listen_addr(&self) -> SocketAddr { self.listen_addr }
}

impl Drop for Socks5ServerGuard { 
    fn drop(&mut self) { if let Some(tx) = self.shutdown_tx.take() { let _ = tx.send(()); } } 
}

#[derive(Debug, Clone, Default)]
pub struct RelayOptions {
    pub fragment_client_hello: bool,
    pub fragment_size_min: usize,
    pub fragment_size_max: usize,
    pub fragment_sleep_ms: u64,
    pub fragment_budget_bytes: usize,
    pub randomize_fragment_size: bool,
    pub bypass_socks5: Option<SocketAddr>,
    pub bypass_socks5_pool: Vec<SocketAddr>,
    pub bypass_domain_check: Option<fn(&str) -> bool>,
    pub classifier_emit_interval_secs: u64,
    pub suspicious_zero_reply_min_c2u: usize,
    pub split_at_sni: bool,
    pub client_hello_split_offsets: Vec<usize>,
    pub tcp_window_size: u16,
    pub classifier_persist_enabled: bool,
    pub classifier_cache_path: Option<PathBuf>,
    pub classifier_entry_ttl_secs: u64,
    pub strategy_race_enabled: bool,
}

pub async fn connect_bypass_upstream(
    _conn_id: u64,
    target: &TargetEndpoint,
    target_label: &str,
    bypass_addr: SocketAddr,
    bypass_profile_idx: u8,
    bypass_profile_total: u8,
    _resolver: Option<Arc<ResolverChain>>,
    cfg: Arc<EngineConfig>,
    _relay_opts: RelayOptions,
) -> Result<TcpStream> {
    let mut bypass = TcpStream::connect(bypass_addr).await.map_err(EngineError::Io)?;
    bypass.write_all(&[0x05, 0x01, 0x00]).await.map_err(EngineError::Io)?;
    let mut auth_res = [0u8; 2];
    bypass.read_exact(&mut auth_res).await.map_err(EngineError::Io)?;
    
    let mut req = vec![0x05, 0x01, 0x00];
    match &target.addr {
        TargetAddr::Ip(std::net::IpAddr::V4(v4)) => { req.push(0x01); req.extend_from_slice(&v4.octets()); }
        TargetAddr::Domain(host) => { req.push(0x03); req.push(host.len() as u8); req.extend_from_slice(host.as_bytes()); }
        TargetAddr::Ip(std::net::IpAddr::V6(v6)) => { req.push(0x04); req.extend_from_slice(&v6.octets()); }
    }
    let port_bytes = target.port.to_be_bytes();
    req.extend_from_slice(&port_bytes);
    bypass.write_all(&req).await.map_err(EngineError::Io)?;

    let mut reply_hdr = [0u8; 4];
    bypass.read_exact(&mut reply_hdr).await.map_err(EngineError::Io)?;
    if reply_hdr[1] != 0x00 {
        crate::pt::socks5_server::route_scoring::record_bypass_profile_failure(target_label, bypass_profile_idx, bypass_profile_total, "proxy-err", &cfg);
        return Err(EngineError::Internal("SOCKS5 proxy refused connection".to_owned()));
    }
    
    let mut addr_buf = match reply_hdr[3] {
        0x01 => vec![0u8; 4],
        0x03 => { let mut len = [0u8; 1]; bypass.read_exact(&mut len).await?; vec![0u8; len[0] as usize] }
        0x04 => vec![0u8; 16],
        _ => return Err(EngineError::Internal("invalid SOCKS5 reply ATYP".to_owned())),
    };
    bypass.read_exact(&mut addr_buf).await?;
    let mut p_buf = [0u8; 2];
    bypass.read_exact(&mut p_buf).await?;

    Ok(bypass)
}
