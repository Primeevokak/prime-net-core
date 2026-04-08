// TUN/VPN mode: routes raw IP traffic through the engine's bypass SOCKS5 stack.
//
// Architecture:
//   [OS traffic] → [TUN device] → [smoltcp TCP stack] → [SOCKS5 relay] → [bypass engine]
//
// Requires: cargo build --features tun
//   Linux/macOS: run as root or with CAP_NET_ADMIN
//   Windows:     WinTUN driver must be installed (https://wintun.net)
//
// Routing setup (must be done manually or via --auto-route):
//   Linux:  ip route add 0.0.0.0/1 dev <tun_name>
//           ip route add 128.0.0.0/1 dev <tun_name>
//   macOS:  sudo route add -net 0.0.0.0/1 -interface <tun_name>
//           sudo route add -net 128.0.0.0/1 -interface <tun_name>

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::thread;
use std::time::Duration;

use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::EngineConfig;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp as tcp_sock;
use smoltcp::socket::AnySocket;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// Buffer sizes per TCP connection in smoltcp
const TCP_BUF: usize = 64 * 1024;
// smoltcp poll interval
const POLL_INTERVAL_US: u64 = 500;

#[derive(Debug, Clone)]
pub struct TunOpts {
    /// TUN interface name (e.g. "prime0")
    pub tun_name: String,
    /// IP address of the TUN interface itself (e.g. 10.88.0.1)
    pub tun_addr: Ipv4Addr,
    /// CIDR prefix length (e.g. 16 for /16)
    pub tun_prefix: u8,
    /// Local SOCKS5 server to forward traffic through
    pub socks_addr: SocketAddr,
    /// MTU (default 1500)
    pub mtu: u16,
    /// Print routing setup commands and exit without starting
    pub print_routes_only: bool,
    /// Automatically configure system routes so all traffic goes through TUN.
    pub auto_route: bool,
    /// CIDRs that must bypass the TUN and go through the original gateway
    /// (split tunneling — e.g. your bypass proxy server IP).
    pub exclude: Vec<crate::auto_route::Cidr>,
    /// If set, engine stats are written to this path every 5 s.
    pub stats_file: Option<std::path::PathBuf>,
}

impl Default for TunOpts {
    fn default() -> Self {
        Self {
            tun_name: "prime0".to_owned(),
            tun_addr: Ipv4Addr::new(10, 88, 0, 1),
            tun_prefix: 16,
            socks_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            mtu: 1500,
            print_routes_only: false,
            auto_route: false,
            exclude: Vec::new(),
            stats_file: None,
        }
    }
}

/// Messages from TUN reader to smoltcp thread (ordered channel ensures sequencing)
enum TunMsg {
    /// Prepare a socket to listen on this port BEFORE the SYN arrives
    PrepListen {
        dst_port: u16,
        nat_key: (Ipv4Addr, u16),
        orig_dst_ip: Ipv4Addr,
    },
    /// Raw (already dst-rewritten) IP packet for smoltcp
    Packet(Vec<u8>),
}

// ─── smoltcp Device impl ───────────────────────────────────────────────────

/// Bridges smoltcp to async channels. Rx comes from a VecDeque (filled by TUN reader).
/// Tx goes to an unbounded mpsc sender (drained by async TUN writer).
struct ChanDevice {
    rx: VecDeque<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    mtu: usize,
}

struct OwnedRxToken(Vec<u8>);
impl smoltcp::phy::RxToken for OwnedRxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, f: F) -> R {
        let mut buf = self.0;
        f(&mut buf)
    }
}

struct ChanTxToken(mpsc::UnboundedSender<Vec<u8>>);
impl smoltcp::phy::TxToken for ChanTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.0.send(buf);
        r
    }
}

impl Device for ChanDevice {
    type RxToken<'a>
        = OwnedRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = ChanTxToken
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((OwnedRxToken(pkt), ChanTxToken(self.tx.clone())))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ChanTxToken(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // Skip checksum validation for incoming packets (we may have zeroed them during DNAT rewrite)
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps
    }
}

// ─── Packet helpers ────────────────────────────────────────────────────────

/// Check whether this IPv4/TCP packet is a pure SYN (first segment of new connection).
fn is_ipv4_tcp_syn(pkt: &[u8]) -> bool {
    if pkt.len() < 20 {
        return false;
    }
    if pkt[0] >> 4 != 4 {
        return false;
    } // IPv4
    if pkt[9] != 6 {
        return false;
    } // TCP
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 14 {
        return false;
    }
    let flags = pkt[ihl + 13];
    flags & 0x12 == 0x02 // SYN=1, ACK=0
}

/// NAT key: (source IP, source port).
type NatKey = (Ipv4Addr, u16);
/// DNAT result: (rewritten packet, nat key, original dst IP, dst port).
type DnatResult = (Vec<u8>, NatKey, Ipv4Addr, u16);

/// Rewrite dst_ip to tun_ip (DNAT), zero checksums (smoltcp recomputes on Tx).
fn rewrite_dnat(mut pkt: Vec<u8>, tun_ip: Ipv4Addr) -> Option<DnatResult> {
    if pkt.len() < 20 {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    } // IPv4 only
    if pkt[9] != 6 {
        return None;
    } // TCP only

    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 4 {
        return None;
    }

    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let orig_dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);

    // Don't capture loopback or the TUN IP itself → infinite loop prevention
    if src_ip.is_loopback() || orig_dst_ip.is_loopback() || orig_dst_ip == tun_ip {
        return None;
    }

    // Rewrite dst_ip → tun_ip
    pkt[16..20].copy_from_slice(&tun_ip.octets());

    // Zero IP checksum (smoltcp skips Rx validation)
    pkt[10] = 0;
    pkt[11] = 0;

    // Zero TCP checksum
    if pkt.len() >= ihl + 18 {
        pkt[ihl + 16] = 0;
        pkt[ihl + 17] = 0;
    }

    Some((pkt, (src_ip, src_port), orig_dst_ip, dst_port))
}

fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let bits: u32 = !0u32 << (32 - prefix.min(32));
    let [a, b, c, d] = bits.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

// ─── SOCKS5 handshake ──────────────────────────────────────────────────────

async fn socks5_connect(stream: &mut TcpStream, dst: SocketAddr) -> std::io::Result<()> {
    // Greeting: version=5, nmethods=1, method=0 (no auth)
    stream.write_all(&[5u8, 1, 0]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 5 || resp[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "SOCKS5 auth negotiation failed",
        ));
    }

    // CONNECT request
    let mut req = vec![5u8, 1, 0]; // ver=5, cmd=CONNECT, rsv=0
    match dst {
        SocketAddr::V4(v4) => {
            req.push(1); // ATYP=IPv4
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            req.push(4); // ATYP=IPv6
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    stream.write_all(&req).await?;

    // Response (minimum 10 bytes for IPv4)
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT rejected: code {}", hdr[1]),
        ));
    }
    // Drain bound address
    let skip = match hdr[3] {
        1 => 4 + 2,  // IPv4 + port
        4 => 16 + 2, // IPv6 + port
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        _ => 4 + 2,
    };
    let mut tail = vec![0u8; skip];
    stream.read_exact(&mut tail).await?;

    Ok(())
}

// ─── Per-connection relay task ─────────────────────────────────────────────

async fn relay_task(
    socks_addr: SocketAddr,
    dst: SocketAddr,
    mut from_smol: mpsc::UnboundedReceiver<Vec<u8>>,
    to_smol: mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut stream = match TcpStream::connect(socks_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(dst = %dst, err = %e, "TUN relay: SOCKS5 connect failed");
            return;
        }
    };
    if let Err(e) = socks5_connect(&mut stream, dst).await {
        warn!(dst = %dst, err = %e, "TUN relay: SOCKS5 handshake failed");
        return;
    }

    debug!(dst = %dst, "TUN relay: connected");
    let (mut reader, mut writer) = stream.into_split();

    // smoltcp → SOCKS5
    let upload = tokio::spawn(async move {
        while let Some(data) = from_smol.recv().await {
            if writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // SOCKS5 → smoltcp
    let download = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_smol.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let _ = tokio::join!(upload, download);
    debug!(dst = %dst, "TUN relay: done");
}

// ─── smoltcp poll thread ───────────────────────────────────────────────────

fn smoltcp_thread(
    tun_ip: Ipv4Addr,
    tun_prefix: u8,
    mtu: usize,
    socks_addr: SocketAddr,
    mut from_tun: mpsc::UnboundedReceiver<TunMsg>,
    to_tun: mpsc::UnboundedSender<Vec<u8>>,
    rt_handle: tokio::runtime::Handle,
) {
    let [a, b, c, d] = tun_ip.octets();
    let tun_cidr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(a, b, c, d), tun_prefix));

    let mut device = ChanDevice {
        rx: VecDeque::new(),
        tx: to_tun,
        mtu,
    };

    let iface_config = IfaceConfig::new(smoltcp::wire::HardwareAddress::Ip);
    let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(tun_cidr);
    });

    let mut socket_set = SocketSet::new(vec![]);

    // NAT table: (src_ip, src_port) → original_dst_ip
    let mut nat: HashMap<(Ipv4Addr, u16), Ipv4Addr> = HashMap::new();

    // Per-connection relay channels (indexed by SocketHandle)
    let mut smol_to_relay: HashMap<SocketHandle, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
    let mut relay_to_smol: HashMap<SocketHandle, mpsc::UnboundedReceiver<Vec<u8>>> = HashMap::new();
    let mut handle_to_dst: HashMap<SocketHandle, SocketAddr> = HashMap::new();

    info!("smoltcp poll thread started");

    loop {
        // 1. Drain messages from TUN reader
        loop {
            match from_tun.try_recv() {
                Ok(TunMsg::PrepListen {
                    dst_port,
                    nat_key,
                    orig_dst_ip,
                }) => {
                    nat.insert(nat_key, orig_dst_ip);
                    // Allocate a new TCP socket and listen on this port
                    let rx_buf = tcp_sock::SocketBuffer::new(vec![0u8; TCP_BUF]);
                    let tx_buf = tcp_sock::SocketBuffer::new(vec![0u8; TCP_BUF]);
                    let mut sock = tcp_sock::Socket::new(rx_buf, tx_buf);
                    let listen_ep = smoltcp::wire::IpEndpoint::new(
                        IpAddress::Ipv4(Ipv4Address::new(a, b, c, d)),
                        dst_port,
                    );
                    if let Err(e) = sock.listen(listen_ep) {
                        warn!(port = dst_port, err = ?e, "smoltcp: listen failed");
                        continue;
                    }
                    let handle = socket_set.add(sock);
                    debug!(port = dst_port, handle = %handle, "smoltcp: listening");
                }
                Ok(TunMsg::Packet(pkt)) => {
                    device.rx.push_back(pkt);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    info!("smoltcp thread: TUN channel closed, exiting");
                    return;
                }
            }
        }

        // 2. Poll smoltcp
        let ts = SmolInstant::now();
        iface.poll(ts, &mut device, &mut socket_set);

        // 3. Process each socket
        let mut to_remove: Vec<SocketHandle> = Vec::new();
        for (handle, socket) in socket_set.iter_mut() {
            let sock = match tcp_sock::Socket::downcast_mut(socket) {
                Some(s) => s,
                None => continue,
            };

            // New established connection
            if sock.is_active() && !handle_to_dst.contains_key(&handle) {
                let remote = match sock.remote_endpoint() {
                    Some(ep) => ep,
                    None => continue,
                };
                let local_port = match sock.local_endpoint() {
                    Some(ep) => ep.port,
                    None => continue,
                };
                let src_ip = match remote.addr {
                    IpAddress::Ipv4(a) => Ipv4Addr::from(a.0),
                    _ => continue,
                };
                let src_port = remote.port;
                let nat_key = (src_ip, src_port);

                if let Some(orig_dst_ip) = nat.get(&nat_key).copied() {
                    let dst = SocketAddr::V4(SocketAddrV4::new(orig_dst_ip, local_port));
                    let (s2r_tx, s2r_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    let (r2s_tx, r2s_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    smol_to_relay.insert(handle, s2r_tx);
                    relay_to_smol.insert(handle, r2s_rx);
                    handle_to_dst.insert(handle, dst);
                    nat.remove(&nat_key);

                    rt_handle.spawn(relay_task(socks_addr, dst, s2r_rx, r2s_tx));
                    debug!(dst = %dst, handle = %handle, "TUN: new connection relayed");
                }
            }

            // Forward data: smoltcp socket → relay task
            if sock.may_recv() {
                if let Some(tx) = smol_to_relay.get(&handle) {
                    let mut buf = vec![0u8; sock.recv_queue()];
                    if !buf.is_empty() {
                        if let Ok(n) = sock.recv_slice(&mut buf) {
                            if n > 0 {
                                buf.truncate(n);
                                let _ = tx.send(buf);
                            }
                        }
                    }
                }
            }

            // Forward data: relay task → smoltcp socket
            if sock.may_send() {
                if let Some(rx) = relay_to_smol.get_mut(&handle) {
                    while let Ok(data) = rx.try_recv() {
                        let _ = sock.send_slice(&data);
                    }
                }
            }

            // Cleanup closed sockets
            if !sock.is_open() {
                smol_to_relay.remove(&handle);
                relay_to_smol.remove(&handle);
                handle_to_dst.remove(&handle);
                to_remove.push(handle);
            }
        }

        for handle in to_remove {
            socket_set.remove(handle);
        }

        // 4. Brief sleep to avoid burning CPU
        thread::sleep(Duration::from_micros(POLL_INTERVAL_US));
    }
}

// ─── WinTUN bootstrap (Windows only) ──────────────────────────────────────
//
// wintun.dll is the WireGuard WinTUN driver interface.
// It must reside next to the executable — no installation required.
//
// The DLL is embedded in the binary at build time by build.rs (downloaded
// once via PowerShell during `cargo build`).  At runtime we simply write it
// next to the executable if it is not already present.

#[cfg(target_os = "windows")]
const WINTUN_DLL_NAME: &str = "wintun.dll";

// Embedded at build time by build.rs → OUT_DIR/wintun.dll.
#[cfg(target_os = "windows")]
const WINTUN_DLL_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wintun.dll"));

#[cfg(target_os = "windows")]
async fn ensure_wintun() -> Result<()> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let dll_path = exe_dir.join(WINTUN_DLL_NAME);
    if dll_path.exists() {
        debug!("wintun.dll found at {}", dll_path.display());
        return Ok(());
    }

    info!("wintun.dll not found — extracting from embedded binary");

    std::fs::write(&dll_path, WINTUN_DLL_BYTES)
        .map_err(|e| EngineError::Internal(format!("wintun: write dll: {e}")))?;

    info!("wintun.dll installed → {}", dll_path.display());
    Ok(())
}

// ─── Public entry point ────────────────────────────────────────────────────

/// Returns `true` when the calling process holds the Administrators token.
///
/// WinTUN requires administrator rights to create a kernel TUN adapter.
/// Checking this upfront gives a clear error instead of the opaque
/// `WintunCreateAdapter failed "No inner logs"` message from the driver.
#[cfg(target_os = "windows")]
fn is_running_as_admin() -> bool {
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
    // SAFETY: IsUserAnAdmin() is a read-only, thread-safe Windows API call.
    unsafe { IsUserAnAdmin() != 0 }
}

pub async fn run_tun(cfg: EngineConfig, opts: &TunOpts) -> Result<()> {
    if opts.print_routes_only {
        print_routing_instructions(opts);
        return Ok(());
    }

    // On Windows, TUN/WinTUN requires administrator privileges to create a kernel adapter.
    #[cfg(target_os = "windows")]
    if !is_running_as_admin() {
        return Err(EngineError::Internal(
            "TUN mode requires Administrator privileges — \
             re-launch the application as Administrator and try again"
                .to_owned(),
        ));
    }

    // On Windows, ensure wintun.dll is present before creating the TUN device
    #[cfg(target_os = "windows")]
    ensure_wintun().await?;

    // On Windows, start WinDivert-level QUIC bypass if evasion is enabled.
    // This intercepts outgoing UDP:443 packets and injects fake QUIC Initials
    // with whitelisted SNIs before the real packet.
    #[cfg(target_os = "windows")]
    let _quic_bypass_handle = if cfg.evasion.strategy.is_some() {
        match prime_net_engine_core::evasion::packet_intercept::quic_bypass::start(
            cfg.evasion.quic_fake_repeat_count.max(1),
        ) {
            Ok(h) => Some(h),
            Err(e) => {
                warn!(target: "tun_cmd", error = %e, "QUIC WinDivert bypass unavailable — QUIC will use SOCKS5 relay fallback");
                None
            }
        }
    } else {
        None
    };

    // 1. Start SOCKS5 in background.
    //    Detect the physical NIC IP before TUN routes are installed so outgoing
    //    relay sockets can be bound to it, preventing a TUN routing loop where
    //    outbound SOCKS5 connections get re-captured by the 0/1+128/1 TUN routes.
    let bypass_bind_ip = crate::auto_route::get_local_ip_for_default_route()
        .map(std::net::IpAddr::V4)
        .inspect(|ip| {
            info!(target: "tun_cmd", %ip, "physical NIC IP detected — relay sockets will bypass TUN");
        });
    if bypass_bind_ip.is_none() {
        warn!(
            target: "tun_cmd",
            "could not detect physical NIC IP; TUN routing loop prevention disabled"
        );
    }

    let socks_cfg = cfg.clone();
    let socks_bind = opts.socks_addr.to_string();
    let stats_file = opts.stats_file.clone();
    tokio::spawn(async move {
        let socks_opts = crate::socks_cmd::SocksOpts {
            bind: socks_bind,
            silent_drop: true,
            config_path: None,
            stats_file,
            bypass_bind_ip,
        };
        if let Err(e) = crate::socks_cmd::run_socks(socks_cfg, &socks_opts).await {
            error!("TUN background SOCKS5 error: {e}");
        }
    });
    // Wait until SOCKS5 is actually accepting connections (up to 20 s).
    // On first run, profile discovery runs for up to 10 s before SOCKS5 binds,
    // so the timeout must exceed the discovery window.
    let socks_ready = {
        let addr = opts.socks_addr;
        async move {
            for _ in 0..200u32 {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            false
        }
    };
    if !tokio::time::timeout(Duration::from_secs(20), socks_ready)
        .await
        .unwrap_or(false)
    {
        return Err(EngineError::Internal(
            "SOCKS5 did not become ready within 20 s".to_owned(),
        ));
    }

    // 2. Create TUN device
    let mut tun_config = tun2::Configuration::default();
    tun_config
        .tun_name(&opts.tun_name)
        .address(opts.tun_addr)
        .netmask(prefix_to_mask(opts.tun_prefix))
        .mtu(opts.mtu)
        .up();

    let tun_dev = tun2::create_as_async(&tun_config)
        .map_err(|e| EngineError::Internal(format!("TUN device creation failed: {e}")))?;

    info!(
        name = %opts.tun_name,
        addr = %opts.tun_addr,
        prefix = opts.tun_prefix,
        socks = %opts.socks_addr,
        auto_route = opts.auto_route,
        "TUN/VPN mode started"
    );

    // 2b. Auto-route: add 0/1 and 128/1 routes through TUN.
    let _route_guard = if opts.auto_route {
        match crate::auto_route::AutoRouteGuard::setup(
            &opts.tun_name,
            opts.tun_addr,
            opts.exclude.clone(),
        ) {
            Ok(guard) => {
                info!("auto-route: routing configured — all traffic now goes through TUN");
                Some(guard)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "auto-route setup failed — continuing without automatic routing; \
                     configure routes manually"
                );
                None
            }
        }
    } else {
        print_routing_instructions(opts);
        None
    };

    let (mut tun_reader, mut tun_writer) = tokio::io::split(tun_dev);

    // 3. Channels between async TUN I/O and the smoltcp thread
    let (to_smol_tx, to_smol_rx) = mpsc::unbounded_channel::<TunMsg>();
    let (smol_to_tun_tx, mut smol_to_tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let tun_ip = opts.tun_addr;

    // 4. Async TUN reader → smoltcp thread
    let to_smol_tx_clone = to_smol_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            let pkt = buf[..n].to_vec();

            // For TCP SYN: send PrepListen BEFORE the packet so smoltcp has a listening socket ready
            if is_ipv4_tcp_syn(&pkt) {
                if let Some((rewritten, nat_key, orig_dst_ip, dst_port)) =
                    rewrite_dnat(pkt.clone(), tun_ip)
                {
                    let _ = to_smol_tx_clone.send(TunMsg::PrepListen {
                        dst_port,
                        nat_key,
                        orig_dst_ip,
                    });
                    let _ = to_smol_tx_clone.send(TunMsg::Packet(rewritten));
                }
            } else if let Some((rewritten, _key, _orig, _port)) = rewrite_dnat(pkt, tun_ip) {
                let _ = to_smol_tx_clone.send(TunMsg::Packet(rewritten));
            }
        }
        warn!("TUN reader task ended");
    });

    // 5. Async TUN writer ← smoltcp thread
    tokio::spawn(async move {
        while let Some(pkt) = smol_to_tun_rx.recv().await {
            if tun_writer.write_all(&pkt).await.is_err() {
                break;
            }
        }
        warn!("TUN writer task ended");
    });

    // 6. smoltcp poll thread (blocking OS thread, runs tight loop)
    let rt_handle = tokio::runtime::Handle::current();
    let tun_prefix = opts.tun_prefix;
    let mtu = opts.mtu as usize;
    let socks_addr = opts.socks_addr;
    thread::spawn(move || {
        smoltcp_thread(
            tun_ip,
            tun_prefix,
            mtu,
            socks_addr,
            to_smol_rx,
            smol_to_tun_tx,
            rt_handle,
        );
    });

    // 7. Block until Ctrl-C
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| EngineError::Internal(format!("signal error: {e}")))?;
    info!("TUN/VPN mode shutting down");
    Ok(())
}

fn print_routing_instructions(opts: &TunOpts) {
    let name = &opts.tun_name;
    let addr = &opts.tun_addr;
    info!("─── TUN routing setup ───────────────────────────────");
    info!("Linux:");
    info!("  sudo ip route add 0.0.0.0/1 dev {name}");
    info!("  sudo ip route add 128.0.0.0/1 dev {name}");
    info!("macOS:");
    info!("  sudo route add -net 0.0.0.0/1 -interface {name}");
    info!("  sudo route add -net 128.0.0.0/1 -interface {name}");
    info!("Windows (PowerShell, as Administrator):");
    info!("  route add 0.0.0.0 mask 0.0.0.0 {addr} metric 1");
    info!("────────────────────────────────────────────────────");
    info!("To keep existing routes for SOCKS5 upstream, exclude them explicitly.");
}
