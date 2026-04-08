//! Platform-specific routing setup for TUN/VPN mode.
//!
//! Adds two /1 routes through the TUN interface so all internet traffic is
//! captured, then cleans them up on [`AutoRouteGuard`] drop.  This is
//! intentionally split from the default route (0.0.0.0/0) so that any
//! existing default gateway is NOT removed — it remains as a fallback.
//!
//! # Routing loop warning
//! In native-desync mode the engine's own outbound sockets also go through
//! the TUN.  To prevent a loop, pass the bypass-proxy server CIDRs via
//! `exclude` so they are routed directly through the original gateway.

use std::net::Ipv4Addr;
use std::process::Command;

use tracing::{info, warn};

/// An IPv4 network as (address, prefix_length).
pub type Cidr = (Ipv4Addr, u8);

/// Parse `"1.2.3.4/24"` or `"1.2.3.4"` (host, /32) into a [`Cidr`].
pub fn parse_cidr(s: &str) -> Option<Cidr> {
    if let Some((ip_s, prefix_s)) = s.split_once('/') {
        let ip: Ipv4Addr = ip_s.parse().ok()?;
        let prefix: u8 = prefix_s.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        Some((ip, prefix))
    } else {
        let ip: Ipv4Addr = s.parse().ok()?;
        Some((ip, 32))
    }
}

/// Convert a prefix length (0-32) to an IPv4 dotted-decimal netmask.
pub fn prefix_to_mask_str(prefix: u8) -> String {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let o = mask.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

// ── Gateway detection ─────────────────────────────────────────────────────────

/// Return the current system default IPv4 gateway, if detectable.
pub fn get_default_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "windows")]
    return gateway_windows();
    #[cfg(target_os = "linux")]
    return gateway_linux();
    #[cfg(target_os = "macos")]
    return gateway_macos();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    return None;
}

/// Return the local interface IP that the default route is associated with.
///
/// Used to bind outgoing sockets to the physical NIC so they bypass TUN routing.
pub fn get_local_ip_for_default_route() -> Option<Ipv4Addr> {
    #[cfg(target_os = "windows")]
    return local_ip_windows();
    #[cfg(target_os = "linux")]
    return local_ip_linux();
    #[cfg(target_os = "macos")]
    return local_ip_macos();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    return None;
}

#[cfg(target_os = "windows")]
fn gateway_windows() -> Option<Ipv4Addr> {
    // `route print 0.0.0.0` output contains a line like:
    //   0.0.0.0          0.0.0.0    192.168.1.1    192.168.1.100     25
    let out = Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            return cols[2].parse().ok();
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn local_ip_windows() -> Option<Ipv4Addr> {
    // Same output as gateway_windows(); column 4 is the interface (local) IP.
    //   0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.100  25
    let out = Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            return cols[3].parse().ok();
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn gateway_linux() -> Option<Ipv4Addr> {
    // `ip route show default` → "default via 192.168.1.1 dev eth0 …"
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "via" {
                if let Some(gw) = it.next() {
                    return gw.parse().ok();
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn local_ip_linux() -> Option<Ipv4Addr> {
    // `ip route get 1.1.1.1` → "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100 …"
    let out = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "src" {
                if let Some(ip) = it.next() {
                    return ip.parse().ok();
                }
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn gateway_macos() -> Option<Ipv4Addr> {
    // `netstat -rn -f inet` → "default  192.168.1.1  UGSc  …"
    let out = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.first().map_or(false, |c| *c == "default") && cols.len() >= 2 {
            return cols[1].parse().ok();
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn local_ip_macos() -> Option<Ipv4Addr> {
    // `route get default` → line containing "interface:" and then a name, then
    // `ifconfig <iface>` for the inet address.  Simpler: use `route get 1.1.1.1`.
    //   route to: 1.1.1.1  …  interface: en0  …  if address: 192.168.1.100
    let out = Command::new("route")
        .args(["get", "1.1.1.1"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("if address:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

// ── Route manipulation ────────────────────────────────────────────────────────

fn add_tun_routes(tun_name: &str, tun_addr: Ipv4Addr) -> Result<(), String> {
    // Split the default route into two /1 halves so the original 0/0 route
    // is not removed and DNS/management traffic can still reach the real GW.
    add_route_via_tun(tun_name, tun_addr, "0.0.0.0", 1)?;
    add_route_via_tun(tun_name, tun_addr, "128.0.0.0", 1)?;
    Ok(())
}

fn del_tun_routes(tun_name: &str, tun_addr: Ipv4Addr) {
    del_route_via_tun(tun_name, tun_addr, "0.0.0.0", 1);
    del_route_via_tun(tun_name, tun_addr, "128.0.0.0", 1);
}

fn add_exclude_routes(gateway: Ipv4Addr, exclude: &[Cidr]) -> Result<(), String> {
    for &(ip, prefix) in exclude {
        add_route_via_gateway(gateway, ip, prefix)?;
    }
    Ok(())
}

fn del_exclude_routes(gateway: Ipv4Addr, exclude: &[Cidr]) {
    for &(ip, prefix) in exclude {
        del_route_via_gateway(gateway, ip, prefix);
    }
}

// ── Per-platform route add/del ────────────────────────────────────────────────

fn add_route_via_tun(
    tun_name: &str,
    tun_addr: Ipv4Addr,
    net: &str,
    prefix: u8,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let _ = tun_name; // Windows routes by gateway IP, not interface name
        let mask = prefix_to_mask_str(prefix);
        let out = Command::new("route")
            .args([
                "add",
                net,
                "MASK",
                &mask,
                &tun_addr.to_string(),
                "METRIC",
                "1",
            ])
            .output()
            .map_err(|e| format!("route add failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "route add {net}/{prefix} via TUN failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ip")
            .args(["route", "add", &format!("{net}/{prefix}"), "dev", tun_name])
            .output()
            .map_err(|e| format!("ip route add failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "ip route add {net}/{prefix} dev {tun_name} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route")
            .args([
                "add",
                "-net",
                &format!("{net}/{prefix}"),
                "-interface",
                tun_name,
            ])
            .output()
            .map_err(|e| format!("route add failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "route add -net {net}/{prefix} -interface {tun_name} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        return Ok(());
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (tun_name, tun_addr, net, prefix);
        Err("auto-route is not supported on this platform".to_owned())
    }
}

fn del_route_via_tun(tun_name: &str, tun_addr: Ipv4Addr, net: &str, prefix: u8) {
    #[cfg(target_os = "windows")]
    {
        let _ = tun_name; // Windows routes by gateway IP, not interface name
        let mask = prefix_to_mask_str(prefix);
        let _ = Command::new("route")
            .args(["delete", net, "MASK", &mask, &tun_addr.to_string()])
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("ip")
            .args(["route", "del", &format!("{net}/{prefix}"), "dev", tun_name])
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route")
            .args([
                "delete",
                "-net",
                &format!("{net}/{prefix}"),
                "-interface",
                tun_name,
            ])
            .output();
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (tun_name, tun_addr, net, prefix);
    }
}

fn add_route_via_gateway(gateway: Ipv4Addr, ip: Ipv4Addr, prefix: u8) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let mask = prefix_to_mask_str(prefix);
        let out = Command::new("route")
            .args(["add", &ip.to_string(), "MASK", &mask, &gateway.to_string()])
            .output()
            .map_err(|e| format!("route add failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "route add {ip}/{prefix} via {gateway} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("ip")
            .args([
                "route",
                "add",
                &format!("{ip}/{prefix}"),
                "via",
                &gateway.to_string(),
            ])
            .output()
            .map_err(|e| format!("ip route add failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "ip route add {ip}/{prefix} via {gateway} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route")
            .args([
                "add",
                "-net",
                &format!("{ip}/{prefix}"),
                &gateway.to_string(),
            ])
            .output()
            .map_err(|e| format!("route add failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "route add -net {ip}/{prefix} {gateway} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        return Ok(());
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (gateway, ip, prefix);
        Err("auto-route is not supported on this platform".to_owned())
    }
}

fn del_route_via_gateway(gateway: Ipv4Addr, ip: Ipv4Addr, prefix: u8) {
    #[cfg(target_os = "windows")]
    {
        let mask = prefix_to_mask_str(prefix);
        let _ = Command::new("route")
            .args([
                "delete",
                &ip.to_string(),
                "MASK",
                &mask,
                &gateway.to_string(),
            ])
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("ip")
            .args([
                "route",
                "del",
                &format!("{ip}/{prefix}"),
                "via",
                &gateway.to_string(),
            ])
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route")
            .args([
                "delete",
                "-net",
                &format!("{ip}/{prefix}"),
                &gateway.to_string(),
            ])
            .output();
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (gateway, ip, prefix);
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// RAII guard: sets up routes on [`AutoRouteGuard::setup`], removes them on [`Drop`].
///
/// Routes added:
/// - `0.0.0.0/1` and `128.0.0.0/1` through the TUN interface
/// - For each excluded CIDR: a host/net route via the original gateway
pub struct AutoRouteGuard {
    tun_name: String,
    tun_addr: Ipv4Addr,
    exclude: Vec<Cidr>,
    gateway: Option<Ipv4Addr>,
}

impl AutoRouteGuard {
    /// Set up routing, returning a guard that removes routes on drop.
    ///
    /// Detects the current default gateway automatically.  Pass
    /// `exclude_cidrs` for IPs/networks that must bypass the TUN (e.g. your
    /// external proxy server IP, or corporate intranet ranges).
    pub fn setup(
        tun_name: &str,
        tun_addr: Ipv4Addr,
        exclude_cidrs: Vec<Cidr>,
    ) -> Result<Self, String> {
        let gateway = get_default_gateway();
        if let Some(gw) = gateway {
            info!(
                tun = tun_name,
                gw = %gw,
                "auto-route: detected default gateway"
            );
        } else {
            warn!(
                tun = tun_name,
                "auto-route: could not detect default gateway — exclude routes will be skipped"
            );
        }

        add_tun_routes(tun_name, tun_addr)?;
        info!(
            tun = tun_name,
            "auto-route: 0.0.0.0/1 and 128.0.0.0/1 → TUN"
        );

        if let Some(gw) = gateway {
            if !exclude_cidrs.is_empty() {
                add_exclude_routes(gw, &exclude_cidrs)?;
                for &(ip, prefix) in &exclude_cidrs {
                    info!(%ip, prefix, %gw, "auto-route: exclude → gateway");
                }
            }
        }

        Ok(Self {
            tun_name: tun_name.to_owned(),
            tun_addr,
            exclude: exclude_cidrs,
            gateway,
        })
    }
}

impl Drop for AutoRouteGuard {
    fn drop(&mut self) {
        del_tun_routes(&self.tun_name, self.tun_addr);
        info!(tun = %self.tun_name, "auto-route: removed TUN routes");

        if let Some(gw) = self.gateway {
            del_exclude_routes(gw, &self.exclude);
        }
    }
}
