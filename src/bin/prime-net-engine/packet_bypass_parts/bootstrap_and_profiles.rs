use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::version::APP_VERSION;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, OnceCell};
use tracing::{info, warn};

static RELEASE_CACHE: OnceCell<Mutex<HashMap<String, Option<String>>>> = OnceCell::const_new();
static RELEASE_ASSET_SHA256_CACHE: OnceCell<Mutex<HashMap<String, Option<String>>>> =
    OnceCell::const_new();

#[derive(Debug)]
pub struct PacketBypassGuard {
    children: Vec<Child>,
    log_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub socks5_ports: Vec<u16>,
}

#[derive(Debug, Clone)]
struct PacketBypassProfile {
    name: String,
    args: Vec<String>,
}

impl Drop for PacketBypassGuard {
    fn drop(&mut self) {
        for mut child in self.children.drain(..) {
            let _ = child.start_kill();
        }
        for task in self.log_tasks.drain(..) {
            task.abort();
        }
    }
}

impl PacketBypassGuard {
    pub fn socks5_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.socks5_ports
            .iter()
            .copied()
            .map(|p| std::net::SocketAddr::from(([127, 0, 0, 1], p)))
            .collect()
    }
}

pub async fn maybe_start_packet_bypass(
    enabled_by_config: bool,
) -> Result<Option<PacketBypassGuard>> {
    if !packet_bypass_enabled(enabled_by_config) {
        return Ok(None);
    }

    let install_dir = bootstrap_install_dir()?;
    let bin = resolve_or_bootstrap_binary(&install_dir).await?;
    let profiles = resolve_packet_profiles();
    let mut children = Vec::new();
    let mut log_tasks = Vec::new();
    let mut socks5_ports = Vec::new();
    let mut last_err: Option<EngineError> = None;

    for profile in profiles {
        match start_packet_bypass_process(&bin, &profile).await {
            Ok((child, mut tasks, socks5_port)) => {
                children.push(child);
                log_tasks.append(&mut tasks);
                if let Some(port) = socks5_port {
                    socks5_ports.push(port);
                }
            }
            Err(e) => {
                warn!(target: "packet_bypass", profile = %profile.name, error = %e, "profile failed to start");
                last_err = Some(e);
            }
        }
    }

    if children.is_empty() {
        return Err(last_err.unwrap_or_else(|| {
            EngineError::Config("all packet-level bypass profiles failed to start".to_owned())
        }));
    }

    info!(target: "packet_bypass", count = children.len(), ports = ?socks5_ports, "packet-level bypass active");
    Ok(Some(PacketBypassGuard {
        children,
        log_tasks,
        socks5_ports,
    }))
}

fn parse_port_arg(args: &[String]) -> Option<u16> {
    let mut idx = 0usize;
    while idx < args.len() {
        if args[idx] == "--port" {
            if let Some(v) = args.get(idx + 1) {
                return v.parse::<u16>().ok();
            }
        }
        if let Some(v) = args[idx].strip_prefix("--port=") {
            return v.parse::<u16>().ok();
        }
        idx += 1;
    }
    None
}

fn packet_bypass_enabled(enabled_by_config: bool) -> bool {
    if !enabled_by_config { return false; }
    std::env::var("PRIME_PACKET_BYPASS")
        .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off"))
        .unwrap_or(true)
}

fn resolve_packet_profiles() -> Vec<PacketBypassProfile> {
    if let Ok(v) = std::env::var("PRIME_PACKET_BYPASS_ARGS") {
        if !v.trim().is_empty() {
            return vec![PacketBypassProfile {
                name: "env".to_owned(),
                args: v.split_whitespace().map(|s| s.to_owned()).collect(),
            }];
        }
    }
    default_bypass_profiles()
}

fn find_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(10801)
}

fn set_port_arg(args: &mut Vec<String>, port: u16) {
    let port_str = port.to_string();
    for i in 0..args.len() {
        if args[i] == "--port" {
            if i + 1 < args.len() { args[i + 1] = port_str.clone(); }
            return;
        }
        if args[i].starts_with("--port=") {
            args[i] = format!("--port={port_str}");
            return;
        }
    }
    args.push("--port".to_owned());
    args.push(port_str);
}

fn default_bypass_profiles() -> Vec<PacketBypassProfile> {
    #[cfg(target_os = "windows")]
    {
        let mut profiles = vec![
            PacketBypassProfile {
                name: "clean-split-1".to_owned(),
                args: vec!["--split".into(), "1".into(), "--timeout".into(), "10".into()],
            },
            PacketBypassProfile {
                name: "tlsrec-1s".to_owned(),
                args: vec!["--tlsrec".into(), "1+s".into(), "--timeout".into(), "10".into()],
            },
            PacketBypassProfile {
                name: "discord-optimized".to_owned(),
                args: vec!["--split".into(), "1".into(), "--tlsrec".into(), "1+s".into(), "--timeout".into(), "10".into()],
            },
        ];
        for p in &mut profiles {
            set_port_arg(&mut p.args, find_free_port());
        }
        profiles
    }
    #[cfg(not(target_os = "windows"))]
    { vec![] }
}

async fn start_packet_bypass_process(
    bin: &Path,
    profile: &PacketBypassProfile,
) -> Result<(Child, Vec<tokio::task::JoinHandle<()>>, Option<u16>)> {
    let socks5_port = parse_port_arg(&profile.args);
    let mut cmd = Command::new(bin);
    cmd.args(&profile.args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());

    let mut child = cmd.spawn().map_err(EngineError::Io)?;
    let mut log_tasks = Vec::new();
    
    if let Some(stdout) = child.stdout.take() {
        let name = profile.name.clone();
        log_tasks.push(tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                info!(target: "packet_bypass", profile = %name, "{line}");
            }
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let name = profile.name.clone();
        log_tasks.push(tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                info!(target: "packet_bypass", profile = %name, "{line}");
            }
        }));
    }

    tokio::time::sleep(Duration::from_millis(1000)).await;
    if let Some(status) = child.try_wait().map_err(EngineError::Io)? {
        return Err(EngineError::Config(format!("profile {} exited with {}", profile.name, status)));
    }

    Ok((child, log_tasks, socks5_port))
}

fn bootstrap_install_dir() -> Result<PathBuf> {
    let p = if let Ok(v) = std::env::var("PRIME_PT_BOOTSTRAP_DIR") {
        PathBuf::from(v)
    } else {
        std::env::current_exe()?.parent().unwrap().join("pt-tools")
    };
    let _ = fs::create_dir_all(&p);
    Ok(p)
}

async fn resolve_or_bootstrap_binary(install_dir: &Path) -> Result<PathBuf> {
    let name = if cfg!(windows) { "ciadpi.exe" } else { "ciadpi" };
    let p = install_dir.join(name);
    if p.exists() { return Ok(p); }
    // Note: this depends on the function being available in the same binary
    super::download_and_permissions::download_best_binary(install_dir).await
}
