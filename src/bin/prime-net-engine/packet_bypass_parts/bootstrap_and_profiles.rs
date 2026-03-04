use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration};
use std::fs;
use std::sync::{Mutex, OnceLock};

use prime_net_engine_core::error::{EngineError, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{info, warn};

static RELEASE_ASSET_SHA256_CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
const PACKET_BYPASS_REPO: &str = "hufrea/byedpi";
const PACKET_BYPASS_STABLE_TAG: &str = "v0.17.3";

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
        match start_packet_bypass_process_with_port_retry(&bin, &profile).await {
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

pub fn candidate_binary_names() -> Vec<String> {
    if cfg!(windows) { vec!["ciadpi.exe".into()] } else { vec!["ciadpi".into()] }
}

pub async fn build_mirror_urls(_name: &str) -> Vec<String> {
    let tag = resolve_packet_bypass_tag().await;
    let version = release_asset_version(&tag);
    let compact = version.replace('.', "");
    let mut assets = Vec::new();
    if cfg!(windows) {
        assets.push(format!("byedpi-{version}-x86_64-w64.zip"));
        if compact != version {
            assets.push(format!("byedpi-{compact}-x86_64-w64.zip"));
        }
    } else {
        assets.push(format!("byedpi-{version}-x86_64-linux.zip"));
        if compact != version {
            assets.push(format!("byedpi-{compact}-x86_64-linux.zip"));
        }
    }
    assets
        .into_iter()
        .map(|asset| format!("https://github.com/{}/releases/download/{tag}/{asset}", PACKET_BYPASS_REPO))
        .collect()
}

async fn resolve_packet_bypass_tag() -> String {
    if let Ok(v) = std::env::var("PRIME_PACKET_BYPASS_TAG") {
        let pinned = v.trim();
        if !pinned.is_empty() {
            return pinned.to_owned();
        }
    }
    // Strict trust mode: pin to stable tag by default.
    // Explicit custom pin is still allowed via PRIME_PACKET_BYPASS_TAG.
    if env_flag_enabled("PRIME_PACKET_BYPASS_USE_LATEST") {
        warn!(
            target: "packet_bypass",
            env = "PRIME_PACKET_BYPASS_USE_LATEST",
            stable = PACKET_BYPASS_STABLE_TAG,
            "ignoring latest-tag auto-discovery in strict trust mode; use PRIME_PACKET_BYPASS_TAG to pin an explicit tag"
        );
    }
    PACKET_BYPASS_STABLE_TAG.to_owned()
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn release_asset_version(tag: &str) -> String {
    let trimmed = tag.trim().trim_start_matches(['v', 'V']);
    if trimmed.is_empty() {
        return PACKET_BYPASS_STABLE_TAG
            .trim_start_matches('v')
            .trim_start_matches("0.")
            .to_owned();
    }
    let mut parts: Vec<&str> = trimmed.split('.').filter(|p| !p.is_empty()).collect();
    let numeric = parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()));
    if numeric && parts.first().copied() == Some("0") && parts.len() > 1 {
        parts.remove(0);
    }
    if numeric && !parts.is_empty() {
        return parts.join(".");
    }
    trimmed.to_owned()
}

pub fn release_asset_sha256_hex(url: &str) -> Option<String> {
    let cache = RELEASE_ASSET_SHA256_CACHE.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    cache.get(url).cloned().flatten()
}

fn parse_port_arg(args: &[String]) -> Option<u16> {
    let mut idx = 0usize;
    while idx < args.len() {
        if args[idx] == "--port" {
            if let Some(v) = args.get(idx + 1) { return v.parse::<u16>().ok(); }
        }
        if let Some(v) = args[idx].strip_prefix("--port=") { return v.parse::<u16>().ok(); }
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
            let parsed = parse_env_packet_profiles(&v);
            if !parsed.is_empty() {
                return parsed;
            }
        }
    }
    default_bypass_profiles()
}

fn parse_env_packet_profiles(raw: &str) -> Vec<PacketBypassProfile> {
    let chunks: Vec<&str> = raw
        .split(|c| c == ';' || c == '\n')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if chunks.is_empty() {
        return Vec::new();
    }

    if chunks.len() == 1 {
        return vec![PacketBypassProfile {
            name: "env".to_owned(),
            args: chunks[0]
                .split_whitespace()
                .map(|s| s.to_owned())
                .collect(),
        }];
    }

    chunks
        .into_iter()
        .enumerate()
        .map(|(idx, chunk)| PacketBypassProfile {
            name: format!("env-{}", idx + 1),
            args: chunk.split_whitespace().map(|s| s.to_owned()).collect(),
        })
        .filter(|profile| !profile.args.is_empty())
        .collect()
}

fn find_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(10801)
}

fn set_port_arg(args: &mut Vec<String>, port: u16) {
    let port_str = port.to_string();
    for i in 0..args.len() {
        if args[i] == "--port" {
            if i + 1 < args.len() { args[i + 1] = port_str.clone(); }
            return;
        }
        if args[i].starts_with("--port=") { args[i] = format!("--port={port_str}"); return; }
    }
    args.push("--port".to_owned()); args.push(port_str);
}

fn default_bypass_profiles() -> Vec<PacketBypassProfile> {
    let mut profiles = vec![
        PacketBypassProfile {
            name: "modern-disorder-split".to_owned(),
            args: vec![
                "--split".into(), "1".into(),
                "--disorder".into(), "3+s".into(),
                "--mod-http".into(), "h,d".into(),
                "--auto".into(), "none".into(),
                "--timeout".into(), "10".into(),
            ],
        },
        PacketBypassProfile {
            name: "tlsrec-fake-ttl".to_owned(),
            args: vec![
                "--tlsrec".into(), "3+s".into(),
                "--fake".into(), "-1".into(),
                "--ttl".into(), "5".into(),
                "--auto".into(), "none".into(),
                "--timeout".into(), "10".into(),
            ],
        },
        PacketBypassProfile {
            name: "aggressive-disorder-fake".to_owned(),
            args: vec![
                "--disorder".into(), "1".into(),
                "--fake".into(), "-1".into(),
                "--udp-fake".into(), "-1".into(),
                "--auto".into(), "none".into(),
                "--timeout".into(), "10".into(),
            ],
        },
        PacketBypassProfile {
            name: "sni-split-oob".to_owned(),
            args: vec![
                "--split".into(), "2".into(),
                "--oob".into(), "1".into(),
                "--tlsrec".into(), "3+s".into(),
                "--auto".into(), "none".into(),
                "--timeout".into(), "10".into(),
            ],
        },
    ];
    for p in &mut profiles {
        set_port_arg(&mut p.args, find_free_port());
    }
    profiles
}

async fn start_packet_bypass_process(bin: &Path, profile: &PacketBypassProfile) -> Result<(Child, Vec<tokio::task::JoinHandle<()>>, Option<u16>)> {
    let socks5_port = parse_port_arg(&profile.args);
    let mut cmd = Command::new(bin);
    cmd.args(&profile.args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .env("HTTP_PROXY", "")
        .env("HTTPS_PROXY", "")
        .env("ALL_PROXY", "")
        .env("no_proxy", "localhost,127.0.0.1")
        .env("NO_PROXY", "localhost,127.0.0.1")
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(EngineError::Io)?;
    let mut log_tasks = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let name = profile.name.clone();
        log_tasks.push(tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await { info!(target: "packet_bypass", profile = %name, "{line}"); }
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let name = profile.name.clone();
        log_tasks.push(tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await { info!(target: "packet_bypass", profile = %name, "{line}"); }
        }));
    }
    tokio::time::sleep(Duration::from_millis(1000)).await;
    if let Some(status) = child.try_wait().map_err(EngineError::Io)? { return Err(EngineError::Config(format!("profile {} exited with {}", profile.name, status))); }
    Ok((child, log_tasks, socks5_port))
}

async fn start_packet_bypass_process_with_port_retry(
    bin: &Path,
    profile: &PacketBypassProfile,
) -> Result<(Child, Vec<tokio::task::JoinHandle<()>>, Option<u16>)> {
    let mut candidate = profile.clone();
    let has_port = parse_port_arg(&candidate.args).is_some();
    let mut last_err: Option<EngineError> = None;
    for attempt in 0..3 {
        if attempt > 0 && has_port {
            set_port_arg(&mut candidate.args, find_free_port());
        }
        match start_packet_bypass_process(bin, &candidate).await {
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        EngineError::Config("packet bypass process failed to start".to_owned())
    }))
}

fn bootstrap_install_dir() -> Result<PathBuf> {
    let p = if let Ok(v) = std::env::var("PRIME_PT_BOOTSTRAP_DIR") {
        PathBuf::from(v)
    } else {
        std::env::current_exe()?
            .parent()
            .map(|p| p.join("pt-tools"))
            .unwrap_or_else(|| PathBuf::from("pt-tools"))
    };
    let _ = fs::create_dir_all(&p);
    Ok(p)
}

async fn resolve_or_bootstrap_binary(install_dir: &Path) -> Result<PathBuf> {
    let name = if cfg!(windows) { "ciadpi.exe" } else { "ciadpi" };
    let p = install_dir.join(name);
    if p.exists() { return Ok(p); }
    download_best_binary(install_dir).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_asset_version_strips_v_and_leading_zero_major() {
        assert_eq!(release_asset_version("v0.17.3"), "17.3");
        assert_eq!(release_asset_version("0.13.1"), "13.1");
        assert_eq!(release_asset_version("v1.2.3"), "1.2.3");
    }

    #[test]
    fn release_asset_version_keeps_non_numeric_tags() {
        assert_eq!(release_asset_version("nightly-2025-10-01"), "nightly-2025-10-01");
    }

    #[test]
    fn parse_env_packet_profiles_supports_multiple_entries() {
        let raw = "--disorder 1 --fake -1; --split 1+s --auto=torst";
        let parsed = parse_env_packet_profiles(raw);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "env-1");
        assert_eq!(parsed[1].name, "env-2");
        assert!(parsed[0].args.iter().any(|a| a == "--fake"));
        assert!(parsed[1].args.iter().any(|a| a == "--split"));
    }

    #[tokio::test]
    async fn resolve_packet_bypass_tag_uses_stable_by_default() {
        std::env::remove_var("PRIME_PACKET_BYPASS_TAG");
        std::env::remove_var("PRIME_PACKET_BYPASS_USE_LATEST");
        let tag = resolve_packet_bypass_tag().await;
        assert_eq!(tag, PACKET_BYPASS_STABLE_TAG);
    }

    #[tokio::test]
    async fn resolve_packet_bypass_tag_ignores_use_latest_in_strict_mode() {
        std::env::remove_var("PRIME_PACKET_BYPASS_TAG");
        std::env::set_var("PRIME_PACKET_BYPASS_USE_LATEST", "1");
        let tag = resolve_packet_bypass_tag().await;
        assert_eq!(tag, PACKET_BYPASS_STABLE_TAG);
        std::env::remove_var("PRIME_PACKET_BYPASS_USE_LATEST");
    }
}
