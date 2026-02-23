use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt};

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
        info!(
            target: "packet_bypass",
            "packet-level bypass backend is disabled by config/env"
        );
        return Ok(None);
    }

    #[cfg(windows)]
    {
        let require_admin = std::env::var("PRIME_PACKET_BYPASS_REQUIRE_ADMIN")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "on"
                )
            })
            .unwrap_or(false);
        if require_admin && !is_elevated() {
            return Err(EngineError::Config(
                "packet-level bypass strict admin mode is enabled but process is not elevated. restart terminal as Administrator or unset PRIME_PACKET_BYPASS_REQUIRE_ADMIN".to_owned(),
            ));
        }
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
                warn!(
                    target: "packet_bypass",
                    profile = profile.name.as_str(),
                    error = %e,
                    "packet-level bypass profile failed to start; trying next profile"
                );
                last_err = Some(e);
            }
        }
    }

    if children.is_empty() {
        return Err(last_err.unwrap_or_else(|| {
            EngineError::Config(
                "all packet-level bypass profiles failed to start; check PRIME_PACKET_BYPASS_BIN / PRIME_PACKET_BYPASS_ARGS".to_owned(),
            )
        }));
    }

    info!(
        target: "packet_bypass",
        profiles = children.len(),
        socks5_ports = ?socks5_ports,
        "packet-level bypass profile pool is active"
    );

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
            return None;
        }
        if let Some(v) = args[idx].strip_prefix("--port=") {
            return v.parse::<u16>().ok();
        }
        idx += 1;
    }
    None
}

fn packet_bypass_enabled(enabled_by_config: bool) -> bool {
    if !enabled_by_config {
        return false;
    }
    std::env::var("PRIME_PACKET_BYPASS")
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off"
            )
        })
        .unwrap_or(true)
}

fn parse_packet_args_from_env() -> Option<Vec<String>> {
    if let Ok(v) = std::env::var("PRIME_PACKET_BYPASS_ARGS") {
        let args = parse_shell_like_args(&v).unwrap_or_else(|| {
            v.split_whitespace()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        });
        if !args.is_empty() {
            return Some(args);
        }
    }
    None
}

fn parse_shell_like_args(input: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                cur.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        cur.push(ch);
    }
    if escaped {
        cur.push('\\');
    }
    if quote.is_some() {
        return None;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Some(out)
}

fn resolve_packet_profiles() -> Vec<PacketBypassProfile> {
    if let Some(args) = parse_packet_args_from_env() {
        return vec![PacketBypassProfile {
            name: "env".to_owned(),
            args,
        }];
    }
    default_bypass_profiles()
}

async fn get_release_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    RELEASE_CACHE
        .get_or_init(|| async { Mutex::new(HashMap::new()) })
        .await
}

async fn get_release_asset_sha256_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    RELEASE_ASSET_SHA256_CACHE
        .get_or_init(|| async { Mutex::new(HashMap::new()) })
        .await
}

async fn remember_release_asset_sha256(url: &str, sha256_hex: Option<String>) {
    let mut cache = get_release_asset_sha256_cache().await.lock().await;
    cache.insert(url.to_owned(), sha256_hex);
}

async fn release_asset_sha256_hex(url: &str) -> Option<String> {
    let cache = get_release_asset_sha256_cache().await.lock().await;
    cache.get(url).cloned().flatten()
}

fn parse_sha256_digest_field(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let digest = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .unwrap_or(trimmed)
        .trim();
    if parse_sha256_hex(digest).is_some() {
        return Some(digest.to_ascii_lowercase());
    }
    None
}

/// Finds a free TCP port on 127.0.0.1.
fn find_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(10801)
}

fn find_free_port_excluding(used: &HashSet<u16>) -> u16 {
    for _ in 0..64 {
        let p = find_free_port();
        if !used.contains(&p) {
            return p;
        }
    }
    for p in 20000u16..60000u16 {
        if !used.contains(&p) {
            return p;
        }
    }
    10801
}

fn set_port_arg(args: &mut Vec<String>, port: u16) {
    let port_str = port.to_string();
    for i in 0..args.len() {
        if args[i] == "--port" {
            if i + 1 < args.len() {
                args[i + 1] = port_str.clone();
            } else {
                args.push(port_str.clone());
            }
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

fn assign_unique_profile_ports(profiles: &mut [PacketBypassProfile]) {
    let mut used = HashSet::new();
    for profile in profiles {
        let port = find_free_port_excluding(&used);
        used.insert(port);
        set_port_arg(&mut profile.args, port);
    }
}

fn default_bypass_profiles() -> Vec<PacketBypassProfile> {
    #[cfg(target_os = "windows")]
    {
        let mut profiles = vec![
            PacketBypassProfile {
                name: "balanced".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--disorder".to_owned(),
                    "1".to_owned(),
                    "--oob".to_owned(),
                    "1".to_owned(),
                    "--tlsrec".to_owned(),
                    "1+s".to_owned(),
                    "--timeout".to_owned(),
                    "5".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "split-heavy".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--split".to_owned(),
                    "1+s".to_owned(),
                    "--oob".to_owned(),
                    "1".to_owned(),
                    "--tlsrec".to_owned(),
                    "1+s".to_owned(),
                    "--timeout".to_owned(),
                    "6".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "mixed-fast".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--disorder".to_owned(),
                    "1".to_owned(),
                    "--split".to_owned(),
                    "1+s".to_owned(),
                    "--oob".to_owned(),
                    "1".to_owned(),
                    "--tlsrec".to_owned(),
                    "1+s".to_owned(),
                    "--timeout".to_owned(),
                    "4".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "discord-robust".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--split".to_owned(),
                    "1".to_owned(),
                    "--oob".to_owned(),
                    "1".to_owned(),
                    "--tlsrec".to_owned(),
                    "1+s".to_owned(),
                    "--timeout".to_owned(),
                    "5".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "extreme-evasion".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--disorder".to_owned(),
                    "1".to_owned(),
                    "--split".to_owned(),
                    "1+s".to_owned(),
                    "--oob".to_owned(),
                    "1".to_owned(),
                    "--tlsrec".to_owned(),
                    "1+s".to_owned(),
                    "--mod-http".to_owned(),
                    "hl,host,hcsmix".to_owned(),
                    "--timeout".to_owned(),
                    "7".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "huge-fake".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--fake".to_owned(),
                    "-1".to_owned(),
                    "--ttl".to_owned(),
                    "5".to_owned(),
                    "--tlsrec".to_owned(),
                    "1+s".to_owned(),
                    "--timeout".to_owned(),
                    "6".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "super-safe".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--split".to_owned(),
                    "1+s".to_owned(),
                    "--timeout".to_owned(),
                    "5".to_owned(),
                ],
            },
        ];
        assign_unique_profile_ports(&mut profiles);
        profiles
    }
    #[cfg(target_os = "linux")]
    {
        let mut profiles = vec![
            PacketBypassProfile {
                name: "balanced".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--disorder".to_owned(),
                    "1".to_owned(),
                    "--fake-ttl".to_owned(),
                    "5".to_owned(),
                    "--oob".to_owned(),
                    "1".to_owned(),
                    "--timeout".to_owned(),
                    "5".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "split-heavy".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--split".to_owned(),
                    "1+s".to_owned(),
                    "--fake-ttl".to_owned(),
                    "5".to_owned(),
                    "--oob".to_owned(),
                    "1".to_owned(),
                    "--timeout".to_owned(),
                    "6".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "mixed-fast".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--disorder".to_owned(),
                    "1".to_owned(),
                    "--split".to_owned(),
                    "1+s".to_owned(),
                    "--fake-ttl".to_owned(),
                    "4".to_owned(),
                    "--oob".to_owned(),
                    "1".to_owned(),
                    "--timeout".to_owned(),
                    "4".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "extreme-evasion".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--disorder".to_owned(),
                    "1".to_owned(),
                    "--split".to_owned(),
                    "1+s".to_owned(),
                    "--oob".to_owned(),
                    "1".to_owned(),
                    "--fake-ttl".to_owned(),
                    "5".to_owned(),
                    "--mod-http".to_owned(),
                    "hl,host,hcsmix".to_owned(),
                    "--timeout".to_owned(),
                    "7".to_owned(),
                ],
            },
            PacketBypassProfile {
                name: "huge-fake".to_owned(),
                args: vec![
                    "--port".to_owned(),
                    find_free_port().to_string(),
                    "--fake".to_owned(),
                    "-1".to_owned(),
                    "--fake-ttl".to_owned(),
                    "5".to_owned(),
                    "--timeout".to_owned(),
                    "6".to_owned(),
                ],
            },
        ];
        assign_unique_profile_ports(&mut profiles);
        profiles
    }
    #[cfg(target_os = "macos")]
    {
        let mut profiles = vec![PacketBypassProfile {
            name: "default".to_owned(),
            args: vec!["--port".to_owned(), find_free_port().to_string()],
        }];
        assign_unique_profile_ports(&mut profiles);
        profiles
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        vec![]
    }
}

async fn start_packet_bypass_process(
    bin: &Path,
    profile: &PacketBypassProfile,
) -> Result<(Child, Vec<tokio::task::JoinHandle<()>>, Option<u16>)> {
    let socks5_port = parse_port_arg(&profile.args);
    info!(
        target: "packet_bypass",
        profile = profile.name.as_str(),
        binary = %bin.display(),
        args = ?profile.args,
        "starting packet-level bypass backend"
    );

    let mut cmd = Command::new(bin);
    cmd.args(profile.args.iter())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());

    let mut child = cmd.spawn().map_err(|e| {
        EngineError::Config(format!(
            "failed to start packet-level bypass backend '{}' profile '{}': {e}",
            bin.display(),
            profile.name
        ))
    })?;

    let mut log_tasks = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let profile_name = profile.name.clone();
        log_tasks.push(tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.trim().is_empty() {
                    info!(
                        target: "packet_bypass",
                        profile = profile_name.as_str(),
                        stream = "stdout",
                        "{line}"
                    );
                }
            }
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let profile_name = profile.name.clone();
        log_tasks.push(tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.trim().is_empty() {
                    info!(
                        target: "packet_bypass",
                        profile = profile_name.as_str(),
                        stream = "stderr",
                        "{line}"
                    );
                }
            }
        }));
    }

    tokio::time::sleep(Duration::from_millis(1500)).await;
    if let Some(status) = child.try_wait().map_err(EngineError::Io)? {
        return Err(EngineError::Config(format!(
            "packet-level bypass profile '{}' exited immediately with status {status}; check PRIME_PACKET_BYPASS_BIN / PRIME_PACKET_BYPASS_ARGS",
            profile.name
        )));
    }

    Ok((child, log_tasks, socks5_port))
}

fn bootstrap_install_dir() -> Result<PathBuf> {
    if let Ok(v) = std::env::var("PRIME_PT_BOOTSTRAP_DIR") {
        let p = PathBuf::from(v);
        ensure_dir_writable(&p).map_err(|e| {
            EngineError::Config(format!(
                "cannot use PRIME_PT_BOOTSTRAP_DIR '{}': {e}",
                p.display()
            ))
        })?;
        return Ok(p);
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("pt-tools"));
        }
    }
    if let Some(base) = dirs::data_local_dir() {
        candidates.push(base.join("prime-net-engine").join("tools"));
    }
    candidates.push(std::env::temp_dir().join("prime-net-engine-tools"));

    let mut errors: Vec<String> = Vec::new();
    for path in candidates {
        match ensure_dir_writable(&path) {
            Ok(()) => return Ok(path),
            Err(e) => errors.push(format!("{} ({e})", path.display())),
        }
    }
    Err(EngineError::Config(format!(
        "cannot create writable bootstrap directory for packet bypass; tried: {}",
        errors.join("; ")
    )))
}

async fn resolve_or_bootstrap_binary(install_dir: &Path) -> Result<PathBuf> {
    if let Ok(path) = std::env::var("PRIME_PACKET_BYPASS_BIN") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if p.exists() {
                return Ok(p);
            }
            warn!(
                target: "packet_bypass",
                path = %p.display(),
                "PRIME_PACKET_BYPASS_BIN is set but file does not exist; continuing auto-discovery"
            );
        } else {
            warn!(
                target: "packet_bypass",
                "PRIME_PACKET_BYPASS_BIN is set but empty; continuing auto-discovery"
            );
        }
    }

    let candidates = candidate_binary_names();
    for name in &candidates {
        if let Some(found) = which_binary(name) {
            return Ok(found);
        }
    }

    for name in &candidates {
        let p = install_dir.join(name);
        if p.exists() {
            return Ok(p);
        }
    }

    download_best_binary(install_dir).await
}

#[cfg(target_os = "windows")]
fn candidate_binary_names() -> Vec<String> {
    vec!["ciadpi.exe".into()]
}

#[cfg(target_os = "linux")]
fn candidate_binary_names() -> Vec<String> {
    vec!["ciadpi".into(), "byedpi".into()]
}

#[cfg(target_os = "macos")]
fn candidate_binary_names() -> Vec<String> {
    vec!["byedpi".into()]
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn candidate_binary_names() -> Vec<String> {
    vec![]
}

async fn resolve_latest_asset_url(repo: &str, asset_pattern: &str) -> Result<String> {
    let cache_key = format!("{repo}#{asset_pattern}");
    {
        let cache = get_release_cache().await.lock().await;
        if let Some(entry) = cache.get(&cache_key) {
            return entry.clone().ok_or_else(|| {
                EngineError::Config(format!(
                    "cached: no asset matching '{asset_pattern}' in latest release of {repo}"
                ))
            });
        }
    }

    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let result: Result<String> = async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .user_agent(format!(
                "prime-net-engine/{APP_VERSION} (packet-bypass-bootstrap)"
            ))
            .build()
            .map_err(|e| EngineError::Config(format!("failed to build api client: {e}")))?;

        let resp = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| EngineError::Config(format!("github api request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::FORBIDDEN {
            if resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                == Some("0")
            {
                warn!(
                    target: "packet_bypass",
                    "github api rate limit reached; cannot auto-download"
                );
            }
            return Err(EngineError::Config(format!(
                "github api returned {} for {repo}",
                resp.status()
            )));
        }

        if !resp.status().is_success() {
            return Err(EngineError::Config(format!(
                "github api returned {} for {repo}",
                resp.status()
            )));
        }

        let json: Value = resp
            .json()
            .await
            .map_err(|e| EngineError::Config(format!("failed to parse github api response: {e}")))?;

        let tag_name = json["tag_name"].as_str().unwrap_or("unknown");
        let assets = json["assets"]
            .as_array()
            .ok_or_else(|| EngineError::Config(format!("no assets in release for {repo}")))?;

        for asset in assets {
            let name = asset["name"].as_str().unwrap_or("");
            let download_url = asset["browser_download_url"].as_str().unwrap_or("");
            let digest_hex = asset["digest"]
                .as_str()
                .and_then(parse_sha256_digest_field);
            if (name == asset_pattern || name.contains(asset_pattern)) && !download_url.is_empty() {
                remember_release_asset_sha256(download_url, digest_hex.clone()).await;
                info!(
                    target: "packet_bypass",
                    repo = repo,
                    tag = tag_name,
                    asset = name,
                    has_sha256 = digest_hex.is_some(),
                    "resolved latest release asset"
                );
                return Ok(download_url.to_owned());
            }
        }

        Err(EngineError::Config(format!(
            "no asset matching '{asset_pattern}' found in latest release of {repo} (tag: {tag_name})"
        )))
    }
    .await;

    if let Ok(download_url) = &result {
        let mut cache = get_release_cache().await.lock().await;
        cache.insert(cache_key, Some(download_url.clone()));
    }

    result
}

async fn build_mirror_urls(filename: &str) -> Vec<String> {
    let mut out = Vec::new();

    if let Ok(v) = std::env::var("PRIME_PACKET_BYPASS_URLS") {
        out.extend(
            v.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
        );
    }
    if let Ok(v) = std::env::var("PRIME_PACKET_BYPASS_URL") {
        let url = v.trim();
        if !url.is_empty() {
            out.push(url.to_owned());
        }
    }
    if !out.is_empty() {
        return out;
    }

    #[cfg(target_os = "windows")]
    {
        match filename {
            "ciadpi.exe" => match std::env::consts::ARCH {
                "aarch64" | "arm64" => {
                    warn!(
                        target: "packet_bypass",
                        "no byedpi Windows build for aarch64"
                    );
                    vec![]
                }
                arch => {
                    let pattern = if matches!(arch, "x86" | "i686") {
                        "-i686-w64.zip"
                    } else {
                        "-x86_64-w64.zip"
                    };
                    match resolve_latest_asset_url("hufrea/byedpi", pattern).await {
                        Ok(url) => {
                            info!(
                                target: "packet_bypass",
                                url = %url,
                                "resolved byedpi zip via github api"
                            );
                            vec![url]
                        }
                        Err(e) => {
                            warn!(
                                target: "packet_bypass",
                                "byedpi api lookup failed: {e}"
                            );
                            vec![]
                        }
                    }
                }
            },
            _ => vec![],
        }
    }

    #[cfg(target_os = "linux")]
    {
        match filename {
            "ciadpi" | "byedpi" => {
                let arch_suffix = match std::env::consts::ARCH {
                    "x86_64" => Some("x86_64"),
                    "aarch64" | "arm64" => Some("aarch64"),
                    "arm" | "armv7" | "armv7l" => Some("armhf"),
                    _ => None,
                };
                match arch_suffix {
                    Some(arch_suffix) => {
                        let pattern = format!("ciadpi-{arch_suffix}");
                        match resolve_latest_asset_url("hufrea/byedpi", &pattern).await {
                            Ok(url) => vec![url],
                            Err(e) => {
                                warn!(
                                    target: "packet_bypass",
                                    error = %e,
                                    "api lookup failed for byedpi/linux asset"
                                );
                                vec![]
                            }
                        }
                    }
                    None => {
                        warn!(
                            target: "packet_bypass",
                            arch = std::env::consts::ARCH,
                            "unsupported linux architecture for byedpi asset"
                        );
                        vec![]
                    }
                }
            }
            _ => vec![],
        }
    }

    #[cfg(target_os = "macos")]
    {
        match filename {
            "byedpi" => {
                let darwin_arch = match std::env::consts::ARCH {
                    "aarch64" | "arm64" => Some("darwin-arm64"),
                    "x86_64" => Some("darwin-x86_64"),
                    _ => None,
                };
                match darwin_arch {
                    Some(darwin_arch) => {
                        match resolve_latest_asset_url("hufrea/byedpi", darwin_arch).await {
                            Ok(url) => vec![url],
                            Err(e) => {
                                warn!(
                                    target: "packet_bypass",
                                    error = %e,
                                    "api lookup failed for byedpi/macos asset"
                                );
                                vec![]
                            }
                        }
                    }
                    None => {
                        warn!(
                            target: "packet_bypass",
                            arch = std::env::consts::ARCH,
                            "unsupported macos architecture for byedpi asset"
                        );
                        vec![]
                    }
                }
            }
            _ => vec![],
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = filename;
        vec![]
    }
}
