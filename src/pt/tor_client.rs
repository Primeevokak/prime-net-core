use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command as StdCommand;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tracing::info;

use crate::config::{Obfs4PtConfig, SnowflakePtConfig};
use crate::error::{EngineError, Result};

#[derive(Debug)]
pub struct TorClientGuard {
    socks_addr: SocketAddr,
    child: Option<Child>,
    data_dir: PathBuf,
    _log_task: Option<tokio::task::JoinHandle<()>>,
}

impl TorClientGuard {
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }
}

impl Drop for TorClientGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        if let Some(t) = self._log_task.take() {
            t.abort();
        }
        // Best-effort cleanup.
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

pub async fn start_tor_obfs4(bind: &str, cfg: &Obfs4PtConfig) -> Result<TorClientGuard> {
    let bind_result = normalize_bind(bind).await?;
    let socks_addr = bind_result.addr;
    let data_dir = make_temp_dir("tor-obfs4")?;
    let tor_bin = ensure_pt_binary("tor", &cfg.tor_bin).await?;
    let obfs4_bin = ensure_pt_binary("obfs4proxy", &cfg.obfs4proxy_bin).await?;

    let iat_mode = cfg.iat_mode.unwrap_or(0);
    let mut bridge_line = format!("Bridge obfs4 {}", cfg.server.trim());
    if let Some(fp) = cfg.fingerprint.as_deref() {
        let fp = fp.trim();
        if !fp.is_empty() {
            bridge_line.push(' ');
            bridge_line.push_str(fp);
        }
    }
    bridge_line.push_str(&format!(" cert={} iat-mode={iat_mode}", cfg.cert.trim()));

    let plugin_line = torrc_client_transport_plugin_line("obfs4", &obfs4_bin, &cfg.obfs4proxy_args);

    let torrc = render_torrc(
        &data_dir,
        socks_addr,
        &["UseBridges 1".to_owned(), plugin_line, bridge_line],
    );

    // Drop the ephemeral port guard right before spawning Tor so that
    // the port is freed for Tor to bind.  This minimises the TOCTOU
    // window compared to dropping early.
    drop(bind_result._ephemeral_guard);

    spawn_tor_and_wait_ready(socks_addr, &data_dir, &tor_bin, &cfg.tor_args, &torrc).await
}

pub async fn start_tor_snowflake(bind: &str, cfg: &SnowflakePtConfig) -> Result<TorClientGuard> {
    let bind_result = normalize_bind(bind).await?;
    let socks_addr = bind_result.addr;
    let data_dir = make_temp_dir("tor-snowflake")?;
    let tor_bin = ensure_pt_binary("tor", &cfg.tor_bin).await?;
    let snowflake_bin = ensure_pt_binary("snowflake-client", &cfg.snowflake_bin).await?;

    let mut args: Vec<String> = Vec::new();
    if let Some(b) = cfg.broker.as_deref() {
        if !b.trim().is_empty() {
            args.push("-broker".to_owned());
            args.push(b.trim().to_owned());
        }
    }
    if let Some(front) = cfg.front.as_deref() {
        if !front.trim().is_empty() {
            args.push("-front".to_owned());
            args.push(front.trim().to_owned());
        }
    }
    if let Some(amp) = cfg.amp_cache.as_deref() {
        if !amp.trim().is_empty() {
            args.push("-ampcache".to_owned());
            args.push(amp.trim().to_owned());
        }
    }
    for s in &cfg.stun_servers {
        let s = s.trim();
        if !s.is_empty() {
            args.push("-stun".to_owned());
            args.push(s.to_owned());
        }
    }
    args.extend(cfg.snowflake_args.iter().cloned());

    let plugin_line = torrc_client_transport_plugin_line("snowflake", &snowflake_bin, &args);

    // Snowflake bridge address is effectively a placeholder in Tor config. Keep it configurable.
    let bridge = cfg
        .bridge
        .as_deref()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "192.0.2.3:1".to_owned());

    let torrc = render_torrc(
        &data_dir,
        socks_addr,
        &[
            "UseBridges 1".to_owned(),
            plugin_line,
            format!("Bridge snowflake {bridge}"),
        ],
    );

    // Drop the ephemeral port guard right before spawning Tor so that
    // the port is freed for Tor to bind.  This minimises the TOCTOU
    // window compared to dropping early.
    drop(bind_result._ephemeral_guard);

    spawn_tor_and_wait_ready(socks_addr, &data_dir, &tor_bin, &cfg.tor_args, &torrc).await
}

async fn ensure_pt_binary(tool: &str, configured: &str) -> Result<String> {
    let requested = configured.trim();
    if requested.is_empty() {
        return Err(EngineError::Config(format!(
            "pt binary path for '{tool}' is empty"
        )));
    }

    if binary_exists(requested) {
        return Ok(requested.to_owned());
    }

    // Always allow pre-bundled tools near the engine binary (pt-tools),
    // even when auto-bootstrap is disabled.
    let install_dir = bootstrap_install_dir()?;
    let file_name = tool_file_name(tool);
    let target_path = install_dir.join(file_name);
    if target_path.exists() {
        return Ok(target_path.to_string_lossy().to_string());
    }

    if !auto_bootstrap_enabled() {
        return Err(EngineError::Config(format!(
            "binary '{requested}' for {tool} not found. Put '{}' into '{}' (or set PRIME_PT_AUTO_BOOTSTRAP=1)",
            tool_file_name(tool),
            install_dir.display(),
        )));
    }

    let urls = tool_bootstrap_urls(tool);
    if !urls.is_empty() {
        info!(target: "pt.bootstrap", tool = %tool, path = %target_path.display(), "downloading missing PT binary from mirrors");
        download_to_path_from_urls(&urls, &target_path).await?;
        ensure_executable(&target_path)?;
        info!(target: "pt.bootstrap", tool = %tool, path = %target_path.display(), "PT binary downloaded");
        return Ok(target_path.to_string_lossy().to_string());
    }

    if is_tor_bundle_tool(tool) {
        ensure_tools_from_tor_bundle(&install_dir).await?;
        if target_path.exists() {
            return Ok(target_path.to_string_lossy().to_string());
        }
    }

    Err(EngineError::Config(format!(
        "binary '{requested}' for {tool} not found and automatic bootstrap failed"
    )))
}

fn auto_bootstrap_enabled() -> bool {
    std::env::var("PRIME_PT_AUTO_BOOTSTRAP")
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off"
            )
        })
        .unwrap_or(true)
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
        "cannot create writable bootstrap directory; tried: {}",
        errors.join("; ")
    )))
}

fn is_tor_bundle_tool(tool: &str) -> bool {
    matches!(tool, "tor" | "snowflake-client" | "obfs4proxy")
}

async fn ensure_tools_from_tor_bundle(install_dir: &Path) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = install_dir;
        Err(EngineError::Config(
            "automatic tor bundle bootstrap is currently implemented for Windows only".to_owned(),
        ))
    }
    #[cfg(windows)]
    {
        let tor_path = install_dir.join(tool_file_name("tor"));
        let snowflake_path = install_dir.join(tool_file_name("snowflake-client"));
        let obfs4_path = install_dir.join(tool_file_name("obfs4proxy"));
        if tor_path.exists() && snowflake_path.exists() && obfs4_path.exists() {
            return Ok(());
        }

        let urls = tor_bundle_urls();
        info!(target: "pt.bootstrap", dir = %install_dir.display(), mirrors = urls.len(), "downloading tor expert bundle");
        let bytes = download_bytes_from_urls(&urls).await?;

        let install_dir_owned = install_dir.to_owned();
        tokio::task::spawn_blocking(move || extract_tor_bundle_tools(&bytes, &install_dir_owned))
            .await
            .map_err(|e| EngineError::Internal(format!("bootstrap task failed: {e}")))??;

        info!(target: "pt.bootstrap", dir = %install_dir.display(), "tor expert bundle extracted");
        Ok(())
    }
}

fn tool_file_name(tool: &str) -> String {
    #[cfg(windows)]
    {
        if tool.ends_with(".exe") {
            tool.to_owned()
        } else {
            format!("{tool}.exe")
        }
    }
    #[cfg(not(windows))]
    {
        tool.to_owned()
    }
}

fn tool_bootstrap_urls(tool: &str) -> Vec<String> {
    let env_key_single = format!(
        "PRIME_PT_{}_URL",
        tool.to_ascii_uppercase().replace('-', "_")
    );
    let env_key_list = format!(
        "PRIME_PT_{}_URLS",
        tool.to_ascii_uppercase().replace('-', "_")
    );
    let mut out = Vec::new();
    if let Ok(v) = std::env::var(&env_key_list) {
        out.extend(parse_url_list(&v));
    }
    if let Ok(v) = std::env::var(&env_key_single) {
        let v = v.trim();
        if !v.is_empty() {
            out.push(v.to_owned());
        }
    }
    dedup_urls(out)
}

async fn download_to_path_from_urls(urls: &[String], target_path: &Path) -> Result<()> {
    let bytes = download_bytes_from_urls(urls).await?;
    if bytes.is_empty() {
        return Err(EngineError::Config(
            "bootstrap download returned empty file from all mirrors".to_owned(),
        ));
    }
    if let Some(parent) = target_path.parent() {
        ensure_dir_writable(parent)?;
    }
    std::fs::write(target_path, &bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            EngineError::Config(format!(
                "cannot write bootstrap binary '{}': permission denied (admin rights may be required)",
                target_path.display()
            ))
        } else {
            EngineError::Io(e)
        }
    })?;
    Ok(())
}

async fn download_bytes_from_urls(urls: &[String]) -> Result<bytes::Bytes> {
    if urls.is_empty() {
        return Err(EngineError::Config(
            "no bootstrap URLs configured".to_owned(),
        ));
    }
    let mut errors = Vec::new();
    for url in urls {
        match download_bytes_with_retries(url, 3).await {
            Ok(b) => return Ok(b),
            Err(e) => {
                errors.push(format!("{url}: {e}"));
                info!(target: "pt.bootstrap", url = %url, error = %e, "bootstrap mirror failed");
            }
        }
    }
    Err(EngineError::Config(format!(
        "bootstrap download failed for all mirrors: {}",
        errors.join(" | ")
    )))
}

async fn download_bytes_with_retries(url: &str, retries: usize) -> Result<bytes::Bytes> {
    let client = bootstrap_http_client()?;
    let attempts = retries.max(1);
    let mut last_err: Option<EngineError> = None;
    for attempt in 1..=attempts {
        info!(target: "pt.bootstrap", url = %url, attempt, "bootstrap download attempt");
        match client.get(url).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    last_err = Some(EngineError::Config(format!("HTTP {}", resp.status())));
                } else {
                    let bytes = resp.bytes().await?;
                    if !bytes.is_empty() {
                        return Ok(bytes);
                    }
                    last_err = Some(EngineError::Config("empty body".to_owned()));
                }
            }
            Err(e) => {
                last_err = Some(EngineError::Http(e));
            }
        }
        if attempt < attempts {
            tokio::time::sleep(Duration::from_millis(300 * attempt as u64)).await;
        }
    }
    Err(last_err.unwrap_or_else(|| EngineError::Config("download failed".to_owned())))
}

fn bootstrap_http_client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(45))
        .user_agent("prime-net-engine/pt-bootstrap");
    if let Ok(proxy) = std::env::var("PRIME_PT_BOOTSTRAP_PROXY") {
        let p = proxy.trim();
        if !p.is_empty() {
            builder = builder.proxy(reqwest::Proxy::all(p).map_err(|e| {
                EngineError::Config(format!("invalid PRIME_PT_BOOTSTRAP_PROXY: {e}"))
            })?);
        } else {
            // Empty env var means explicit "no proxy" — honour it.
            builder = builder.no_proxy();
        }
    } else {
        // No env var set: bypass system proxy to avoid looping through ourselves
        // when the engine has configured itself as the system proxy.
        builder = builder.no_proxy();
    }
    Ok(builder.build()?)
}

#[cfg(windows)]
fn extract_tor_bundle_tools(bundle: &[u8], install_dir: &Path) -> Result<()> {
    let work_dir = make_temp_dir("tor-bootstrap-extract")?;
    let archive_path = work_dir.join("tor-bundle.tar.gz");
    std::fs::write(&archive_path, bundle)?;

    let output = StdCommand::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&work_dir)
        .output()
        .map_err(|e| {
            EngineError::Config(format!(
                "failed to launch system 'tar' for bootstrap extraction: {e}"
            ))
        })?;
    if !output.status.success() {
        return Err(EngineError::Config(format!(
            "failed to extract tor bundle with system tar (status {})",
            output.status
        )));
    }

    let mut copied = 0usize;
    for (tool, raw_name) in [
        ("tor", "tor.exe"),
        ("snowflake-client", "snowflake-client.exe"),
        ("obfs4proxy", "obfs4proxy.exe"),
    ] {
        if let Some(src) = find_file_recursively(&work_dir, raw_name) {
            let dst = install_dir.join(tool_file_name(tool));
            if let Some(parent) = dst.parent() {
                ensure_dir_writable(parent)?;
            }
            std::fs::copy(&src, &dst).map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    EngineError::Config(format!(
                        "cannot copy '{}' to '{}': permission denied (admin rights may be required)",
                        src.display(),
                        dst.display()
                    ))
                } else {
                    EngineError::Io(e)
                }
            })?;
            ensure_executable(&dst)?;
            copied += 1;
        }
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir_all(&work_dir);
    if copied == 0 {
        return Err(EngineError::Config(
            "tor bundle extracted but required binaries were not found".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn find_file_recursively(root: &Path, file_name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let matches = path
                .file_name()
                .and_then(|v| v.to_str())
                .map(|v| v.eq_ignore_ascii_case(file_name))
                .unwrap_or(false);
            if matches {
                return Some(path);
            }
        }
    }
    None
}

fn ensure_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        let _ = path;
    }
    Ok(())
}

fn binary_exists(bin: &str) -> bool {
    let p = Path::new(bin);
    if p.is_absolute() || bin.contains(std::path::MAIN_SEPARATOR) || bin.contains('/') {
        return p.is_file();
    }
    if find_in_path(bin).is_some() {
        return true;
    }
    false
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    #[cfg(windows)]
    let exts = windows_pathexts();
    for dir in std::env::split_paths(&path_var) {
        let direct = dir.join(bin);
        if direct.is_file() {
            return Some(direct);
        }
        #[cfg(windows)]
        {
            for ext in &exts {
                let with_ext = dir.join(format!("{bin}{ext}"));
                if with_ext.is_file() {
                    return Some(with_ext);
                }
            }
        }
    }
    None
}

#[cfg(windows)]
fn windows_pathexts() -> Vec<String> {
    let from_env = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned());
    from_env
        .split(';')
        .filter_map(|v| {
            let t = v.trim();
            if t.is_empty() {
                None
            } else if t.starts_with('.') {
                Some(t.to_owned())
            } else {
                Some(format!(".{t}"))
            }
        })
        .collect()
}

/// Result of [`normalize_bind`]: a concrete socket address and an optional
/// ephemeral port guard that must be kept alive until the consumer is about
/// to bind the port itself.
struct BindResult {
    addr: SocketAddr,
    /// When the caller requested port 0 we bind an ephemeral port and hold
    /// the listener here so no other process can steal the port before Tor
    /// starts.  The caller must [`drop`] this guard immediately before
    /// spawning Tor.
    _ephemeral_guard: Option<tokio::net::TcpListener>,
}

async fn normalize_bind(bind: &str) -> Result<BindResult> {
    let bind = bind.trim();
    if bind.is_empty() {
        return Err(EngineError::Config(
            "pt.local_socks5_bind must not be empty".to_owned(),
        ));
    }
    let addr: SocketAddr = bind.parse().map_err(|_| {
        EngineError::Config(
            "pt.local_socks5_bind must be a socket addr, e.g. 127.0.0.1:1080".to_owned(),
        )
    })?;
    if addr.port() != 0 {
        return Ok(BindResult {
            addr,
            _ephemeral_guard: None,
        });
    }

    // Port 0: pick an ephemeral port ourselves and pass a concrete SocksPort
    // to Tor.  Keep the listener alive so no other process can steal the port
    // between now and the moment Tor binds it (TOCTOU mitigation).
    let host = addr.ip();
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(host, 0)).await?;
    let picked = listener.local_addr()?;
    Ok(BindResult {
        addr: picked,
        _ephemeral_guard: Some(listener),
    })
}

fn make_temp_dir(prefix: &str) -> Result<PathBuf> {
    let mut base = std::env::temp_dir();
    let rnd: u64 = rand::random();
    base.push(format!("coreprime-{prefix}-{rnd:016x}"));
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

fn ensure_dir_writable(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            EngineError::Config(format!(
                "permission denied for '{}' (admin rights may be required)",
                path.display()
            ))
        } else {
            EngineError::Io(e)
        }
    })?;
    let probe = path.join(format!(".write-test-{:016x}", rand::random::<u64>()));
    std::fs::write(&probe, b"ok").map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            EngineError::Config(format!(
                "directory '{}' is not writable (admin rights may be required)",
                path.display()
            ))
        } else {
            EngineError::Io(e)
        }
    })?;
    let _ = std::fs::remove_file(probe);
    Ok(())
}

fn parse_url_list(raw: &str) -> Vec<String> {
    raw.split([';', ',', '\n', '\r'])
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn dedup_urls(urls: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for u in urls {
        if seen.insert(u.clone()) {
            out.push(u);
        }
    }
    out
}

#[cfg(windows)]
fn tor_bundle_urls() -> Vec<String> {
    let mut urls = Vec::new();
    if let Ok(v) = std::env::var("PRIME_PT_TOR_BUNDLE_URLS") {
        urls.extend(parse_url_list(&v));
    }
    if let Ok(v) = std::env::var("PRIME_PT_TOR_BUNDLE_URL") {
        let v = v.trim();
        if !v.is_empty() {
            urls.push(v.to_owned());
        }
    }
    if urls.is_empty() {
        urls.push(
            "https://archive.torproject.org/tor-package-archive/torbrowser/14.0.9/tor-expert-bundle-windows-x86_64-14.0.9.tar.gz".to_owned(),
        );
        urls.push(
            "https://archive.torproject.org/tor-package-archive/torbrowser/13.5.7/tor-expert-bundle-windows-x86_64-13.5.7.tar.gz".to_owned(),
        );
    }
    dedup_urls(urls)
}

async fn spawn_tor_and_wait_ready(
    socks_addr: SocketAddr,
    data_dir: &Path,
    tor_bin: &str,
    tor_args: &[String],
    torrc: &str,
) -> Result<TorClientGuard> {
    let torrc_path = data_dir.join("torrc");
    std::fs::write(&torrc_path, torrc.as_bytes())?;

    let mut cmd = Command::new(tor_bin);
    cmd.arg("-f").arg(&torrc_path);
    for a in tor_args {
        let a = a.trim();
        if !a.is_empty() {
            cmd.arg(a);
        }
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        EngineError::Config(format!(
            "failed to start tor ({tor_bin}): {e}. Ensure 'tor' is installed and on PATH (or set pt.*.tor_bin)."
        ))
    })?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let log_task = Some(tokio::spawn(async move {
        if let Some(mut out) = stdout {
            let mut buf = [0u8; 4096];
            loop {
                let n = match out.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                let s = String::from_utf8_lossy(&buf[..n]);
                for line in s.lines() {
                    tracing::info!(target: "tor", "{}", line);
                }
            }
        }
        if let Some(mut err) = stderr {
            let mut buf = [0u8; 4096];
            loop {
                let n = match err.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                let s = String::from_utf8_lossy(&buf[..n]);
                for line in s.lines() {
                    tracing::warn!(target: "tor", "{}", line);
                }
            }
        }
    }));

    let ready = wait_socks5_ready(socks_addr, Duration::from_secs(30)).await;
    if let Err(e) = ready {
        let _ = child.start_kill();
        return Err(e);
    }

    Ok(TorClientGuard {
        socks_addr,
        child: Some(child),
        data_dir: data_dir.to_path_buf(),
        _log_task: log_task,
    })
}

async fn wait_socks5_ready(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let start = tokio::time::Instant::now();
    loop {
        if start.elapsed() > timeout {
            return Err(EngineError::Internal(format!(
                "tor SOCKS5 did not become ready within {}s at {addr}",
                timeout.as_secs()
            )));
        }
        match socks5_noauth_probe(addr).await {
            Ok(()) => return Ok(()),
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn socks5_noauth_probe(addr: SocketAddr) -> Result<()> {
    let mut tcp = TcpStream::connect(addr).await?;
    // Greeting: VER=5, NMETHODS=1, METHODS=[0x00]
    tcp.write_all(&[0x05u8, 0x01u8, 0x00u8]).await?;
    tcp.flush().await?;
    let mut rep = [0u8; 2];
    tcp.read_exact(&mut rep).await?;
    if rep != [0x05, 0x00] {
        return Err(EngineError::Internal("SOCKS5 probe failed".to_owned()));
    }
    Ok(())
}

fn render_torrc(data_dir: &Path, socks_addr: SocketAddr, extra_lines: &[String]) -> String {
    let mut out = String::new();
    // Keep Tor fully client-side and avoid persisting state where possible.
    out.push_str(&format!(
        "DataDirectory {}\n",
        torrc_quote(&data_dir.to_string_lossy())
    ));
    out.push_str("ClientOnly 1\n");
    out.push_str("AvoidDiskWrites 1\n");
    out.push_str("Log notice stdout\n");
    out.push_str(&format!("SocksPort {}\n", socks_addr));

    for l in extra_lines {
        let l = l.trim();
        if !l.is_empty() {
            out.push_str(l);
            out.push('\n');
        }
    }
    out
}

fn torrc_client_transport_plugin_line(kind: &str, bin: &str, args: &[String]) -> String {
    let mut out = String::new();
    out.push_str("ClientTransportPlugin ");
    out.push_str(kind);
    out.push_str(" exec ");
    out.push_str(&torrc_quote(bin.trim()));
    for a in args {
        let a = a.trim();
        if !a.is_empty() {
            out.push(' ');
            out.push_str(&torrc_quote(a));
        }
    }
    out
}

fn torrc_quote(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return "\"\"".to_owned();
    }
    let needs = s.bytes().any(|b| b.is_ascii_whitespace() || b == b'"');
    if !needs {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '"' {
            out.push('\\');
            out.push('"');
        } else {
            out.push(ch);
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn torrc_quotes_args_with_spaces() {
        assert_eq!(
            torrc_quote("C:\\Program Files\\Tor\\tor.exe"),
            "\"C:\\Program Files\\Tor\\tor.exe\""
        );
        assert_eq!(torrc_quote("tor"), "tor");
    }

    #[test]
    fn plugin_line_renders() {
        let line = torrc_client_transport_plugin_line(
            "obfs4",
            "obfs4proxy",
            &["-log".to_owned(), "stdout".to_owned()],
        );
        assert!(line.contains("ClientTransportPlugin obfs4 exec obfs4proxy"));
        assert!(line.contains("-log"));
    }

    #[tokio::test]
    async fn normalize_bind_picks_ephemeral_port_on_zero() {
        let result = normalize_bind("127.0.0.1:0").await.expect("bind");
        assert_eq!(result.addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(result.addr.port() != 0);
        // The ephemeral guard should be present when port 0 is requested.
        assert!(result._ephemeral_guard.is_some());
    }
}
