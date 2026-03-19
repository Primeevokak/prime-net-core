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
    let explicit_proxy = std::env::var("PRIME_PT_BOOTSTRAP_PROXY")
        .ok()
        .filter(|p| !p.trim().is_empty());
    if let Some(proxy) = explicit_proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy.trim()).map_err(|e| {
            EngineError::Config(format!("invalid PRIME_PT_BOOTSTRAP_PROXY: {e}"))
        })?);
    } else {
        // No explicit proxy configured — bypass system/env proxies to avoid
        // accidentally routing bootstrap traffic through the engine itself.
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
