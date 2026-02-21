fn extract_from_zip(zip_bytes: &[u8], target_filename: &str) -> Result<Vec<u8>> {
    use std::io::Read;

    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| EngineError::Config(format!("failed to open zip: {e}")))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| EngineError::Config(format!("zip entry error: {e}")))?;
        let entry_name = entry.name().to_owned();
        let file_name = std::path::Path::new(&entry_name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if file_name.eq_ignore_ascii_case(target_filename) {
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry
                .read_to_end(&mut buf)
                .map_err(|e| EngineError::Config(format!("failed to read zip entry: {e}")))?;
            info!(
                target: "packet_bypass",
                zip_entry = entry_name.as_str(),
                filename = target_filename,
                "extracted binary from zip"
            );
            return Ok(buf);
        }
    }

    Err(EngineError::Config(format!(
        "'{target_filename}' not found inside zip archive"
    )))
}

async fn download_best_binary(install_dir: &Path) -> Result<PathBuf> {
    let candidates = candidate_binary_names();
    if candidates.is_empty() {
        return Err(EngineError::Config(
            "packet-level bypass is not supported on this platform".to_owned(),
        ));
    }

    let mut last_err = EngineError::Config("no mirrors tried".to_owned());

    for name in &candidates {
        let urls = build_mirror_urls(name).await;
        if urls.is_empty() {
            warn!(
                target: "packet_bypass",
                binary = %name,
                "no packet bypass mirrors available for candidate"
            );
            continue;
        }

        info!(
            target: "packet_bypass",
            binary = %name,
            mirrors = urls.len(),
            "downloading packet bypass binary"
        );
        match download_from_mirrors(name, &urls).await {
            Ok((bytes, source_url)) => {
                let final_bytes = if source_url.ends_with(".zip") {
                    match extract_from_zip(&bytes, name) {
                        Ok(extracted) => extracted,
                        Err(e) => {
                            warn!(
                                target: "packet_bypass",
                                binary = %name,
                                "zip extraction failed: {e}"
                            );
                            last_err = e;
                            continue;
                        }
                    }
                } else {
                    bytes
                };

                let path = install_dir.join(name);
                std::fs::write(&path, &final_bytes).map_err(EngineError::Io)?;
                make_executable(&path)?;
                info!(
                    target: "packet_bypass",
                    path = %path.display(),
                    bytes = final_bytes.len(),
                    "packet bypass binary installed successfully"
                );
                return Ok(path);
            }
            Err(e) => {
                warn!(
                    target: "packet_bypass",
                    binary = %name,
                    error = %e,
                    "packet bypass download failed; trying next candidate"
                );
                last_err = e;
            }
        }
    }

    Err(EngineError::Config(format!(
        "failed to install any packet bypass binary; last error: {last_err}"
    )))
}

fn which_binary(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path).map_err(EngineError::Io)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).map_err(EngineError::Io)?;
    Ok(())
}

#[cfg(windows)]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

async fn download_from_mirrors(name: &str, urls: &[String]) -> Result<(Vec<u8>, String)> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .user_agent("prime-net-engine/packet-bypass-bootstrap")
        .build()
        .map_err(|e| {
            EngineError::Config(format!(
                "failed to build packet bypass download client: {e}"
            ))
        })?;

    let mut errors = Vec::new();
    for url in urls {
        info!(
            target: "packet_bypass",
            binary = %name,
            url = %url,
            "packet bypass bootstrap attempt"
        );
        match client.get(url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.bytes().await {
                        Ok(body) => {
                            if !body.is_empty() {
                                return Ok((body.to_vec(), url.clone()));
                            }
                            errors.push(format!("{url}: empty body"));
                        }
                        Err(e) => errors.push(format!("{url}: {e}")),
                    }
                } else {
                    errors.push(format!("{url}: http {}", resp.status()));
                }
            }
            Err(e) => errors.push(format!("{url}: {e}")),
        }
    }
    Err(EngineError::Config(format!(
        "all packet bypass bootstrap mirrors failed for '{name}': {}",
        errors.join(" | ")
    )))
}

fn ensure_dir_writable(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    let probe = path.join(".prime-write-test");
    std::fs::write(&probe, b"ok").map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            EngineError::Config(format!(
                "permission denied for '{}'; administrator rights may be required",
                path.display()
            ))
        } else {
            EngineError::Io(e)
        }
    })?;
    let _ = std::fs::remove_file(probe);
    Ok(())
}

#[cfg(windows)]
fn is_elevated() -> bool {
    std::process::Command::new("net")
        .args(["session"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
