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

pub async fn download_best_binary(install_dir: &Path) -> Result<PathBuf> {
    let candidates = candidate_binary_names();
    if candidates.is_empty() {
        return Err(EngineError::Config(
            "packet-level bypass is not supported on this platform".to_owned(),
        ));
    }

    let mut last_err = EngineError::Config("no mirrors tried".to_owned());

    for name in &candidates {
        let urls: Vec<String> = build_mirror_urls(name).await;
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
                verify_downloaded_payload_integrity(name, &source_url, &bytes).await?;

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

                verify_final_binary_integrity_if_configured(name, &final_bytes)?;

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

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
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
        .no_proxy()
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

async fn verify_downloaded_payload_integrity(
    binary_name: &str,
    source_url: &str,
    payload: &[u8],
) -> Result<()> {
    let expected = if let Some(hex) = std::env::var("PRIME_PACKET_BYPASS_PAYLOAD_SHA256")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
    {
        parse_sha256_hex(&hex).ok_or_else(|| {
            EngineError::Config(
                "PRIME_PACKET_BYPASS_PAYLOAD_SHA256 must contain a 64-hex sha256 digest".to_owned(),
            )
        })?
    } else if let Some(hex) = release_asset_sha256_hex(source_url) {
        let parsed = parse_sha256_hex(&hex).ok_or_else(|| {
            EngineError::Config(format!(
                "cached release asset digest is invalid for '{source_url}'"
            ))
        })?;
        info!(
            target: "packet_bypass",
            source = source_url,
            "resolved packet bypass sha256 from release metadata cache"
        );
        parsed
    } else {
        match resolve_sha256_from_sidecar(source_url).await? {
            Some(v) => v,
            None => {
                if allow_unverified_packet_bypass_bootstrap() {
                    warn!(
                        target: "packet_bypass",
                        binary = binary_name,
                        source = source_url,
                        "packet bypass integrity sidecar not found; continuing because PRIME_PACKET_BYPASS_ALLOW_UNVERIFIED=1"
                    );
                    return Ok(());
                }
                return Err(EngineError::Config(format!(
                    "packet bypass integrity check failed: no sha256 sidecar for '{source_url}'. set PRIME_PACKET_BYPASS_PAYLOAD_SHA256 or PRIME_PACKET_BYPASS_ALLOW_UNVERIFIED=1"
                )));
            }
        }
    };

    let got = sha256_bytes(payload);
    if got != expected {
        return Err(EngineError::Config(format!(
            "packet bypass integrity check failed for '{binary_name}': sha256 mismatch (source: {source_url})"
        )));
    }
    info!(
        target: "packet_bypass",
        binary = binary_name,
        source = source_url,
        "packet bypass payload sha256 verified"
    );
    Ok(())
}

fn verify_final_binary_integrity_if_configured(binary_name: &str, bytes: &[u8]) -> Result<()> {
    let Some(expected_hex) = std::env::var("PRIME_PACKET_BYPASS_BINARY_SHA256")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
    else {
        return Ok(());
    };

    let expected = parse_sha256_hex(&expected_hex).ok_or_else(|| {
        EngineError::Config(
            "PRIME_PACKET_BYPASS_BINARY_SHA256 must contain a 64-hex sha256 digest".to_owned(),
        )
    })?;
    let got = sha256_bytes(bytes);
    if got != expected {
        return Err(EngineError::Config(format!(
            "packet bypass final binary integrity check failed for '{binary_name}': sha256 mismatch"
        )));
    }
    info!(
        target: "packet_bypass",
        binary = binary_name,
        "packet bypass final binary sha256 verified"
    );
    Ok(())
}

async fn resolve_sha256_from_sidecar(source_url: &str) -> Result<Option<[u8; 32]>> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .user_agent("prime-net-engine/packet-bypass-bootstrap")
        .build()
        .map_err(|e| EngineError::Config(format!("failed to build integrity-check client: {e}")))?;

    let candidates = [format!("{source_url}.sha256"), format!("{source_url}.sha256sum")];
    for url in candidates {
        let resp = match client.get(&url).send().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !resp.status().is_success() {
            continue;
        }
        let text = match resp.text().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(hex) = extract_sha256_from_text(&text) else {
            continue;
        };
        if let Some(parsed) = parse_sha256_hex(&hex) {
            info!(
                target: "packet_bypass",
                sidecar_url = url.as_str(),
                "resolved packet bypass sha256 sidecar"
            );
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn allow_unverified_packet_bypass_bootstrap() -> bool {
    std::env::var("PRIME_PACKET_BYPASS_ALLOW_UNVERIFIED")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = nibble(bytes[i * 2])?;
        let lo = nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn extract_sha256_from_text(s: &str) -> Option<String> {
    for token in s.split_whitespace() {
        if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(token.to_ascii_lowercase());
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    for i in 0..=(bytes.len() - 64) {
        let sub = &bytes[i..i + 64];
        if sub.iter().all(|b| b.is_ascii_hexdigit()) {
            return Some(String::from_utf8_lossy(sub).to_ascii_lowercase());
        }
    }
    None
}
