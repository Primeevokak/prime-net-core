impl PrimeHttpClient {
    async fn probe_range_support(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
        headers: &HeaderMap,
    ) -> Result<bool> {
        if request.method != Method::GET {
            return Ok(false);
        }
        let _permit = match &self.h2_reset_limiter {
            Some(s) => Some(
                s.clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| EngineError::Internal("h2 reset limiter closed".to_owned()))?,
            ),
            None => None,
        };

        let mut h = headers.clone();
        h.insert(RANGE, HeaderValue::from_static("bytes=0-0"));
        let resp = self
            .send_with_retry(self.config.download.max_retries, || {
                client.get(&request.url).headers(h.clone())
            })
            .await?;
        let ok = resp.status().as_u16() == 206
            && parse_total_length_from_content_range(resp.headers()).is_some();
        // If the server honored the 1-byte range, consuming the body avoids an HTTP/2 RST_STREAM on drop.
        if ok {
            let _ = resp.bytes().await;
        }
        Ok(ok)
    }

    async fn send_with_retry(
        &self,
        max_retries: usize,
        mut make: impl FnMut() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let mut last_err: Option<EngineError> = None;
        for attempt in 0..=max_retries {
            let res = make().send().await;
            match res {
                Ok(resp) => {
                    let code = resp.status().as_u16();
                    let retryable_status = code == 408 || code == 429 || (500..600).contains(&code);
                    if retryable_status && attempt < max_retries {
                        tokio::time::sleep(retry_delay(attempt)).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    let retryable = e.is_timeout() || e.is_connect() || e.is_request();
                    last_err = Some(EngineError::Http(e));
                    if retryable && attempt < max_retries {
                        tokio::time::sleep(retry_delay(attempt)).await;
                        continue;
                    }
                    return Err(last_err
                        .unwrap_or_else(|| EngineError::Internal("request failed".to_owned())));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("request failed".to_owned())))
    }

    async fn download_chunked_to_parts(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
        headers: &HeaderMap,
        content_length: u64,
        path: &Path,
        progress: Option<ProgressHook>,
    ) -> Result<(u64, bool)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio::io::AsyncWriteExt;

        let mut resumed = false;
        let parts_dir: PathBuf = PathBuf::from(format!("{}.prime.parts", path.to_string_lossy()));
        let parts_dir_preexists = parts_dir.exists();
        std::fs::create_dir_all(&parts_dir)?;
        let manifest_path = parts_dir.join("resume.key");
        let expected_resume_key = build_parts_resume_key(&request.url, content_length);
        let manifest_matches = std::fs::read_to_string(&manifest_path)
            .ok()
            .map(|s| s.trim() == expected_resume_key)
            .unwrap_or(false);
        if !manifest_matches {
            // Existing part files may belong to another URL/version; never reuse them blindly.
            if parts_dir_preexists {
                let _ = std::fs::remove_dir_all(&parts_dir);
                std::fs::create_dir_all(&parts_dir)?;
            }
            std::fs::write(&manifest_path, format!("{expected_resume_key}\n"))?;
        }

        let chunks = self.chunk_manager.calculate_chunks(content_length);
        if chunks.is_empty() {
            // Create an empty file.
            tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .await?;
            return Ok((0, false));
        }

        let mut target_concurrency = self
            .chunk_manager
            .current_concurrency()
            .min(self.config.download.max_concurrency.max(1))
            .max(1);

        let downloaded = std::sync::Arc::new(AtomicU64::new(0));
        let started_at = Instant::now();

        let mut pending_parts: Vec<(ChunkRange, PathBuf, u64)> = Vec::new();
        for (index, chunk) in chunks.iter().copied().enumerate() {
            let part_path = parts_dir.join(format!("{index:08}.part"));
            let expected_len = (chunk.end - chunk.start) + 1;

            if manifest_matches {
                if let Ok(meta) = std::fs::metadata(&part_path) {
                    if meta.is_file() && meta.len() == expected_len {
                        resumed = true;
                        downloaded.fetch_add(expected_len, Ordering::Relaxed);
                        continue;
                    }
                }
            }
            pending_parts.push((chunk, part_path, expected_len));
        }

        let max_retries = self.config.download.max_retries;
        let max_concurrency = self.config.download.max_concurrency.max(1);
        let mut next_pending = 0usize;
        let mut in_flight = 0usize;
        let mut join_set: tokio::task::JoinSet<std::result::Result<(), EngineError>> =
            tokio::task::JoinSet::new();

        while next_pending < pending_parts.len() && in_flight < target_concurrency {
            let (chunk, part_path, expected_len) = pending_parts[next_pending].clone();
            next_pending += 1;
            in_flight += 1;

            join_set.spawn(download_part_to_file(
                client.clone(),
                request.url.clone(),
                headers.clone(),
                chunk,
                part_path,
                expected_len,
                content_length,
                max_retries,
                downloaded.clone(),
                started_at,
                progress.clone(),
            ));
        }

        while in_flight > 0 {
            let result = join_set.join_next().await.ok_or_else(|| {
                EngineError::Internal("part worker join set unexpectedly empty".to_owned())
            })?;
            in_flight = in_flight.saturating_sub(1);
            result??;

            let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
            let speed_mbps =
                (downloaded.load(Ordering::Relaxed) as f64 * 8.0 / 1_000_000.0) / elapsed;
            self.chunk_manager.adjust_concurrency(speed_mbps);
            target_concurrency = self
                .chunk_manager
                .current_concurrency()
                .min(max_concurrency)
                .max(1);

            while next_pending < pending_parts.len() && in_flight < target_concurrency {
                let (chunk, part_path, expected_len) = pending_parts[next_pending].clone();
                next_pending += 1;
                in_flight += 1;

                join_set.spawn(download_part_to_file(
                    client.clone(),
                    request.url.clone(),
                    headers.clone(),
                    chunk,
                    part_path,
                    expected_len,
                    content_length,
                    max_retries,
                    downloaded.clone(),
                    started_at,
                    progress.clone(),
                ));
            }
        }

        // Merge parts sequentially into a temp file, then rename into place.
        let tmp_path: PathBuf = PathBuf::from(format!("{}.prime.tmp", path.to_string_lossy()));
        let mut out = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .await?;

        for index in 0..chunks.len() {
            let part_path = parts_dir.join(format!("{index:08}.part"));
            let mut input = tokio::fs::File::open(&part_path).await?;
            tokio::io::copy(&mut input, &mut out).await?;
        }
        out.flush().await?;
        drop(out);

        if let Ok(meta) = tokio::fs::metadata(path).await {
            if meta.is_file() {
                let _ = tokio::fs::remove_file(path).await;
            }
        }
        tokio::fs::rename(&tmp_path, path).await?;

        // Best-effort cleanup of parts.
        let _ = tokio::fs::remove_dir_all(&parts_dir).await;

        Ok((content_length, resumed))
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_single_to_file(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
        headers: &HeaderMap,
        content_length: Option<u64>,
        path: &Path,
        supports_ranges: bool,
        progress: Option<ProgressHook>,
    ) -> Result<(u64, bool)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio::io::AsyncWriteExt;

        let mut resumed = false;
        let mut offset: u64 = 0;
        if supports_ranges {
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.is_file() && meta.len() > 0 {
                    offset = meta.len();
                    resumed = true;
                }
            }
        }

        let mut h = headers.clone();
        if offset > 0 {
            h.insert(RANGE, HeaderValue::from_str(&format!("bytes={offset}-"))?);
        }

        let max_retries = self.config.download.max_retries;
        let resp = self
            .send_with_retry(max_retries, || client.get(&request.url).headers(h.clone()))
            .await?;

        // If we attempted a resume but the server ignored Range and returned 200, restart from scratch.
        let (resp, offset) = if offset > 0 && resp.status().as_u16() == 200 {
            resumed = false;
            offset = 0;
            let resp = self
                .send_with_retry(max_retries, || {
                    client.get(&request.url).headers(headers.clone())
                })
                .await?;
            (resp, offset)
        } else {
            (resp, offset)
        };

        // Validate status before writing any bytes to disk.
        let status = resp.status();
        let expected_total_from_range = parse_total_length_from_content_range(resp.headers());
        if offset > 0 {
            match status.as_u16() {
                206 => {
                    let bounds = parse_content_range_bounds(resp.headers()).ok_or_else(|| {
                        EngineError::Internal(
                            "download failed: missing or invalid Content-Range for resume request"
                                .to_owned(),
                        )
                    })?;
                    if bounds.start != offset {
                        return Err(EngineError::Internal(format!(
                            "download failed: resume Content-Range start mismatch (expected {offset}, got {})",
                            bounds.start
                        )));
                    }
                    if bounds.end < bounds.start {
                        return Err(EngineError::Internal(
                            "download failed: invalid Content-Range bounds for resume request"
                                .to_owned(),
                        ));
                    }
                    if let (Some(expected_total), Some(actual_total)) =
                        (content_length, bounds.total)
                    {
                        if expected_total != actual_total {
                            return Err(EngineError::Internal(format!(
                                "download failed: Content-Range total mismatch (expected {expected_total}, got {actual_total})"
                            )));
                        }
                    }
                }
                416 => {
                    // Range Not Satisfiable. Only treat as "already complete" if local size exactly
                    // matches server's total size. If local is larger, it is corrupted/stale and must
                    // be restarted to avoid silent on-disk corruption.
                    let total = resp
                        .headers()
                        .get(reqwest::header::CONTENT_RANGE)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.rsplit('/').next())
                        .and_then(|s| s.parse::<u64>().ok())
                        .or(content_length);

                    if let Some(total) = total {
                        if offset == total {
                            return Ok((total, true));
                        }
                        // Local file size doesn't match server total (smaller or larger) but server rejected
                        // the range; restart full download (truncate and re-download).
                        let resp = self
                            .send_with_retry(max_retries, || {
                                client.get(&request.url).headers(headers.clone())
                            })
                            .await?;
                        let status = resp.status();
                        if !status.is_success() {
                            return Err(EngineError::Internal(format!(
                                "download failed: server returned HTTP {} on restart",
                                status.as_u16()
                            )));
                        }
                        // Continue below with fresh response.
                        // NOTE: shadowing keeps the rest of the function unchanged.
                        let resp = resp;

                        let mut file = tokio::fs::OpenOptions::new()
                            .create(true)
                            .truncate(true)
                            .write(true)
                            .open(path)
                            .await?;

                        let downloaded = AtomicU64::new(0);
                        let started_at = Instant::now();
                        let mut stream = resp.bytes_stream();
                        while let Some(buf) = stream.try_next().await.map_err(EngineError::Http)? {
                            file.write_all(&buf).await?;
                            let total_downloaded = downloaded
                                .fetch_add(buf.len() as u64, Ordering::Relaxed)
                                + (buf.len() as u64);
                            if let Some(cb) = &progress {
                                let total = content_length.unwrap_or(0);
                                let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                                let speed_mbps =
                                    (total_downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                                cb(total_downloaded, total, speed_mbps);
                            }
                        }
                        file.flush().await?;
                        let final_len = file.metadata().await?.len();
                        return Ok((final_len, false));
                    }

                    return Err(EngineError::Internal(
                        "download failed: server returned HTTP 416 (Range Not Satisfiable) and total size is unknown"
                            .to_owned(),
                    ));
                }
                _ => {
                    return Err(EngineError::Internal(format!(
                        "download failed: server returned HTTP {} for a ranged request",
                        status.as_u16()
                    )));
                }
            }
        } else if !status.is_success() {
            return Err(EngineError::Internal(format!(
                "download failed: server returned HTTP {}",
                status.as_u16()
            )));
        }

        let mut file = if offset > 0 {
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?
        } else {
            tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .await?
        };

        let downloaded = AtomicU64::new(offset);
        let started_at = Instant::now();
        let mut stream = resp.bytes_stream();
        while let Some(buf) = stream.try_next().await.map_err(EngineError::Http)? {
            file.write_all(&buf).await?;
            let total_downloaded =
                downloaded.fetch_add(buf.len() as u64, Ordering::Relaxed) + (buf.len() as u64);
            if let Some(cb) = &progress {
                let total = content_length.unwrap_or(0);
                let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                let speed_mbps = (total_downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                cb(total_downloaded, total, speed_mbps);
            }
        }
        file.flush().await?;
        let final_len = file.metadata().await?.len();
        if offset > 0 {
            if let Some(total) = expected_total_from_range.or(content_length) {
                if final_len != total {
                    return Err(EngineError::Internal(format!(
                        "download failed: resumed file length mismatch (expected {total}, got {final_len})"
                    )));
                }
            }
        }
        Ok((final_len, resumed))
    }

    async fn verify_download_integrity_if_configured(&self, path: &Path) -> Result<()> {
        use tokio::io::AsyncReadExt;

        let Some(spec) = self.config.download.verify_hash.as_deref() else {
            return Ok(());
        };
        let spec = spec.trim();
        if spec.is_empty() {
            // Config validation should have prevented this; treat as no-op.
            return Ok(());
        }

        let expected_hex = if spec.eq_ignore_ascii_case("auto") {
            let sha_path = PathBuf::from(format!("{}.sha256", path.to_string_lossy()));
            let content = tokio::fs::read_to_string(&sha_path).await.map_err(|e| {
                EngineError::Internal(format!(
                    "download integrity failed: unable to read sha256 file '{}': {e}",
                    sha_path.to_string_lossy()
                ))
            })?;
            extract_sha256_from_text(&content).ok_or_else(|| {
                EngineError::Internal(format!(
                    "download integrity failed: sha256 file '{}' does not contain a 64-hex digest",
                    sha_path.to_string_lossy()
                ))
            })?
        } else if let Some(hex) = spec.strip_prefix("sha256:") {
            hex.trim().to_owned()
        } else {
            return Err(EngineError::Config(
                "download.verify_hash must be 'auto' or 'sha256:<64 hex>'".to_owned(),
            ));
        };

        let expected = parse_sha256_hex(&expected_hex).ok_or_else(|| {
            EngineError::Config("download.verify_hash contains invalid sha256 hex".to_owned())
        })?;

        let mut file = tokio::fs::File::open(path).await.map_err(|e| {
            EngineError::Internal(format!(
                "download integrity failed: unable to open '{}': {e}",
                path.to_string_lossy()
            ))
        })?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let got_bytes: [u8; 32] = hasher.finalize().into();

        if got_bytes != expected {
            return Err(EngineError::Internal(format!(
                "download integrity failed: sha256 mismatch for '{}'",
                path.to_string_lossy()
            )));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn download_part_to_file(
    client: reqwest::Client,
    url: String,
    base_headers: HeaderMap,
    chunk: ChunkRange,
    part_path: PathBuf,
    expected_len: u64,
    content_length: u64,
    max_retries: usize,
    downloaded: std::sync::Arc<std::sync::atomic::AtomicU64>,
    started_at: Instant,
    progress: Option<ProgressHook>,
) -> Result<()> {
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&part_path)
        .await?;

    let range_value = format!("bytes={}-{}", chunk.start, chunk.end);
    let mut h = base_headers.clone();
    h.insert(RANGE, HeaderValue::from_str(&range_value)?);

    let mut last_err: Option<EngineError> = None;
    for attempt in 0..=max_retries {
        last_err = None;
        let mut attempt_written: u64 = 0;
        let resp = client.get(&url).headers(h.clone()).send().await;
        match resp {
            Ok(r) => {
                if r.status().as_u16() != 206 {
                    last_err = Some(EngineError::Internal(format!(
                        "server did not return Partial Content (expected 206, got {})",
                        r.status().as_u16()
                    )));
                } else if let Some(bounds) = parse_content_range_bounds(r.headers()) {
                    if bounds.start != chunk.start || bounds.end != chunk.end {
                        last_err = Some(EngineError::Internal(format!(
                            "part Content-Range mismatch: requested {}-{}, got {}-{}",
                            chunk.start, chunk.end, bounds.start, bounds.end
                        )));
                    } else if let Some(total) = bounds.total {
                        if total != content_length {
                            last_err = Some(EngineError::Internal(format!(
                                "part Content-Range total mismatch: expected {}, got {}",
                                content_length, total
                            )));
                        }
                    }

                    if last_err.is_none() {
                        let mut r = r;
                        let mut ok = true;
                        loop {
                            match r.chunk().await {
                                Ok(Some(buf)) => {
                                    file.write_all(&buf).await?;
                                    attempt_written += buf.len() as u64;
                                    let total_downloaded = downloaded
                                        .fetch_add(buf.len() as u64, Ordering::Relaxed)
                                        + (buf.len() as u64);
                                    if let Some(cb) = &progress {
                                        let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                                        let speed_mbps =
                                            (total_downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                                        cb(total_downloaded, content_length, speed_mbps);
                                    }
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    last_err = Some(EngineError::Http(e));
                                    ok = false;
                                    break;
                                }
                            }
                        }

                        if ok {
                            file.flush().await?;
                            let size = file.metadata().await?.len();
                            if size == expected_len {
                                return Ok(());
                            }
                            last_err = Some(EngineError::Internal(format!(
                                "downloaded part size mismatch (expected {expected_len}, got {size})"
                            )));
                        }
                    }
                } else {
                    last_err = Some(EngineError::Internal(
                        "missing or invalid Content-Range for part response".to_owned(),
                    ));
                }
            }
            Err(e) => {
                last_err = Some(EngineError::Http(e));
            }
        }

        if attempt < max_retries {
            if attempt_written > 0 {
                downloaded.fetch_sub(attempt_written, Ordering::Relaxed);
            }
            tokio::time::sleep(retry_delay(attempt)).await;
            file = tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&part_path)
                .await?;
            continue;
        }
    }

    Err(last_err.unwrap_or_else(|| EngineError::Internal("part download failed".to_owned())))
}

fn build_parts_resume_key(url: &str, content_length: u64) -> String {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(url.as_bytes());
    hasher.update(b"\n");
    hasher.update(content_length.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}
