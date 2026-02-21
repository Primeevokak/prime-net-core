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
        std::fs::create_dir_all(&parts_dir)?;

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

        let concurrency = self
            .config
            .download
            .initial_concurrency
            .min(self.config.download.max_concurrency)
            .max(1);

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
        let downloaded = std::sync::Arc::new(AtomicU64::new(0));
        let started_at = Instant::now();

        let mut join_set = tokio::task::JoinSet::new();
        for (index, chunk) in chunks.iter().copied().enumerate() {
            let part_path = parts_dir.join(format!("{index:08}.part"));
            let expected_len = (chunk.end - chunk.start) + 1;

            if let Ok(meta) = std::fs::metadata(&part_path) {
                if meta.is_file() && meta.len() == expected_len {
                    resumed = true;
                    downloaded.fetch_add(expected_len, Ordering::Relaxed);
                    continue;
                }
            }

            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| EngineError::Internal("semaphore closed".to_owned()))?;

            let client = client.clone();
            let url = request.url.clone();
            let base_headers = headers.clone();
            let downloaded = downloaded.clone();
            let progress = progress.clone();
            let max_retries = self.config.download.max_retries;
            join_set.spawn(async move {
                let _permit = permit;

                // (Re)download this part into its own file.
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&part_path)
                    .await?;

                let range_value = format!("bytes={}-{}", chunk.start, chunk.end);
                let mut h = base_headers.clone();
                h.insert(RANGE, HeaderValue::from_str(&range_value)?);

                // Retry the whole part download on transient failures.
                let mut last_err: Option<EngineError> = None;
                for attempt in 0..=max_retries {
                    let mut attempt_written: u64 = 0;
                    let resp = client.get(&url).headers(h.clone()).send().await;
                    match resp {
                        Ok(r) => {
                            if r.status().as_u16() != 206 {
                                last_err = Some(EngineError::Internal(format!(
                                    "server did not return Partial Content (expected 206, got {})",
                                    r.status().as_u16()
                                )));
                            } else {
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
                                                let elapsed =
                                                    started_at.elapsed().as_secs_f64().max(0.001);
                                                let speed_mbps = (total_downloaded as f64 * 8.0
                                                    / 1_000_000.0)
                                                    / elapsed;
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
                                        return Ok::<(), EngineError>(());
                                    }
                                    last_err = Some(EngineError::Internal(format!(
                                        "downloaded part size mismatch (expected {expected_len}, got {size})"
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            last_err = Some(EngineError::Http(e));
                        }
                    }

                    if attempt < max_retries {
                        // Roll back progress for bytes written during this attempt since we will re-download it.
                        if attempt_written > 0 {
                            downloaded.fetch_sub(attempt_written, Ordering::Relaxed);
                        }
                        tokio::time::sleep(retry_delay(attempt)).await;
                        // Reset file to overwrite from scratch.
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
            });
        }

        while let Some(result) = join_set.join_next().await {
            result??;
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
        if offset > 0 {
            match status.as_u16() {
                206 => {}
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
