impl PrimeHttpClient {
    async fn fetch_fragmented_http1_stream_with_cfg(
        &self,
        parsed: &Url,
        request: RequestData,
        fragment_cfg: FragmentConfig,
    ) -> Result<ResponseStream> {
        use std::io;

        let resp = self.fragmented_send(parsed, &request, fragment_cfg).await?;
        let status = resp.status();

        let headers = resp.headers().clone();
        let body_stream = resp
            .into_body()
            .into_data_stream()
            .map_err(io::Error::other);
        let reader = StreamReader::new(body_stream);
        Ok(ResponseStream {
            status,
            headers,
            stream: Box::new(reader),
        })
    }

    /// Downloads the response body to `path` without buffering the whole payload in memory.
    ///
    /// If the server supports ranged requests, the engine will attempt an adaptive chunked download and
    /// will also resume from existing partial data (best-effort).
    pub async fn download_to_path(
        &self,
        mut request: RequestData,
        path: impl AsRef<Path>,
        progress: Option<ProgressHook>,
    ) -> Result<DownloadOutcome> {
        self.validate_request(&request)?;
        if request.method != Method::GET {
            return Err(EngineError::InvalidInput(
                "download_to_path only supports GET requests".to_owned(),
            ));
        }
        if !request.body.is_empty() {
            return Err(EngineError::InvalidInput(
                "download_to_path does not support non-empty request bodies".to_owned(),
            ));
        }

        self.inject_default_headers(&mut request);
        match self.apply_privacy_middleware(&mut request)? {
            PrivacyInterception::None => {}
            PrivacyInterception::Empty200 => {
                return self.empty_download_outcome(path.as_ref()).await;
            }
        }
        self.apply_fronting_v2_if_enabled(&mut request).await?;

        let parsed = Url::parse(&request.url)?;
        let host = parsed.host_str().map(|v| v.to_ascii_lowercase());

        let path = path.as_ref().to_path_buf();
        let request_for_fragment = request.clone();
        let res = self
            .download_to_path_inner(request, &path, host.as_deref(), progress.clone())
            .await;

        match res {
            Ok(v) => Ok(v),
            Err(e) => {
                if self.should_try_fragment_fallback(&parsed, &e) {
                    self.download_to_path_fragment_fallback(request_for_fragment, &path, progress)
                        .await
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn download_to_path_inner(
        &self,
        request: RequestData,
        path: &Path,
        host: Option<&str>,
        progress: Option<ProgressHook>,
    ) -> Result<DownloadOutcome> {
        let (primary_client, used_ech) = self.select_client_for_host(host).await;
        let mut client: &reqwest::Client = &primary_client;

        let path = path.to_path_buf();
        let headers_map = build_headers(&request.headers)?;

        // Probe server metadata: prefer HEAD but fall back to a tiny Range GET if needed.
        let max_retries = self.config.download.max_retries;
        let head_res = self
            .send_with_retry(max_retries, || {
                client.head(&request.url).headers(headers_map.clone())
            })
            .await;

        let probe = match head_res {
            Ok(r) => r,
            Err(e) if used_ech && should_fallback_from_ech(&e) => {
                client = &self.client_plain;
                // Retry probe on plain transport.
                let head_res = self
                    .send_with_retry(max_retries, || {
                        client.head(&request.url).headers(headers_map.clone())
                    })
                    .await;
                match head_res {
                    Ok(r) => r,
                    Err(_) => {
                        let mut h = headers_map.clone();
                        h.insert(RANGE, HeaderValue::from_static("bytes=0-0"));
                        self.send_with_retry(max_retries, || {
                            client.get(&request.url).headers(h.clone())
                        })
                        .await?
                    }
                }
            }
            Err(_) => {
                let mut h = headers_map.clone();
                h.insert(RANGE, HeaderValue::from_static("bytes=0-0"));
                self.send_with_retry(max_retries, || client.get(&request.url).headers(h.clone()))
                    .await?
            }
        };

        // Extract content length and range support.
        let status_code = probe.status().as_u16();
        let probe_headers = collect_headers(probe.headers());
        let mut content_length = probe
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        // If we probed using Range GET, Content-Length is "1", so prefer parsing Content-Range.
        if let Some(total) = parse_total_length_from_content_range(probe.headers()) {
            content_length = Some(total);
        }

        let _supports_ranges_header = probe
            .headers()
            .get(reqwest::header::ACCEPT_RANGES)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("bytes"))
            .unwrap_or(false);

        // If we used a range GET probe and the server honored it, consuming the tiny body avoids an
        // HTTP/2 RST_STREAM on drop.
        if status_code == 206 && probe.content_length().unwrap_or(0) <= 1024 {
            let _permit =
                match &self.h2_reset_limiter {
                    Some(s) => Some(s.clone().acquire_owned().await.map_err(|_| {
                        EngineError::Internal("h2 reset limiter closed".to_owned())
                    })?),
                    None => None,
                };
            let _ = probe.bytes().await;
        }

        // Confirm the server actually honors Range requests (HEAD can lie).
        let supports_ranges = self
            .probe_range_support(client, &request, &headers_map)
            .await
            .unwrap_or(false);

        // Fast-path: if we know the expected size and the target already exists and matches, skip.
        if let (Some(expected), Ok(meta)) = (content_length, std::fs::metadata(&path)) {
            if meta.is_file() && meta.len() == expected {
                self.verify_download_integrity_if_configured(&path).await?;
                return Ok(DownloadOutcome {
                    status_code,
                    headers: probe_headers,
                    bytes_written: expected,
                    resumed: true,
                    chunked: false,
                    path,
                });
            }
        }

        let chunk_threshold = (self.config.download.chunk_size_mb as u64) * 1024 * 1024;
        let can_chunk = supports_ranges
            && content_length.is_some()
            && content_length.unwrap_or(0) >= chunk_threshold;

        let (bytes_written, resumed, chunked) = if can_chunk {
            let total = content_length.unwrap_or(0);
            let (written, resumed) = self
                .download_chunked_to_parts(
                    client,
                    &request,
                    &headers_map,
                    total,
                    &path,
                    progress.clone(),
                )
                .await?;
            (written, resumed, true)
        } else {
            let (written, resumed) = self
                .download_single_to_file(
                    client,
                    &request,
                    &headers_map,
                    content_length,
                    &path,
                    supports_ranges,
                    progress.clone(),
                )
                .await?;
            (written, resumed, false)
        };

        self.verify_download_integrity_if_configured(&path).await?;
        Ok(DownloadOutcome {
            status_code,
            headers: probe_headers,
            bytes_written,
            resumed,
            chunked,
            path,
        })
    }

    async fn download_to_path_fragment_fallback(
        &self,
        request: RequestData,
        path: &Path,
        progress: Option<ProgressHook>,
    ) -> Result<DownloadOutcome> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let parsed = Url::parse(&request.url)?;
        if parsed.scheme() != "https" {
            return Err(EngineError::InvalidInput(
                "fragment fallback download only supports https://".to_owned(),
            ));
        }

        let started = Instant::now();
        let resp = self
            .fetch_fragment_fallback_stream(&parsed, request.clone())
            .await?;
        let ResponseStream {
            status,
            headers,
            mut stream,
        } = resp;

        let status_code = status.as_u16();
        if !(200..400).contains(&status_code) {
            return Err(EngineError::Internal(format!(
                "http error status {status_code} (url='{}')",
                request.url
            )));
        }

        let total_opt = headers
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let tmp_path: PathBuf = PathBuf::from(format!("{}.prime.tmp", path.to_string_lossy()));
        let mut out = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .await?;

        let mut buf = vec![0u8; 64 * 1024];
        let mut written: u64 = 0;
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).await?;
            written += n as u64;
            if let Some(cb) = &progress {
                let total = total_opt.unwrap_or(0);
                let elapsed = started.elapsed().as_secs_f64().max(0.001);
                let speed_mbps = (written as f64 * 8.0 / 1_000_000.0) / elapsed;
                cb(written, total, speed_mbps);
            }
        }
        out.flush().await?;
        drop(out);

        if let Ok(meta) = tokio::fs::metadata(path).await {
            if meta.is_file() {
                let _ = tokio::fs::remove_file(path).await;
            }
        }
        tokio::fs::rename(&tmp_path, path).await?;
        self.verify_download_integrity_if_configured(path).await?;

        Ok(DownloadOutcome {
            status_code,
            headers: collect_headers(&headers),
            bytes_written: written,
            resumed: false,
            chunked: false,
            path: path.to_path_buf(),
        })
    }

    fn validate_request(&self, request: &RequestData) -> Result<()> {
        if request.url.trim().is_empty() {
            return Err(EngineError::InvalidInput("url is empty".to_owned()));
        }
        let parsed = Url::parse(&request.url)?;
        match parsed.scheme() {
            "http" | "https" => Ok(()),
            _ => Err(EngineError::InvalidInput(
                "only HTTP/HTTPS schemes are supported".to_owned(),
            )),
        }
    }

    fn apply_privacy_middleware(&self, request: &mut RequestData) -> Result<PrivacyInterception> {
        let parsed = Url::parse(&request.url)?;
        let mut interception = PrivacyInterception::None;

        let referer_decision =
            apply_referer_policy(&parsed, &mut request.headers, &self.config.privacy.referer);
        if !matches!(referer_decision, RefererDecision::Kept) {
            tracing::info!(
                target: "privacy.referer",
                "[PRIVACY] referer policy applied: {:?} for {}",
                referer_decision,
                request.url
            );
        }

        if apply_signals(&mut request.headers, &self.config.privacy.signals) {
            tracing::debug!(
                target: "privacy.signals",
                "[PRIVACY] privacy signals injected (DNT={}, GPC={})",
                self.config.privacy.signals.send_dnt,
                self.config.privacy.signals.send_gpc
            );
        }

        if let Some(blocker) = &self.tracker_blocker {
            if let Some(hit) = blocker.matches(&parsed) {
                record_blocked_domain(&hit.host);
                tracing::info!(
                    target: "privacy.tracker",
                    "[BLOCKED][TRACKER] host={} rule={}",
                    hit.host,
                    hit.matched_rule
                );
                tracing::debug!(
                    target: "privacy.tracker",
                    "[BLOCKED][TRACKER] full_url={}",
                    request.url
                );

                if blocker.is_log_only() {
                    tracing::debug!(
                        target: "privacy.tracker",
                        "[PRIVACY][TRACKER] log_only mode, request allowed: {}",
                        request.url
                    );
                } else {
                    match self.config.privacy.tracker_blocker.on_block {
                        TrackerBlockAction::Error => {
                            return Err(EngineError::BlockedByPrivacyPolicy(format!(
                                "tracker request blocked: host={} rule={}",
                                hit.host, hit.matched_rule
                            )));
                        }
                        TrackerBlockAction::Empty200 => {
                            interception = PrivacyInterception::Empty200;
                        }
                    }
                }
            }
        }

        // Privacy Headers: User-Agent override.
        if self.config.privacy.user_agent.enabled {
            let ua_value = self
                .config
                .privacy
                .user_agent
                .preset
                .ua_string()
                .map(str::to_owned)
                .unwrap_or_else(|| self.config.privacy.user_agent.custom_value.clone());
            request
                .headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("user-agent"));
            if !ua_value.is_empty() {
                request.headers.push(("User-Agent".to_owned(), ua_value));
            }
        }

        // Privacy Headers: Referer override.
        if self.config.privacy.referer_override.enabled
            && !self.config.privacy.referer_override.value.is_empty()
        {
            request
                .headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("referer"));
            request.headers.push((
                "Referer".to_owned(),
                self.config.privacy.referer_override.value.clone(),
            ));
        }

        // Privacy Headers: IP spoofing.
        if self.config.privacy.ip_spoof.enabled
            && !self.config.privacy.ip_spoof.spoofed_ip.is_empty()
        {
            let ip = self.config.privacy.ip_spoof.spoofed_ip.clone();
            request.headers.retain(|(k, _)| {
                !k.eq_ignore_ascii_case("x-forwarded-for") && !k.eq_ignore_ascii_case("x-real-ip")
            });
            request
                .headers
                .push(("X-Forwarded-For".to_owned(), ip.clone()));
            request.headers.push(("X-Real-IP".to_owned(), ip));
        }

        // Privacy Headers: WebRTC/Location best-effort permission policy.
        if self.config.privacy.webrtc.block_enabled
            || self.config.privacy.location_api.block_enabled
        {
            request
                .headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("permissions-policy"));
            let policy = if self.config.privacy.webrtc.block_enabled {
                "camera=(), microphone=(), geolocation=()"
            } else {
                "geolocation=()"
            };
            request
                .headers
                .push(("Permissions-Policy".to_owned(), policy.to_owned()));
        }

        Ok(interception)
    }

    fn empty_response_data() -> ResponseData {
        ResponseData {
            status_code: 200,
            headers: vec![
                (
                    "Content-Type".to_owned(),
                    "text/plain; charset=utf-8".to_owned(),
                ),
                ("X-Prime-Privacy".to_owned(), "tracker_blocked".to_owned()),
            ],
            body: Vec::new(),
        }
    }

    fn empty_response_stream() -> ResponseStream {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-prime-privacy"),
            HeaderValue::from_static("tracker_blocked"),
        );
        ResponseStream {
            status: reqwest::StatusCode::OK,
            headers,
            stream: Box::new(tokio::io::empty()),
        }
    }

    async fn empty_download_outcome(&self, path: &Path) -> Result<DownloadOutcome> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(path, []).await?;
        Ok(DownloadOutcome {
            status_code: 200,
            headers: vec![("X-Prime-Privacy".to_owned(), "tracker_blocked".to_owned())],
            bytes_written: 0,
            resumed: false,
            chunked: false,
            path: path.to_path_buf(),
        })
    }

    fn privacy_filter_active(&self) -> bool {
        self.config.privacy.tracker_blocker.enabled
            || self.config.privacy.referer.enabled
            || self.config.privacy.signals.send_dnt
            || self.config.privacy.signals.send_gpc
            || self.config.privacy.user_agent.enabled
            || self.config.privacy.referer_override.enabled
            || self.config.privacy.ip_spoof.enabled
            || self.config.privacy.webrtc.block_enabled
            || self.config.privacy.location_api.block_enabled
    }

    fn inject_default_headers(&self, request: &mut RequestData) {
        if self.config.anticensorship.tls_randomization_enabled
            && !request
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        {
            request.headers.push((
                "User-Agent".to_owned(),
                self.tls_randomizer.random_user_agent().to_owned(),
            ));
        }
    }

    async fn can_use_chunked(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
    ) -> Result<bool> {
        if !self.config.download.adaptive_enabled || request.method != Method::GET {
            return Ok(false);
        }

        let headers = build_headers(&request.headers)?;
        let response = match self
            .send_with_retry(self.config.download.max_retries, || {
                client.head(&request.url).headers(headers.clone())
            })
            .await
        {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        let len = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_default();
        if len == 0 {
            return Ok(false);
        }
        if len < (self.config.download.chunk_size_mb as u64 * 1024 * 1024) {
            return Ok(false);
        }
        let supports_ranges = response
            .headers()
            .get(reqwest::header::ACCEPT_RANGES)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("bytes"))
            .unwrap_or(false);
        if !supports_ranges {
            return Ok(false);
        }

        // HEAD can lie. Confirm Range is actually honored (tiny 1-byte request).
        Ok(self
            .probe_range_support(client, request, &headers)
            .await
            .unwrap_or(false))
    }

    async fn fetch_chunked(
        &self,
        client: &reqwest::Client,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        let headers = build_headers(&request.headers)?;
        let head = self
            .send_with_retry(self.config.download.max_retries, || {
                client.head(&request.url).headers(headers.clone())
            })
            .await?
            .error_for_status()?;
        let content_length = head
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| {
                EngineError::Internal(format!(
                    "missing content-length for chunked mode (url='{}')",
                    request.url
                ))
            })?;

        let body = self
            .chunk_manager
            .download_chunked(
                client,
                &request,
                content_length,
                self.config.download.max_retries,
                progress,
            )
            .await?;
        let headers = collect_headers(head.headers());
        Ok(ResponseData {
            status_code: 200,
            headers,
            body,
        })
    }

    async fn fetch_single(
        &self,
        client: &reqwest::Client,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        let started = Instant::now();
        let RequestData {
            url,
            method,
            headers,
            body,
        } = request;
        let headers_map = build_headers(&headers)?;

        let max_retries = self.config.download.max_retries;
        let should_retry = method == Method::GET && body.is_empty();

        let response = if should_retry {
            self.send_with_retry(max_retries, || {
                client
                    .request(method.clone(), &url)
                    .headers(headers_map.clone())
            })
            .await?
        } else {
            client
                .request(method.clone(), &url)
                .headers(headers_map.clone())
                .body(body)
                .send()
                .await?
        };

        let mut response = response.error_for_status()?;
        let status_code = response.status().as_u16();
        let headers = collect_headers(response.headers());
        let total_opt = response.content_length();

        let mut out = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            out.extend_from_slice(&chunk);
            if let Some(cb) = &progress {
                let downloaded = out.len() as u64;
                let total = total_opt.unwrap_or(0);
                let elapsed = started.elapsed().as_secs_f64().max(0.001);
                let speed_mbps = (downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                cb(downloaded, total, speed_mbps);
            }
        }

        if let Some(cb) = progress {
            let downloaded = out.len() as u64;
            let total = total_opt.unwrap_or(downloaded);
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            let speed_mbps = (downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
            cb(downloaded, total, speed_mbps);
        }

        Ok(ResponseData {
            status_code,
            headers,
            body: out,
        })
    }

}
