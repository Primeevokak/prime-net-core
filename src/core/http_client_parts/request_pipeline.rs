impl PrimeHttpClient {
    /// Creates a new client from the given engine configuration.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the configuration is invalid or if the underlying HTTP client cannot be built.
    pub fn new(config: EngineConfig) -> Result<Self> {
        config.validate()?;
        let strategy = DownloadStrategy {
            initial_concurrency: config.download.initial_concurrency,
            max_concurrency: config.download.max_concurrency,
            chunk_size_bytes: config.download.chunk_size_mb * 1024 * 1024,
            adaptive_threshold_mbps: config.download.adaptive_threshold_mbps,
        };

        let pool = ConnectionPoolConfig {
            max_idle_per_host: config.download.max_idle_per_host,
            idle_timeout_secs: config.download.pool_idle_timeout_secs,
        };

        let resolver_chain =
            std::sync::Arc::new(ResolverChain::from_config(&config.anticensorship)?);
        let dns_resolver =
            std::sync::Arc::new(PrimeReqwestDnsResolver::new(resolver_chain.clone()));

        // Always build a plain client (no ECH) so we can fall back if ECH fails.
        let tls_plain = build_rustls_client_config(&config, None)?;
        let client_plain = build_reqwest_client(&config, &pool, dns_resolver.clone(), tls_plain)?;

        // Optional ECH GREASE client (used for ech_mode=grease, and as fallback for auto).
        let ech_mode = config.anticensorship.effective_ech_mode();
        let client_ech_grease = match ech_mode {
            Some(EchMode::Grease) | Some(EchMode::Auto) => {
                let tls = build_rustls_client_config(&config, Some(build_ech_grease_mode()?))?;
                Some(build_reqwest_client(
                    &config,
                    &pool,
                    dns_resolver.clone(),
                    tls,
                )?)
            }
            _ => None,
        };

        let (fronting, fronting_v2) =
            build_fronting_maps(&config.anticensorship.domain_fronting_rules);
        let tracker_blocker = TrackerBlocker::from_config(&config.privacy.tracker_blocker)?;

        Ok(Self {
            client_plain,
            client_ech_grease,
            client_ech_real_cache: parking_lot::Mutex::new(std::collections::HashMap::new()),
            chunk_manager: ChunkManager::new(strategy, config.download.adaptive_enabled),
            fronting,
            fronting_v2,
            h2_reset_limiter: config
                .download
                .http2_max_concurrent_reset_streams
                .map(|v| std::sync::Arc::new(tokio::sync::Semaphore::new(v.max(1)))),
            tls_randomizer: TlsFingerprintRandomizer::default(),
            connection_tracker: Some(global_connection_tracker()),
            tracker_blocker,
            resolver_chain,
            dns_resolver,
            config,
        })
    }

    /// Creates a `WebSocketClient` wired to the same DNS resolver chain and domain fronting rules as this HTTP client.
    pub fn websocket_client(&self, ws_config: WsConfig) -> WebSocketClient {
        WebSocketClient::new(ws_config, self.resolver_chain.clone())
            .with_domain_fronting(
                self.config.anticensorship.domain_fronting_enabled,
                self.fronting.clone(),
            )
            .with_domain_fronting_v2(
                self.config.anticensorship.domain_fronting_enabled,
                &self.config.anticensorship.domain_fronting_rules,
                self.config.anticensorship.fronting_probe_ttl_secs,
                self.config.anticensorship.fronting_probe_timeout_secs,
            )
    }

    async fn apply_fronting_v2_if_enabled(&self, req: &mut RequestData) -> Result<()> {
        if !self.config.anticensorship.domain_fronting_enabled {
            return Ok(());
        }

        let parsed = Url::parse(&req.url)?;
        let Some(host) = parsed.host_str() else {
            return Ok(());
        };
        let key = host.to_ascii_lowercase();

        let Some(rule) = self.fronting_v2.rules.get(&key) else {
            // Backward-compatible fallback: if a rule exists only in the legacy proxy map.
            return self.fronting.apply_fronting(req);
        };

        let selected = self.select_working_front_domain(&key, rule).await;
        let front_domain = selected
            .or_else(|| rule.candidates.first().cloned())
            .unwrap_or_else(|| host.to_owned());

        let mut new_url = parsed.clone();
        new_url.set_host(Some(&front_domain))?;
        req.url = new_url.to_string();

        // Override Host header to the real host (domain-fronting).
        req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
        req.headers
            .push(("Host".to_owned(), rule.real_host.clone()));
        Ok(())
    }

    async fn select_working_front_domain(
        &self,
        target_host: &str,
        rule: &FrontingRuleV2,
    ) -> Option<String> {
        let now = Instant::now();
        if let Some(entry) = self
            .fronting_v2
            .cache
            .lock()
            .get(target_host)
            .filter(|e| e.expires_at > now)
        {
            return Some(entry.front_domain.clone());
        }

        for cand in &rule.candidates {
            if self.probe_front_domain(cand, &rule.real_host).await {
                let ttl =
                    Duration::from_secs(self.config.anticensorship.fronting_probe_ttl_secs.max(1));
                self.fronting_v2.cache.lock().insert(
                    target_host.to_owned(),
                    FrontingCacheEntry {
                        front_domain: cand.clone(),
                        expires_at: now + ttl,
                    },
                );
                return Some(cand.clone());
            }
        }
        None
    }

    async fn probe_front_domain(&self, front_domain: &str, real_host: &str) -> bool {
        let Ok(host_header) = HeaderValue::from_str(real_host) else {
            return false;
        };
        let url = format!("https://{front_domain}/");
        let (client, _) = self.select_client_for_host(Some(real_host)).await;
        let req = client.head(url).header(HOST, host_header);

        let timeout = Duration::from_secs(
            self.config
                .anticensorship
                .fronting_probe_timeout_secs
                .max(1),
        );
        match tokio::time::timeout(timeout, req.send()).await {
            Ok(Ok(resp)) => resp.status().as_u16() < 500,
            _ => false,
        }
    }

    #[cfg_attr(feature = "observability", tracing::instrument(skip_all, fields(url = %request.url, method = ?request.method)))]
    /// Executes an HTTP request and returns the full response in memory.
    ///
    /// If `progress` is provided, it is called with progress updates (best-effort).
    ///
    /// # Errors
    ///
    /// Returns `Err` on invalid input, HTTP/TLS errors, or when chunked mode is selected but required
    /// response metadata is missing.
    pub async fn fetch(
        &self,
        mut request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        let started_total = Instant::now();
        self.validate_request(&request)?;
        #[cfg(feature = "observability")]
        tracing::debug!(url = %request.url, method = ?request.method, "http fetch start");
        self.inject_default_headers(&mut request);
        match self.apply_privacy_middleware(&mut request)? {
            PrivacyInterception::None => {}
            PrivacyInterception::Empty200 => {
                #[cfg(feature = "observability")]
                record_http_metrics(started_total, true);
                return Ok(Self::empty_response_data());
            }
        }
        self.apply_fronting_v2_if_enabled(&mut request).await?;

        let parsed = Url::parse(&request.url)?;
        let host = parsed.host_str().map(|v| v.to_ascii_lowercase());

        let evasion = self.effective_evasion_strategy();
        match evasion {
            Some(EvasionStrategy::Desync)
                if parsed.scheme() == "https" || parsed.scheme() == "http" =>
            {
                let res = self
                    .fetch_desync_http1(&parsed, request.clone(), progress.clone())
                    .await;
                match res {
                    Ok(v) => {
                        #[cfg(feature = "observability")]
                        record_http_metrics(started_total, true);
                        return Ok(v);
                    }
                    Err(e) => {
                        if matches!(&e, EngineError::Config(msg) if msg.contains("fragment/desync path only supports proxy.kind=socks5"))
                        {
                            tracing::warn!("desync path not applicable for current proxy settings; falling back to standard HTTP client: {e}");
                        } else {
                            #[cfg(feature = "observability")]
                            record_http_metrics(started_total, false);
                            return Err(e);
                        }
                    }
                }
            }
            Some(EvasionStrategy::Fragment)
                if parsed.scheme() == "https" || parsed.scheme() == "http" =>
            {
                let res = self
                    .fetch_fragmented_http1(&parsed, request.clone(), progress.clone())
                    .await;
                match res {
                    Ok(v) => {
                        #[cfg(feature = "observability")]
                        record_http_metrics(started_total, true);
                        return Ok(v);
                    }
                    Err(e) => {
                        if matches!(&e, EngineError::Config(msg) if msg.contains("fragment/desync path only supports proxy.kind=socks5"))
                        {
                            tracing::warn!("fragment path not applicable for current proxy settings; falling back to standard HTTP client: {e}");
                        } else {
                            #[cfg(feature = "observability")]
                            record_http_metrics(started_total, false);
                            return Err(e);
                        }
                    }
                }
            }
            _ => {}
        }

        if self.config.transport.prefer_http3
            && !matches!(
                evasion,
                Some(EvasionStrategy::Fragment | EvasionStrategy::Desync)
            )
            && parsed.scheme() == "https"
            && self.config.proxy.is_none()
        {
            // Best-effort: try HTTP/3 first, then fall back to the existing stack.
            match self.fetch_http3(request.clone(), progress.clone()).await {
                Ok(v) => {
                    #[cfg(feature = "observability")]
                    record_http_metrics(started_total, true);
                    return Ok(v);
                }
                Err(e) if self.config.transport.http3_only => {
                    #[cfg(feature = "observability")]
                    record_http_metrics(started_total, false);
                    return Err(e);
                }
                Err(_) => {}
            }
        }

        let (primary_client, used_ech) = self.select_client_for_host(host.as_deref()).await;
        let request_for_fragment = request.clone();
        let res = if used_ech {
            let request_plain = request.clone();
            match self
                .fetch_with_client(&primary_client, request, progress.clone())
                .await
            {
                Ok(v) => Ok(v),
                Err(e) if should_fallback_from_ech(&e) => {
                    self.fetch_with_client(&self.client_plain, request_plain, progress.clone())
                        .await
                }
                Err(e) => Err(e),
            }
        } else {
            self.fetch_with_client(&primary_client, request, progress.clone())
                .await
        };

        // Circuit-breaker: if the connection was reset (common DPI behavior), retry once using the
        // fragment strategy (userspace) even if evasion was not explicitly enabled.
        let res = match res {
            Ok(v) => Ok(v),
            Err(e) => {
                if self.should_try_fragment_fallback(&parsed, &e) {
                    self.fetch_fragment_fallback(&parsed, request_for_fragment, progress)
                        .await
                } else {
                    Err(e)
                }
            }
        };

        #[cfg(feature = "observability")]
        record_http_metrics(started_total, res.is_ok());
        res
    }

    #[cfg_attr(feature = "observability", tracing::instrument(skip_all, fields(url = %req.url, method = ?req.method)))]
    /// Executes an HTTP request and returns a streaming response body.
    ///
    /// This avoids buffering the whole payload in memory and is suitable for large downloads.
    pub async fn fetch_stream(&self, mut req: RequestData) -> Result<ResponseStream> {
        let conn = self.connection_tracker.as_ref().map(|tracker| {
            let id = tracker.next_connection_id();
            tracker.begin(id, req.url.clone());
            (tracker, id)
        });
        if let Some((tracker, id)) = conn.as_ref() {
            tracker.update_status(*id, ConnectionStatus::Connecting);
        }

        self.validate_request(&req)?;
        self.inject_default_headers(&mut req);
        match self.apply_privacy_middleware(&mut req) {
            Ok(PrivacyInterception::None) => {
                if self.privacy_filter_active() {
                    if let Some((tracker, id)) = conn.as_ref() {
                        tracker.mark_privacy(*id, false);
                    }
                }
            }
            Ok(PrivacyInterception::Empty200) => {
                if let Some((tracker, id)) = conn.as_ref() {
                    tracker.mark_privacy(*id, true);
                    tracker.update_status(*id, ConnectionStatus::Completed);
                }
                return Ok(Self::empty_response_stream());
            }
            Err(e) => {
                if let Some((tracker, id)) = conn.as_ref() {
                    tracker.mark_privacy(*id, true);
                    tracker.fail(*id, e.to_string());
                }
                return Err(e);
            }
        }
        self.apply_fronting_v2_if_enabled(&mut req).await?;

        let parsed = Url::parse(&req.url)?;
        let host = parsed.host_str().map(|v| v.to_ascii_lowercase());

        // Best-effort DNS resolve via configured chain to avoid leaking to system DNS.
        if let Some(h) = host.as_deref() {
            if let Some((tracker, id)) = conn.as_ref() {
                tracker.update_status(*id, ConnectionStatus::Resolving);
            }
            let dns_started = Instant::now();
            if let Ok(ips) = self.resolver_chain.resolve(h).await {
                if let Some((tracker, id)) = conn.as_ref() {
                    tracker.update_dns(
                        *id,
                        DnsInfo {
                            resolver_used: "Configured chain".to_owned(),
                            resolved_ip: ips
                                .first()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| "n/a".to_owned()),
                            resolution_time_ms: dns_started.elapsed().as_millis() as u64,
                            chain: vec!["resolve".to_owned(), "success".to_owned()],
                        },
                    );
                }
            }
        }

        if let Some((tracker, id)) = conn.as_ref() {
            tracker.update_status(*id, ConnectionStatus::TlsHandshake);
            tracker.update_tls(
                *id,
                TlsInfo {
                    version: "TLS 1.3/1.2".to_owned(),
                    cipher_suite: "negotiated".to_owned(),
                    ech_status: format!("{:?}", self.config.anticensorship.effective_ech_mode()),
                    handshake_time_ms: 0,
                },
            );
        }

        let evasion = self.effective_evasion_strategy();
        match evasion {
            Some(EvasionStrategy::Desync)
                if parsed.scheme() == "https" || parsed.scheme() == "http" =>
            {
                match self.fetch_desync_http1_stream(&parsed, req.clone()).await {
                    Ok(v) => {
                        if let Some((tracker, id)) = conn.as_ref() {
                            tracker.update_status(*id, ConnectionStatus::Completed);
                        }
                        return Ok(v);
                    }
                    Err(e) => {
                        if matches!(&e, EngineError::Config(msg) if msg.contains("fragment/desync path only supports proxy.kind=socks5"))
                        {
                            tracing::warn!("desync stream path not applicable for current proxy settings; falling back to standard HTTP client: {e}");
                        } else {
                            if let Some((tracker, id)) = conn.as_ref() {
                                tracker.fail(*id, e.to_string());
                            }
                            return Err(e);
                        }
                    }
                }
            }
            Some(EvasionStrategy::Fragment)
                if parsed.scheme() == "https" || parsed.scheme() == "http" =>
            {
                match self
                    .fetch_fragmented_http1_stream(&parsed, req.clone())
                    .await
                {
                    Ok(v) => {
                        if let Some((tracker, id)) = conn.as_ref() {
                            tracker.update_status(*id, ConnectionStatus::Completed);
                        }
                        return Ok(v);
                    }
                    Err(e) => {
                        if matches!(&e, EngineError::Config(msg) if msg.contains("fragment/desync path only supports proxy.kind=socks5"))
                        {
                            tracing::warn!("fragment stream path not applicable for current proxy settings; falling back to standard HTTP client: {e}");
                        } else {
                            if let Some((tracker, id)) = conn.as_ref() {
                                tracker.fail(*id, e.to_string());
                            }
                            return Err(e);
                        }
                    }
                }
            }
            _ => {}
        }

        if self.config.transport.prefer_http3
            && !matches!(
                evasion,
                Some(EvasionStrategy::Fragment | EvasionStrategy::Desync)
            )
            && parsed.scheme() == "https"
            && self.config.proxy.is_none()
        {
            match self.fetch_http3_stream(req.clone()).await {
                Ok(v) => {
                    if let Some((tracker, id)) = conn.as_ref() {
                        tracker.update_status(*id, ConnectionStatus::Completed);
                    }
                    return Ok(v);
                }
                Err(e) if self.config.transport.http3_only => {
                    if let Some((tracker, id)) = conn.as_ref() {
                        tracker.fail(*id, e.to_string());
                    }
                    return Err(e);
                }
                Err(_) => {}
            }
        }

        if let Some((tracker, id)) = conn.as_ref() {
            tracker.update_status(*id, ConnectionStatus::Sending);
        }
        let (primary_client, used_ech) = self.select_client_for_host(host.as_deref()).await;
        let req_for_fragment = req.clone();
        let res = if used_ech {
            let req_plain = req.clone();
            match self.fetch_stream_with_client(&primary_client, req).await {
                Ok(v) => Ok(v),
                Err(e) if should_fallback_from_ech(&e) => {
                    self.fetch_stream_with_client(&self.client_plain, req_plain)
                        .await
                }
                Err(e) => Err(e),
            }
        } else {
            self.fetch_stream_with_client(&primary_client, req).await
        };

        let out = match res {
            Ok(v) => Ok(v),
            Err(e) => {
                if self.should_try_fragment_fallback(&parsed, &e) {
                    self.fetch_fragment_fallback_stream(&parsed, req_for_fragment)
                        .await
                } else {
                    Err(e)
                }
            }
        };

        match (&out, conn.as_ref()) {
            (Ok(v), Some((tracker, id))) => {
                tracker.update_status(*id, ConnectionStatus::Receiving);
                let total_bytes = v
                    .headers
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                tracker.update_download(
                    *id,
                    DownloadInfo {
                        bytes_downloaded: 0,
                        total_bytes,
                        speed_bytes_per_sec: 0.0,
                        avg_speed_bytes_per_sec: 0.0,
                    },
                );
                tracker.update_status(*id, ConnectionStatus::Completed);
            }
            (Err(e), Some((tracker, id))) => tracker.fail(*id, e.to_string()),
            _ => {}
        }

        out
    }

    fn should_try_fragment_fallback(&self, parsed: &Url, err: &EngineError) -> bool {
        if parsed.scheme() != "https" {
            return false;
        }
        if self.config.proxy.is_some() {
            return false;
        }
        if matches!(
            self.effective_evasion_strategy(),
            Some(EvasionStrategy::Fragment)
        ) {
            return false;
        }
        is_tcp_connection_reset(err)
    }

    async fn fetch_fragment_fallback(
        &self,
        _parsed: &Url,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        let mut last: Option<EngineError> = None;
        let max = self.config.evasion.rst_retry_max;
        for attempt in 0..=max {
            if attempt > 0 {
                tokio::time::sleep(retry_delay(attempt - 1)).await;
            }

            let parsed = Url::parse(&request.url)?;
            match self
                .fetch_fragmented_http1(&parsed, request.clone(), progress.clone())
                .await
            {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if !is_tcp_connection_reset(&e) {
                        return Err(e);
                    }
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| EngineError::Internal("fragment fallback failed".to_owned())))
    }

    async fn fetch_fragment_fallback_stream(
        &self,
        _parsed: &Url,
        request: RequestData,
    ) -> Result<ResponseStream> {
        let mut last: Option<EngineError> = None;
        let max = self.config.evasion.rst_retry_max;
        for attempt in 0..=max {
            if attempt > 0 {
                tokio::time::sleep(retry_delay(attempt - 1)).await;
            }

            let parsed = Url::parse(&request.url)?;
            match self
                .fetch_fragmented_http1_stream(&parsed, request.clone())
                .await
            {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if !is_tcp_connection_reset(&e) {
                        return Err(e);
                    }
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| EngineError::Internal("fragment fallback failed".to_owned())))
    }

    async fn fetch_stream_with_client(
        &self,
        client: &reqwest::Client,
        request: RequestData,
    ) -> Result<ResponseStream> {
        use std::io;

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

        let response = response.error_for_status()?;
        let status = response.status();
        let headers = response.headers().clone();
        let body_stream = response.bytes_stream().map_err(io::Error::other);
        let reader = StreamReader::new(body_stream);
        Ok(ResponseStream {
            status,
            headers,
            stream: Box::new(reader),
        })
    }

    async fn fetch_with_client(
        &self,
        client: &reqwest::Client,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        if self.can_use_chunked(client, &request).await? {
            return self.fetch_chunked(client, request, progress).await;
        }
        self.fetch_single(client, request, progress).await
    }

}
