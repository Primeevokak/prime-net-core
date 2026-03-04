impl PrimeHttpClient {
    const ECH_REAL_CACHE_MAX_ENTRIES: usize = 128;

    async fn select_client_for_host(&self, host: Option<&str>) -> (reqwest::Client, bool) {
        let Some(mode) = self.config.anticensorship.effective_ech_mode() else {
            return (self.client_plain.clone(), false);
        };

        let Some(host) = host else {
            return match (mode, &self.client_ech_grease) {
                (EchMode::Grease, Some(c)) | (EchMode::Auto, Some(c)) => (c.clone(), true),
                _ => (self.client_plain.clone(), false),
            };
        };

        match mode {
            EchMode::Grease => {
                if let Some(c) = &self.client_ech_grease {
                    return (c.clone(), true);
                }
                (self.client_plain.clone(), false)
            }
            EchMode::Real => {
                if let Some(c) = self.get_or_build_ech_real_client(host).await {
                    return (c, true);
                }
                (self.client_plain.clone(), false)
            }
            EchMode::Auto => {
                if let Some(c) = self.get_or_build_ech_real_client(host).await {
                    return (c, true);
                }
                if let Some(c) = &self.client_ech_grease {
                    return (c.clone(), true);
                }
                (self.client_plain.clone(), false)
            }
        }
    }

    async fn get_or_build_ech_real_client(&self, host: &str) -> Option<reqwest::Client> {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        if let Some(existing) = self.client_ech_real_cache.lock().get(&host).cloned() {
            return Some(existing);
        }

        // Best-effort: no panic, and allow fallback to plain if anything fails.
        let ech_list: Option<Vec<u8>> = self
            .resolver_chain
            .lookup_ech_config_list(&host)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, host = %host, "ECH config lookup failed; falling back to plain TLS");
                None
            });
        let Some(ech_list) = ech_list else {
            return None;
        };

        let ech_config = match build_rustls_ech_config(&ech_list) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, host = %host, "ECH config parse failed; falling back to plain TLS");
                return None;
            }
        };

        let tls = match build_rustls_client_config(
            &self.config,
            Some(rustls::client::EchMode::Enable(ech_config)),
        ) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let pool = ConnectionPoolConfig {
            max_idle_per_host: self.config.download.max_idle_per_host,
            idle_timeout_secs: self.config.download.pool_idle_timeout_secs,
        };
        let client = match build_reqwest_client(&self.config, &pool, self.dns_resolver.clone(), tls)
        {
            Ok(v) => v,
            Err(_) => return None,
        };

        let mut cache = self.client_ech_real_cache.lock();
        if cache.len() >= Self::ECH_REAL_CACHE_MAX_ENTRIES {
            if let Some(old_key) = cache.keys().next().cloned() {
                cache.remove(&old_key);
            }
        }
        cache.insert(host, client.clone());
        Some(client)
    }

    fn effective_evasion_strategy(&self) -> Option<EvasionStrategy> {
        match self.config.evasion.strategy.clone() {
            Some(EvasionStrategy::Auto) => {
                if !self.config.evasion.client_hello_split_offsets.is_empty() {
                    Some(EvasionStrategy::Desync)
                } else {
                    Some(EvasionStrategy::Fragment)
                }
            }
            other => other,
        }
    }

    fn apply_traffic_shaping_to_fragment_cfg(&self, cfg: &mut FragmentConfig) {
        if !self.config.evasion.traffic_shaping_enabled {
            return;
        }
        cfg.jitter_ms = Some((
            self.config.evasion.timing_jitter_ms_min,
            self.config.evasion.timing_jitter_ms_max,
        ));
        cfg.randomize_fragment_size = true;
    }

    fn fragment_cfg_fragment(&self) -> FragmentConfig {
        let mut cfg = FragmentConfig {
            first_write_max: 64,
            first_write_plan: None,
            fragment_size_min: self.config.evasion.fragment_size_min.max(1),
            fragment_size_max: self.config.evasion.fragment_size_max.max(1),
            sleep_ms: self.config.evasion.fragment_sleep_ms,
            jitter_ms: None,
            randomize_fragment_size: self.config.evasion.randomize_fragment_size,
            split_at_sni: false,
        };
        self.apply_traffic_shaping_to_fragment_cfg(&mut cfg);
        cfg
    }

    fn fragment_cfg_desync(&self) -> FragmentConfig {
        let mut sizes: Vec<usize> = Vec::new();
        let mut prev = 0usize;
        for &off in &self.config.evasion.client_hello_split_offsets {
            if off > prev {
                sizes.push(off - prev);
                prev = off;
            }
        }
        if sizes.len() < 3 {
            sizes = vec![1, 1, 1];
        }

        let mut cfg = FragmentConfig {
            first_write_max: 64,
            first_write_plan: Some(sizes),
            fragment_size_min: self.config.evasion.fragment_size_min.max(1),
            fragment_size_max: self.config.evasion.fragment_size_max.max(1),
            sleep_ms: self.config.evasion.fragment_sleep_ms,
            jitter_ms: None,
            randomize_fragment_size: self.config.evasion.randomize_fragment_size,
            split_at_sni: self.config.evasion.split_at_sni,
        };
        self.apply_traffic_shaping_to_fragment_cfg(&mut cfg);
        cfg
    }

    async fn build_rustls_client_config_fragmented(
        &self,
        host: &str,
    ) -> Result<rustls::ClientConfig> {
        // Fragment path uses a dedicated rustls ClientConfig so we can keep ECH behavior consistent
        // while allowing ALPN to negotiate h2 vs http/1.1 (we support both now).
        let cfg = self.config.clone();

        let Some(mode) = cfg.anticensorship.effective_ech_mode() else {
            let mut tls = build_rustls_client_config(&cfg, None)?;
            if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                tls.max_fragment_size = Some(v);
            }
            return Ok(tls);
        };

        match mode {
            EchMode::Grease => {
                let mut tls = build_rustls_client_config(&cfg, Some(build_ech_grease_mode()?))?;
                if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                    tls.max_fragment_size = Some(v);
                }
                Ok(tls)
            }
            EchMode::Real => {
                if host.parse::<std::net::IpAddr>().is_ok() {
                    let mut tls = build_rustls_client_config(&cfg, None)?;
                    if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                        tls.max_fragment_size = Some(v);
                    }
                    return Ok(tls);
                }
                let ech_list = self.resolver_chain.lookup_ech_config_list(host).await?;
                let Some(ech_list) = ech_list else {
                    let mut tls = build_rustls_client_config(&cfg, None)?;
                    if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                        tls.max_fragment_size = Some(v);
                    }
                    return Ok(tls);
                };
                let ech = build_rustls_ech_config(&ech_list)
                    .map_err(|e| EngineError::Internal(format!("ECH config parse failed: {e}")))?;
                let mut tls =
                    build_rustls_client_config(&cfg, Some(rustls::client::EchMode::Enable(ech)))?;
                if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                    tls.max_fragment_size = Some(v);
                }
                Ok(tls)
            }
            EchMode::Auto => {
                if host.parse::<std::net::IpAddr>().is_ok() {
                    let mut tls = build_rustls_client_config(&cfg, Some(build_ech_grease_mode()?))?;
                    if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                        tls.max_fragment_size = Some(v);
                    }
                    return Ok(tls);
                }
                if let Some(ech_list) = self.resolver_chain.lookup_ech_config_list(host).await? {
                    if let Ok(ech) = build_rustls_ech_config(&ech_list) {
                        if let Ok(tls) = build_rustls_client_config(
                            &cfg,
                            Some(rustls::client::EchMode::Enable(ech)),
                        ) {
                            let mut tls = tls;
                            if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                                tls.max_fragment_size = Some(v);
                            }
                            return Ok(tls);
                        }
                    }
                }
                let mut tls = build_rustls_client_config(&cfg, Some(build_ech_grease_mode()?))?;
                if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                    tls.max_fragment_size = Some(v);
                }
                Ok(tls)
            }
        }
    }

    fn url_path_and_query(parsed: &Url) -> String {
        let mut path = parsed.path().to_owned();
        if path.is_empty() {
            path = "/".to_owned();
        }
        if let Some(q) = parsed.query() {
            path.push('?');
            path.push_str(q);
        }
        path
    }

    async fn fragmented_send(
        &self,
        parsed: &Url,
        request: &RequestData,
        fragment_cfg: FragmentConfig,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        use hyper_util::rt::TokioExecutor;

        let host = parsed
            .host_str()
            .ok_or_else(|| EngineError::InvalidInput("url host is missing".to_owned()))?
            .to_owned();
        let scheme = parsed.scheme().to_ascii_lowercase();
        let port = parsed.port_or_known_default().ok_or_else(|| {
            EngineError::InvalidInput(format!(
                "unknown default port for scheme {}",
                parsed.scheme()
            ))
        })?;

        let tcp = if let Some(proxy) = &self.config.proxy {
            match proxy.kind {
                crate::config::ProxyKind::Socks5 => {
                    crate::core::proxy_helper::connect_via_socks5(&proxy.address, &host, port, &self.resolver_chain).await?
                }
                _ => {
                    return Err(EngineError::Config(
                        "fragment/desync path only supports proxy.kind=socks5".to_owned(),
                    ));
                }
            }
        } else {
            let addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                std::net::SocketAddr::new(ip, port)
            } else {
                let ips = self.resolver_chain.resolve(&host).await?;
                let ip = *ips.first().ok_or_else(|| {
                    EngineError::Internal(format!("dns resolver returned no IPs for '{host}'"))
                })?;
                std::net::SocketAddr::new(ip, port)
            };
            TcpStream::connect(addr).await?
        };
        let _ = tcp.set_nodelay(true);

        let (io, handle) = FragmentingIo::new(tcp, fragment_cfg);
        type BoxedIo = Pin<Box<dyn AsyncIo + Send>>;
        let (io, alpn) = match scheme.as_str() {
            "https" => {
                let tls_cfg = self.build_rustls_client_config_fragmented(&host).await?;
                let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_cfg));

                let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                    .map_err(|_| EngineError::InvalidInput(format!("invalid SNI host '{host}'")))?;

                let tls = connector.connect(server_name, io).await?;
                let alpn = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|p| p.to_vec())
                    .unwrap_or_default();
                handle.disable(); // avoid fragmenting application data; keep it during handshake only.
                (TokioIo::new(Box::pin(tls) as BoxedIo), alpn)
            }
            "http" => (TokioIo::new(Box::pin(io) as BoxedIo), Vec::new()),
            _ => {
                return Err(EngineError::InvalidInput(
                    "fragment/desync path only supports http:// and https://".to_owned(),
                ));
            }
        };
        let path = Self::url_path_and_query(parsed);

        let mut headers_map = build_headers(&request.headers)?;
        if !headers_map.contains_key(HOST) {
            headers_map.insert(HOST, HeaderValue::from_str(&host)?);
        }

        let uri = if alpn.as_slice() == b"h2" {
            let scheme = "https";
            let authority = match (host.parse::<std::net::IpAddr>(), port) {
                (Ok(std::net::IpAddr::V6(_)), 443) => format!("[{host}]"),
                (Ok(std::net::IpAddr::V6(_)), _) => format!("[{host}]:{port}"),
                (_, 443) => host.clone(),
                _ => format!("{host}:{port}"),
            };
            http::Uri::builder()
                .scheme(scheme)
                .authority(authority.as_str())
                .path_and_query(path.as_str())
                .build()
                .map_err(|e| {
                    EngineError::InvalidInput(format!("invalid url for h2 request: {e}"))
                })?
        } else {
            path.parse::<http::Uri>().map_err(|e| {
                EngineError::InvalidInput(format!("invalid path for h1 request: {e}"))
            })?
        };

        let mut builder = hyper::Request::builder()
            .method(request.method.clone())
            .uri(uri);
        for (k, v) in headers_map.iter() {
            builder = builder.header(k, v);
        }

        let body = Full::new(Bytes::from(request.body.clone()));
        let req = builder
            .body(body)
            .map_err(|e| EngineError::Internal(format!("failed to build request: {e}")))?;

        if scheme == "https" && alpn.as_slice() == b"h2" {
            let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(io)
                .await
                .map_err(|e| EngineError::Internal(format!("hyper h2 handshake failed: {e}")))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender
                .send_request(req)
                .await
                .map_err(|e| EngineError::Internal(format!("request failed: {e}")))
        } else {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| EngineError::Internal(format!("hyper h1 handshake failed: {e}")))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let res = sender
                .send_request(req)
                .await
                .map_err(|e| EngineError::Internal(format!("request failed: {e}")))?;
            // Best-effort: disable further write fragmentation after the request is sent.
            if scheme == "http" {
                handle.disable();
            }
            Ok(res)
        }
    }

    async fn fetch_fragmented_http1(
        &self,
        parsed: &Url,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        self.fetch_fragmented_http1_with_cfg(
            parsed,
            request,
            progress,
            self.fragment_cfg_fragment(),
        )
        .await
    }

    async fn fetch_desync_http1(
        &self,
        parsed: &Url,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        self.fetch_fragmented_http1_with_cfg(parsed, request, progress, self.fragment_cfg_desync())
            .await
    }

    async fn fetch_fragmented_http1_with_cfg(
        &self,
        parsed: &Url,
        request: RequestData,
        progress: Option<ProgressHook>,
        fragment_cfg: FragmentConfig,
    ) -> Result<ResponseData> {
        let started = Instant::now();
        let resp = self.fragmented_send(parsed, &request, fragment_cfg).await?;

        let status_code = resp.status().as_u16();
        let headers = collect_headers(resp.headers());
        let total_opt = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let max_bytes = (self.config.download.max_response_body_mb as u64) * 1024 * 1024;
        if let Some(cl) = total_opt {
            if cl > max_bytes {
                return Err(EngineError::Internal(format!(
                    "response body too large ({} bytes, limit is {} MB)",
                    cl, self.config.download.max_response_body_mb
                )));
            }
        }

        let mut body = resp.into_body();
        let mut out = Vec::new();
        if let Some(cl) = total_opt {
            out.reserve(cl as usize);
        }

        while let Some(frame) = body.frame().await {
            let frame =
                frame.map_err(|e| EngineError::Internal(format!("body read failed: {e}")))?;
            if let Ok(data) = frame.into_data() {
                if (out.len() + data.len()) as u64 > max_bytes {
                    return Err(EngineError::Internal(format!(
                        "response body exceeded limit of {} MB during fragmented download",
                        self.config.download.max_response_body_mb
                    )));
                }
                out.extend_from_slice(&data);
                if let Some(cb) = &progress {
                    let downloaded = out.len() as u64;
                    let total = total_opt.unwrap_or(0);
                    let elapsed = started.elapsed().as_secs_f64().max(0.001);
                    let speed_mbps = (downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                    cb(downloaded, total, speed_mbps);
                }
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

    async fn fetch_fragmented_http1_stream(
        &self,
        parsed: &Url,
        request: RequestData,
    ) -> Result<ResponseStream> {
        self.fetch_fragmented_http1_stream_with_cfg(parsed, request, self.fragment_cfg_fragment())
            .await
    }

    async fn fetch_desync_http1_stream(
        &self,
        parsed: &Url,
        request: RequestData,
    ) -> Result<ResponseStream> {
        self.fetch_fragmented_http1_stream_with_cfg(parsed, request, self.fragment_cfg_desync())
            .await
    }
}
