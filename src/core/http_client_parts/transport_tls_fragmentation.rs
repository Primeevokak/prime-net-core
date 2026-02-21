impl PrimeHttpClient {
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
            .unwrap_or_default();
        let ech_list = ech_list?;

        let ech_config = match build_rustls_ech_config(&ech_list) {
            Ok(v) => v,
            Err(_) => return None,
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

        self.client_ech_real_cache
            .lock()
            .insert(host, client.clone());
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
            fragment_size: self.config.evasion.fragment_size.max(1),
            sleep_ms: self.config.evasion.fragment_sleep_ms,
            jitter_ms: None,
            randomize_fragment_size: false,
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
            fragment_size: self.config.evasion.fragment_size.max(1),
            sleep_ms: self.config.evasion.fragment_sleep_ms,
            jitter_ms: None,
            randomize_fragment_size: false,
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

        let addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            std::net::SocketAddr::new(ip, port)
        } else {
            let ips = self.resolver_chain.resolve(&host).await?;
            let ip = *ips.first().ok_or_else(|| {
                EngineError::Internal(format!("dns resolver returned no IPs for '{host}'"))
            })?;
            std::net::SocketAddr::new(ip, port)
        };

        let tcp = if let Some(proxy) = &self.config.proxy {
            match proxy.kind {
                crate::config::ProxyKind::Socks5 => {
                    Self::connect_via_socks5(&proxy.address, &host, port).await?
                }
                _ => {
                    return Err(EngineError::Config(
                        "fragment/desync path only supports proxy.kind=socks5".to_owned(),
                    ));
                }
            }
        } else {
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

    async fn connect_via_socks5(proxy_addr: &str, host: &str, port: u16) -> Result<TcpStream> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        fn normalize_proxy_host_port(
            s: &str,
        ) -> Result<(String, u16, Option<String>, Option<String>)> {
            let s = s.trim();
            if s.is_empty() {
                return Err(EngineError::Config("proxy.address is empty".to_owned()));
            }

            if s.contains("://") {
                let url = Url::parse(s)?;
                let user = if !url.username().is_empty() {
                    Some(url.username().to_owned())
                } else {
                    None
                };
                let pass = url.password().map(|v| v.to_owned());
                let host = url.host_str().ok_or_else(|| {
                    EngineError::Config("proxy.address URL missing host".to_owned())
                })?;
                let port = url.port_or_known_default().ok_or_else(|| {
                    EngineError::Config("proxy.address URL missing port".to_owned())
                })?;
                return Ok((host.to_owned(), port, user, pass));
            }

            if let Some((h, p)) = s.rsplit_once(':') {
                let mut host = h.trim().to_owned();
                if host.starts_with('[') {
                    if !host.ends_with(']') {
                        return Err(EngineError::Config(
                            "proxy.address IPv6 must be in the form '[::1]:port'".to_owned(),
                        ));
                    }
                    host = host[1..host.len() - 1].to_owned();
                } else if host.contains(':') {
                    // Likely an IPv6 literal without brackets.
                    return Err(EngineError::Config(
                        "proxy.address IPv6 must be in the form '[::1]:port'".to_owned(),
                    ));
                }
                if host.is_empty() {
                    return Err(EngineError::Config("proxy.address missing host".to_owned()));
                }

                // Support "user:pass@host:port" without a URL scheme (common in config files).
                let (user, pass, host) = if let Some((ui, h2)) = host.rsplit_once('@') {
                    let ui = ui.trim();
                    let h2 = h2.trim();
                    if ui.is_empty() || h2.is_empty() {
                        return Err(EngineError::Config(
                            "proxy.address has invalid credentials syntax".to_owned(),
                        ));
                    }
                    let (u, p) = ui.split_once(':').unwrap_or((ui, ""));
                    (Some(u.to_owned()), Some(p.to_owned()), h2.to_owned())
                } else {
                    (None, None, host)
                };

                let p = p.parse::<u16>().map_err(|_| {
                    EngineError::Config("proxy.address has invalid port".to_owned())
                })?;
                return Ok((host, p, user, pass));
            }

            Err(EngineError::Config(
                "proxy.address must be 'host:port' (or a URL)".to_owned(),
            ))
        }

        let (proxy_host, proxy_port, proxy_user, proxy_pass) =
            normalize_proxy_host_port(proxy_addr)?;
        let mut tcp = TcpStream::connect((proxy_host.as_str(), proxy_port)).await?;
        let _ = tcp.set_nodelay(true);

        let has_creds = proxy_user.is_some();

        // Greeting: VER=5, NMETHODS, METHODS=[USERPASS?, NOAUTH]
        if has_creds {
            tcp.write_all(&[0x05, 0x02, 0x02, 0x00]).await?;
        } else {
            tcp.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut resp = [0u8; 2];
        tcp.read_exact(&mut resp).await?;
        if resp[0] != 0x05 {
            return Err(EngineError::Internal(
                "SOCKS5 invalid reply version".to_owned(),
            ));
        }
        match resp[1] {
            0x00 => {} // NOAUTH
            0x02 => {
                // RFC1929 username/password auth.
                let user = proxy_user.unwrap_or_default();
                let pass = proxy_pass.unwrap_or_default();
                let ub = user.as_bytes();
                let pb = pass.as_bytes();
                if ub.len() > 255 || pb.len() > 255 {
                    return Err(EngineError::InvalidInput(
                        "SOCKS5 username/password is too long".to_owned(),
                    ));
                }
                let mut auth = Vec::with_capacity(3 + ub.len() + pb.len());
                auth.push(0x01); // auth version
                auth.push(ub.len() as u8);
                auth.extend_from_slice(ub);
                auth.push(pb.len() as u8);
                auth.extend_from_slice(pb);
                tcp.write_all(&auth).await?;

                let mut aresp = [0u8; 2];
                tcp.read_exact(&mut aresp).await?;
                if aresp[0] != 0x01 || aresp[1] != 0x00 {
                    return Err(EngineError::Internal(
                        "SOCKS5 username/password auth failed".to_owned(),
                    ));
                }
            }
            0xFF => {
                return Err(EngineError::Internal(
                    "SOCKS5 proxy has no acceptable auth methods".to_owned(),
                ));
            }
            other => {
                return Err(EngineError::Internal(format!(
                    "SOCKS5 proxy selected unsupported auth method 0x{other:02x}"
                )));
            }
        }

        // CONNECT request.
        let mut req = Vec::with_capacity(4 + 1 + host.len() + 2);
        req.push(0x05); // VER
        req.push(0x01); // CMD=CONNECT
        req.push(0x00); // RSV

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    req.push(0x01);
                    req.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    req.push(0x04);
                    req.extend_from_slice(&v6.octets());
                }
            }
        } else {
            let hb = host.as_bytes();
            if hb.len() > 255 {
                return Err(EngineError::InvalidInput(
                    "SOCKS5 host is too long".to_owned(),
                ));
            }
            req.push(0x03);
            req.push(hb.len() as u8);
            req.extend_from_slice(hb);
        }
        req.extend_from_slice(&port.to_be_bytes());

        tcp.write_all(&req).await?;

        // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
        let mut hdr = [0u8; 4];
        tcp.read_exact(&mut hdr).await?;
        if hdr[0] != 0x05 {
            return Err(EngineError::Internal(
                "SOCKS5 invalid reply version".to_owned(),
            ));
        }
        if hdr[1] != 0x00 {
            return Err(EngineError::Internal(format!(
                "SOCKS5 connect failed (REP=0x{:02x})",
                hdr[1]
            )));
        }

        match hdr[3] {
            0x01 => {
                let mut b = [0u8; 4 + 2];
                tcp.read_exact(&mut b).await?;
            }
            0x03 => {
                let mut lenb = [0u8; 1];
                tcp.read_exact(&mut lenb).await?;
                let len = lenb[0] as usize;
                let mut b = vec![0u8; len + 2];
                tcp.read_exact(&mut b).await?;
            }
            0x04 => {
                let mut b = [0u8; 16 + 2];
                tcp.read_exact(&mut b).await?;
            }
            other => {
                return Err(EngineError::Internal(format!(
                    "SOCKS5 invalid reply address type 0x{other:02x}"
                )));
            }
        }

        Ok(tcp)
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
        if !(200..400).contains(&status_code) {
            return Err(EngineError::Internal(format!(
                "http error status {status_code} (url='{}')",
                request.url
            )));
        }

        let headers = collect_headers(resp.headers());
        let total_opt = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame =
                frame.map_err(|e| EngineError::Internal(format!("body read failed: {e}")))?;
            if let Ok(data) = frame.into_data() {
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
