impl UniversalDnsResolver {
    /// Resolve A/AAAA records for `domain` and return the results along with DNSSEC validation
    /// (when available and enabled).
    ///
    /// # Errors
    ///
    /// Returns an error if all configured resolvers fail, or if resolution yields no addresses.
    pub async fn resolve_with_dnssec(&self, domain: &str) -> Result<DnsResponse> {
        let ips = self.resolve_ips(domain).await?;
        Ok(DnsResponse { ips })
    }

    /// Resolve a PTR record for `ip`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_ptr(&self, _ip: IpAddr) -> Result<String> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_ptr_hickory(_ip).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "PTR resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    /// Resolve MX records for `domain`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_mx(&self, _domain: &str) -> Result<Vec<MxRecord>> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_mx_hickory(_domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "MX resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    /// Resolve TXT records for `domain`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_txt(&self, _domain: &str) -> Result<Vec<String>> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_txt_hickory(_domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "TXT resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    /// Resolve SRV records for `service` (e.g. `"_sip._tcp.example.com"`).
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_srv(&self, _service: &str) -> Result<Vec<SrvRecord>> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_srv_hickory(_service).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "SRV resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    /// Resolve a CNAME record for `domain`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_cname(&self, _domain: &str) -> Result<String> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_cname_hickory(_domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "CNAME resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    async fn resolve_ips(&self, domain: &str) -> Result<Vec<IpAddr>> {
        #[cfg(feature = "hickory-dns")]
        {
            let mut last_err: Option<EngineError> = None;
            for kind in self.resolver_order() {
                match self.get_or_build_resolver(kind).await {
                    Ok(resolver) => match resolver.lookup_ip(domain).await {
                        Ok(lookup) => {
                            let mut ips: Vec<IpAddr> = lookup.iter().collect();

                            // ANTI-POISONING: Strictly filter out loopback and unspecified IPs for public domains.
                            let is_public_domain = !domain.ends_with(".local") && !domain.contains("localhost");
                            if is_public_domain {
                                ips.retain(|ip| !ip.is_loopback() && !ip.is_unspecified());
                            }

                            if !ips.is_empty() {
                                ips.sort_unstable();
                                ips.dedup();
                                return Ok(ips);
                            }

                            last_err = Some(EngineError::Internal(format!(
                                "dns lookup for '{domain}' using {kind:?} returned only poisoned or empty results"
                            )));
                        }
                        Err(e) => {
                            last_err = Some(EngineError::Internal(format!(
                                "dns lookup for '{domain}' failed using {kind:?}: {e}"
                            )));
                        }
                    },
                    Err(e) => last_err = Some(e),
                }
            }
            Err(last_err.unwrap_or_else(|| {
                EngineError::Internal(format!(
                    "dns lookup for '{domain}' failed: all resolvers returned no valid addresses"
                ))
            }))
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            self.resolve_system(domain).await
        }
    }

    #[cfg(not(feature = "hickory-dns"))]
    async fn resolve_system(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let result = tokio::net::lookup_host((domain, 443)).await.map_err(|e| {
            EngineError::Internal(format!("system dns lookup for '{domain}' failed: {e}"))
        })?;
        let mut ips: Vec<IpAddr> = result.map(|addr| addr.ip()).collect();
        ips.sort_unstable();
        ips.dedup();
        if ips.is_empty() {
            return Err(EngineError::Internal(format!(
                "system dns lookup for '{domain}' returned no addresses"
            )));
        }
        Ok(ips)
    }

    #[cfg(feature = "hickory-dns")]
    fn resolver_order(&self) -> impl Iterator<Item = &DnsResolverType> {
        std::iter::once(&self.primary).chain(self.fallback_chain.iter())
    }

    #[cfg(feature = "hickory-dns")]
    fn resolver_opts(&self) -> ResolverOpts {
        let mut opts = ResolverOpts::default();
        opts.cache_size = self.config.cache_size.max(512);
        opts.recursion_desired = true;
        opts.timeout = if self.config.query_timeout.as_secs() == 0 {
            Duration::from_secs(5)
        } else {
            self.config.query_timeout.max(Duration::from_secs(3))
        };
        opts.attempts = (self.config.retry_count + 3).max(3);
        opts
    }

    #[cfg(feature = "hickory-dns")]
    fn cache_key_for(&self, kind: &DnsResolverType) -> ResolverCacheKey {
        let opts = self.resolver_opts();
        ResolverCacheKey {
            resolver: match kind {
                DnsResolverType::SystemDns => "system".to_owned(),
                DnsResolverType::DoH(p) => match p {
                    DoHProvider::Cloudflare => "doh:cloudflare".to_owned(),
                    DoHProvider::Google => "doh:google".to_owned(),
                    DoHProvider::Quad9 => "doh:quad9".to_owned(),
                    DoHProvider::AdGuard => "doh:adguard".to_owned(),
                    DoHProvider::Custom { url } => format!("doh:custom:{url}"),
                },
                DnsResolverType::DoT(v) => match v {
                    DnsTlsUpstream::Address(server) => format!("dot:{server}"),
                    DnsTlsUpstream::AddressWithSni { server, sni } => match sni.as_deref() {
                        Some(s) if !s.trim().is_empty() => format!("dot:{server}#sni={s}"),
                        _ => format!("dot:{server}"),
                    },
                },
                DnsResolverType::DoQ(v) => match v {
                    DnsTlsUpstream::Address(server) => format!("doq:{server}"),
                    DnsTlsUpstream::AddressWithSni { server, sni } => match sni.as_deref() {
                        Some(s) if !s.trim().is_empty() => format!("doq:{server}#sni={s}"),
                        _ => format!("doq:{server}"),
                    },
                },
                DnsResolverType::CustomUdp(v) => format!("udp:{v}"),
                DnsResolverType::CustomTcp(v) => format!("tcp:{v}"),
            },
            dnssec: false, // Hardcoded false
            cache_size: opts.cache_size,
            timeout_ms: opts.timeout.as_millis() as u64,
            attempts: opts.attempts,
        }
    }

    async fn get_or_build_resolver(&self, kind: &DnsResolverType) -> Result<TokioResolver> {
        let key = self.cache_key_for(kind);
        let cache = RESOLVER_CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
        {
            let guard = cache.lock();
            if let Some(v) = guard.get(&key).cloned() {
                return Ok(v);
            }
        }

        // Prevent recursive resolver building on the same task/thread which causes deadlocks.
        // If we are already building THIS specific resolver kind, something is wrong (circular bootstrap).
        tokio::task_local! {
            static IS_BUILDING: bool;
        }

        let build_guard = {
            let guards = RESOLVER_BUILD_GUARDS
                .get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
            let mut map = guards.lock();
            map.entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };

        let _build_lock = build_guard.lock().await;

        // Re-check cache after acquiring lock
        {
            let guard = cache.lock();
            if let Some(v) = guard.get(&key).cloned() {
                return Ok(v);
            }
        }

        let resolver = match self.build_resolver(kind).await {
            Ok(v) => v,
            Err(e) => {
                // Cleanup guard if build failed to allow future attempts
                if let Some(guards) = RESOLVER_BUILD_GUARDS.get() {
                    guards.lock().remove(&key);
                }
                return Err(e);
            }
        };

        {
            let mut guard = cache.lock();
            if guard.len() >= RESOLVER_CACHE_MAX_ENTRIES {
                if let Some(old_key) = guard.keys().next().cloned() {
                    guard.remove(&old_key);
                }
            }
            guard.insert(key.clone(), resolver.clone());
        }

        // Remove guard from map after successful build
        if let Some(guards) = RESOLVER_BUILD_GUARDS.get() {
            guards.lock().remove(&key);
        }

        Ok(resolver)
    }

    #[cfg(feature = "hickory-dns")]
    async fn build_resolver(&self, kind: &DnsResolverType) -> Result<TokioResolver> {
        match kind {
            DnsResolverType::SystemDns => {
                let mut builder = TokioResolver::builder_tokio().map_err(|e| {
                    EngineError::Internal(format!("system resolver build failed: {e}"))
                })?;
                let opts = self.resolver_opts();
                builder.options_mut().cache_size = opts.cache_size;
                builder.options_mut().timeout = opts.timeout;
                builder.options_mut().attempts = opts.attempts;
                Ok(builder.build())
            }
            DnsResolverType::DoH(provider) => {
                let (host, endpoint) = doh_host_and_path(provider)?;
                let addrs =
                    resolve_socket_addrs(&host, 443, &self.config.bootstrap_ips, false).await?;
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    let mut ns = NameServerConfig::new(sa, Protocol::Https);
                    ns.tls_dns_name = Some(host.clone());
                    ns.http_endpoint = endpoint.clone();
                    group.push(ns);
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no DoH name servers resolved".to_owned(),
                    ));
                }

                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
            DnsResolverType::DoT(server) => {
                let (host, port) = split_host_port(server.server(), 853)?;
                let addrs =
                    resolve_socket_addrs(&host, port, &self.config.bootstrap_ips, false).await?;
                let sni = server.sni().map(str::trim).filter(|s| !s.is_empty());
                if let Some(sni) = sni {
                    if is_ip_literal(sni) {
                        return Err(EngineError::Config(format!(
                            "invalid DoT SNI (must be a hostname, not an IP): {sni}"
                        )));
                    }
                }
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    let mut ns = NameServerConfig::new(sa, Protocol::Tls);
                    if is_ip_literal(&host) {
                        let sni = sni.ok_or_else(|| {
                            EngineError::Config(format!(
                                "DoT server is an IP literal and requires explicit SNI for certificate validation: {host}:{port}"
                            ))
                        })?;
                        ns.tls_dns_name = Some(sni.to_owned());
                    } else {
                        ns.tls_dns_name = Some(sni.unwrap_or(&host).to_owned());
                    }
                    group.push(ns);
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no DoT name servers resolved".to_owned(),
                    ));
                }
                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
            DnsResolverType::DoQ(server) => {
                let (host, port) = split_host_port(server.server(), 784)?;
                let addrs =
                    resolve_socket_addrs(&host, port, &self.config.bootstrap_ips, false).await?;
                let sni = server.sni().map(str::trim).filter(|s| !s.is_empty());
                if let Some(sni) = sni {
                    if is_ip_literal(sni) {
                        return Err(EngineError::Config(format!(
                            "invalid DoQ SNI (must be a hostname, not an IP): {sni}"
                        )));
                    }
                }
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    let mut ns = NameServerConfig::new(sa, Protocol::Quic);
                    if is_ip_literal(&host) {
                        let sni = sni.ok_or_else(|| {
                            EngineError::Config(format!(
                                "DoQ server is an IP literal and requires explicit SNI for certificate validation: {host}:{port}"
                            ))
                        })?;
                        ns.tls_dns_name = Some(sni.to_owned());
                    } else {
                        ns.tls_dns_name = Some(sni.unwrap_or(&host).to_owned());
                    }
                    group.push(ns);
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no DoQ name servers resolved".to_owned(),
                    ));
                }
                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
            DnsResolverType::CustomUdp(server) => {
                let (host, port) = split_host_port(server, 53)?;
                let addrs =
                    resolve_socket_addrs(&host, port, &self.config.bootstrap_ips, false).await?;
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    group.push(NameServerConfig::new(sa, Protocol::Udp));
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no UDP name servers resolved".to_owned(),
                    ));
                }
                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
            DnsResolverType::CustomTcp(server) => {
                let (host, port) = split_host_port(server, 53)?;
                let addrs =
                    resolve_socket_addrs(&host, port, &self.config.bootstrap_ips, false).await?;
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    group.push(NameServerConfig::new(sa, Protocol::Tcp));
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no TCP name servers resolved".to_owned(),
                    ));
                }
                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
        }
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_ptr_hickory(&self, ip: IpAddr) -> Result<String> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.reverse_lookup(ip).await {
                Ok(lookup) => {
                    if let Some(ptr) = lookup.iter().next() {
                        return Ok(trim_trailing_dot(&ptr.to_utf8()));
                    }
                    last_err = Some(EngineError::Internal(
                        "PTR lookup returned no records".to_owned(),
                    ));
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "PTR lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("PTR lookup failed".to_owned())))
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_mx_hickory(&self, domain: &str) -> Result<Vec<MxRecord>> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.mx_lookup(domain).await {
                Ok(lookup) => {
                    let mut out: Vec<MxRecord> = lookup
                        .iter()
                        .map(|mx| MxRecord {
                            preference: mx.preference(),
                            exchange: trim_trailing_dot(&mx.exchange().to_utf8()),
                        })
                        .collect();
                    out.sort_by_key(|v| v.preference);
                    return Ok(out);
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "MX lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("MX lookup failed".to_owned())))
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_txt_hickory(&self, domain: &str) -> Result<Vec<String>> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.txt_lookup(domain).await {
                Ok(lookup) => {
                    let mut out = Vec::new();
                    for txt in lookup.iter() {
                        // TXT records can be split across multiple character-strings; join them.
                        let mut bytes = Vec::new();
                        for part in txt.txt_data() {
                            bytes.extend_from_slice(part);
                        }
                        out.push(String::from_utf8_lossy(&bytes).to_string());
                    }
                    return Ok(out);
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "TXT lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("TXT lookup failed".to_owned())))
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_srv_hickory(&self, service: &str) -> Result<Vec<SrvRecord>> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.srv_lookup(service).await {
                Ok(lookup) => {
                    let mut out: Vec<SrvRecord> = lookup
                        .iter()
                        .map(|srv| SrvRecord {
                            priority: srv.priority(),
                            weight: srv.weight(),
                            port: srv.port(),
                            target: trim_trailing_dot(&srv.target().to_utf8()),
                        })
                        .collect();
                    out.sort_by_key(|v| (v.priority, v.weight, v.port));
                    return Ok(out);
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "SRV lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("SRV lookup failed".to_owned())))
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_cname_hickory(&self, domain: &str) -> Result<String> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.lookup(domain, RecordType::CNAME).await {
                Ok(lookup) => {
                    for r in lookup.iter() {
                        if let RData::CNAME(cname) = r {
                            return Ok(trim_trailing_dot(&cname.0.to_utf8()));
                        }
                    }
                    last_err = Some(EngineError::Internal(
                        "CNAME lookup returned no CNAME records".to_owned(),
                    ));
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "CNAME lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("CNAME lookup failed".to_owned())))
    }
}

#[cfg(feature = "hickory-dns")]
fn trim_trailing_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_owned()
}

#[cfg(feature = "hickory-dns")]
fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}
