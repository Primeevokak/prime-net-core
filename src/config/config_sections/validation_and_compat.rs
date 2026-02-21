impl EngineConfig {
    pub fn builder() -> EngineConfigBuilder {
        EngineConfigBuilder::new()
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        let ext = path
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or_default();
        let mut config: EngineConfig = match ext {
            "toml" => toml::from_str(&content).map_err(|e| EngineError::Config(e.to_string()))?,
            "json" => {
                serde_json::from_str(&content).map_err(|e| EngineError::Config(e.to_string()))?
            }
            "yaml" | "yml" => {
                serde_yaml::from_str(&content).map_err(|e| EngineError::Config(e.to_string()))?
            }
            _ => toml::from_str(&content)
                .or_else(|_| serde_json::from_str(&content))
                .or_else(|_| serde_yaml::from_str(&content))
                .map_err(|e| EngineError::Config(e.to_string()))?,
        };
        let _ = config.apply_compat_repairs();
        config.validate()?;
        Ok(config)
    }

    /// Applies compatibility repairs for legacy or partially-migrated configs.
    ///
    /// Returns textual notes describing each applied repair.
    pub fn apply_compat_repairs(&mut self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.anticensorship.domain_fronting_enabled
            && self.anticensorship.domain_fronting_rules.is_empty()
        {
            self.anticensorship.domain_fronting_enabled = false;
            notes.push(
                "anticensorship.domain_fronting_enabled disabled because domain_fronting_rules is empty"
                    .to_owned(),
            );
        }

        let old_chain = self.anticensorship.dns_fallback_chain.clone();
        self.anticensorship
            .dns_fallback_chain
            .retain(|kind| match kind {
                DnsResolverKind::Doh => self.anticensorship.doh_enabled,
                DnsResolverKind::Dot => self.anticensorship.dot_enabled,
                DnsResolverKind::Doq => self.anticensorship.doq_enabled,
                DnsResolverKind::System => self.anticensorship.system_dns_enabled,
            });
        if self.anticensorship.dns_fallback_chain.is_empty() {
            if self.anticensorship.doh_enabled {
                self.anticensorship
                    .dns_fallback_chain
                    .push(DnsResolverKind::Doh);
            } else if self.anticensorship.system_dns_enabled {
                self.anticensorship
                    .dns_fallback_chain
                    .push(DnsResolverKind::System);
            } else if self.anticensorship.dot_enabled {
                self.anticensorship
                    .dns_fallback_chain
                    .push(DnsResolverKind::Dot);
            } else if self.anticensorship.doq_enabled {
                self.anticensorship
                    .dns_fallback_chain
                    .push(DnsResolverKind::Doq);
            }
        }
        if self.anticensorship.dns_fallback_chain != old_chain {
            notes.push(
                "anticensorship.dns_fallback_chain repaired to match enabled resolvers".to_owned(),
            );
        }

        let old_doh = self.anticensorship.doh_providers.clone();
        self.anticensorship
            .doh_providers
            .retain(|p| !p.trim().eq_ignore_ascii_case("cloudflare"));
        if self.anticensorship.doh_providers.is_empty() {
            self.anticensorship.doh_providers = vec![
                "adguard".to_owned(),
                "google".to_owned(),
                "quad9".to_owned(),
            ];
        }
        if self.anticensorship.doh_providers != old_doh {
            notes.push(
                "anticensorship.doh_providers repaired: cloudflare removed, adguard/google/quad9 prioritized"
                    .to_owned(),
            );
        }

        let old_dot = self.anticensorship.dot_servers.clone();
        self.anticensorship.dot_servers.retain(|s| {
            let v = s.trim();
            v != "1.1.1.1:853" && v != "1.0.0.1:853"
        });
        if self.anticensorship.dot_enabled && self.anticensorship.dot_servers.is_empty() {
            self.anticensorship.dot_servers = vec![
                "94.140.14.14:853".to_owned(),
                "94.140.15.15:853".to_owned(),
                "8.8.8.8:853".to_owned(),
                "8.8.4.4:853".to_owned(),
            ];
            self.anticensorship.dot_sni = "dns.adguard-dns.com".to_owned();
        }
        if self.anticensorship.dot_servers != old_dot {
            notes.push(
                "anticensorship.dot_servers repaired: cloudflare endpoints removed".to_owned(),
            );
        }

        let old_doq = self.anticensorship.doq_servers.clone();
        self.anticensorship.doq_servers.retain(|s| {
            let v = s.trim();
            v != "1.1.1.1:784" && v != "1.0.0.1:784"
        });
        if self.anticensorship.doq_enabled && self.anticensorship.doq_servers.is_empty() {
            self.anticensorship.doq_servers =
                vec!["94.140.14.14:784".to_owned(), "94.140.15.15:784".to_owned()];
            self.anticensorship.doq_sni = "dns.adguard-dns.com".to_owned();
        }
        if self.anticensorship.doq_servers != old_doq {
            notes.push(
                "anticensorship.doq_servers repaired: cloudflare endpoints removed".to_owned(),
            );
        }
        notes
    }

    pub fn validate(&self) -> Result<()> {
        self.tls.validate()?;
        if self.anticensorship.effective_ech_mode().is_some() {
            let min = self.tls.min_version;
            let max = self.tls.max_version;
            let min_r = tls_version_rank(min);
            let max_r = tls_version_rank(max);
            if !(min_r <= tls_version_rank(crate::tls::TlsVersion::Tls1_3)
                && max_r >= tls_version_rank(crate::tls::TlsVersion::Tls1_3))
            {
                return Err(EngineError::Config(
                    "anticensorship.ech_mode requires TLS 1.3 to be allowed by tls.min_version/tls.max_version"
                        .to_owned(),
                ));
            }
        }
        if self.download.initial_concurrency == 0 {
            return Err(EngineError::Config(
                "download.initial_concurrency must be > 0".to_owned(),
            ));
        }
        if self.download.max_concurrency == 0 {
            return Err(EngineError::Config(
                "download.max_concurrency must be > 0".to_owned(),
            ));
        }
        if self.download.initial_concurrency > self.download.max_concurrency {
            return Err(EngineError::Config(
                "download.initial_concurrency cannot exceed max_concurrency".to_owned(),
            ));
        }
        if self.download.chunk_size_mb == 0 {
            return Err(EngineError::Config(
                "download.chunk_size_mb must be > 0".to_owned(),
            ));
        }
        if self.download.request_timeout_secs == 0 || self.download.connect_timeout_secs == 0 {
            return Err(EngineError::Config(
                "request/connect timeout values must be > 0".to_owned(),
            ));
        }
        if self.transport.http3_connect_timeout_ms == 0 {
            return Err(EngineError::Config(
                "transport.http3_connect_timeout_ms must be > 0".to_owned(),
            ));
        }
        if self.transport.http3_only && !self.transport.prefer_http3 {
            return Err(EngineError::Config(
                "transport.http3_only=true requires transport.prefer_http3=true".to_owned(),
            ));
        }
        if self.transport.http3_idle_timeout_ms == 0 {
            return Err(EngineError::Config(
                "transport.http3_idle_timeout_ms must be > 0".to_owned(),
            ));
        }
        if let Some(v) = self.transport.http3_keep_alive_interval_ms {
            if v == 0 {
                return Err(EngineError::Config(
                    "transport.http3_keep_alive_interval_ms must be > 0 when set".to_owned(),
                ));
            }
        }
        if let Some(pt) = &self.pt {
            if self.proxy.is_some() {
                return Err(EngineError::Config(
                    "pt is enabled but proxy is also set; use only one (pt will provide a local socks5 endpoint)"
                        .to_owned(),
                ));
            }
            if pt.local_socks5_bind.trim().is_empty() {
                return Err(EngineError::Config(
                    "pt.local_socks5_bind must not be empty".to_owned(),
                ));
            }
            match pt.kind {
                PluggableTransportKind::Trojan => {
                    let t = pt.trojan.as_ref().ok_or_else(|| {
                        EngineError::Config("pt.kind=trojan requires [pt].trojan".to_owned())
                    })?;
                    if t.server.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.trojan.server must not be empty".to_owned(),
                        ));
                    }
                    if t.password.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.trojan.password must not be empty".to_owned(),
                        ));
                    }
                }
                PluggableTransportKind::Shadowsocks => {
                    let s = pt.shadowsocks.as_ref().ok_or_else(|| {
                        EngineError::Config(
                            "pt.kind=shadowsocks requires [pt].shadowsocks".to_owned(),
                        )
                    })?;
                    if s.server.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.shadowsocks.server must not be empty".to_owned(),
                        ));
                    }
                    if s.password.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.shadowsocks.password must not be empty".to_owned(),
                        ));
                    }
                    if s.method.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.shadowsocks.method must not be empty".to_owned(),
                        ));
                    }
                }
                PluggableTransportKind::Obfs4 => {
                    let o = pt.obfs4.as_ref().ok_or_else(|| {
                        EngineError::Config("pt.kind=obfs4 requires [pt].obfs4".to_owned())
                    })?;
                    if o.server.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.obfs4.server must not be empty".to_owned(),
                        ));
                    }
                    if o.cert.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.obfs4.cert must not be empty".to_owned(),
                        ));
                    }
                }
                PluggableTransportKind::Snowflake => {
                    let s = pt.snowflake.as_ref().ok_or_else(|| {
                        EngineError::Config("pt.kind=snowflake requires [pt].snowflake".to_owned())
                    })?;
                    if let Some(bridge) = s.bridge.as_deref() {
                        if bridge.trim().is_empty() {
                            return Err(EngineError::Config(
                                "pt.snowflake.bridge must not be empty when set".to_owned(),
                            ));
                        }
                    }
                }
            }
        }
        if let Some(v) = self.evasion.tls_record_max_fragment_size {
            // TLS maximum fragment length is capped at 2^14 (16384) bytes (RFC 8446/5246 record limits).
            if v == 0 || v > 16_384 {
                return Err(EngineError::Config(
                    "evasion.tls_record_max_fragment_size must be in 1..=16384".to_owned(),
                ));
            }
        }
        if !self.evasion.client_hello_split_offsets.is_empty() {
            let mut prev = 0usize;
            for &off in &self.evasion.client_hello_split_offsets {
                if off == 0 {
                    return Err(EngineError::Config(
                        "evasion.client_hello_split_offsets must not contain 0".to_owned(),
                    ));
                }
                if off <= prev {
                    return Err(EngineError::Config(
                        "evasion.client_hello_split_offsets must be strictly increasing".to_owned(),
                    ));
                }
                prev = off;
            }
        }
        if self.evasion.fragment_budget_bytes == 0 {
            return Err(EngineError::Config(
                "evasion.fragment_budget_bytes must be > 0".to_owned(),
            ));
        }
        if self.evasion.classifier_entry_ttl_secs == 0 {
            return Err(EngineError::Config(
                "evasion.classifier_entry_ttl_secs must be > 0".to_owned(),
            ));
        }
        if self.evasion.classifier_cache_path.trim().is_empty() {
            return Err(EngineError::Config(
                "evasion.classifier_cache_path must not be empty".to_owned(),
            ));
        }
        if self.evasion.traffic_shaping_enabled
            && self.evasion.timing_jitter_ms_min > self.evasion.timing_jitter_ms_max
        {
            return Err(EngineError::Config(
                "evasion.timing_jitter_ms_min must be <= evasion.timing_jitter_ms_max".to_owned(),
            ));
        }
        if let Some(v) = self.download.http2_max_concurrent_reset_streams {
            if v == 0 {
                return Err(EngineError::Config(
                    "download.http2_max_concurrent_reset_streams must be > 0".to_owned(),
                ));
            }
        }
        if let Some(v) = self.download.verify_hash.as_deref() {
            let v = v.trim();
            if v.is_empty() {
                return Err(EngineError::Config(
                    "download.verify_hash must not be empty when provided".to_owned(),
                ));
            }
            if v.eq_ignore_ascii_case("auto") {
                // Expected digest comes from "<file>.sha256" at runtime.
            } else if let Some(hex) = v.strip_prefix("sha256:") {
                let hex = hex.trim();
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(EngineError::Config(
                        "download.verify_hash must be 'auto' or 'sha256:<64 hex>'".to_owned(),
                    ));
                }
            } else {
                return Err(EngineError::Config(
                    "download.verify_hash must be 'auto' or 'sha256:<64 hex>'".to_owned(),
                ));
            }
        }
        if self.anticensorship.domain_fronting_enabled
            && self.anticensorship.domain_fronting_rules.is_empty()
        {
            return Err(EngineError::Config(
                "anticensorship.domain_fronting_rules must be provided when domain_fronting_enabled=true"
                    .to_owned(),
            ));
        }
        for rule in &self.anticensorship.domain_fronting_rules {
            if rule.target_host.trim().is_empty() {
                return Err(EngineError::Config(
                    "anticensorship.domain_fronting_rules[*].target_host is empty".to_owned(),
                ));
            }
            let has_v2 = rule.front_domains.iter().any(|d| !d.trim().is_empty());
            let has_v1 = !rule.front_domain.trim().is_empty();
            if !(has_v1 || has_v2) {
                return Err(EngineError::Config(
                    "anticensorship.domain_fronting_rules[*] must have front_domain or front_domains".to_owned(),
                ));
            }
            if rule.front_domains.iter().any(|d| d.trim().is_empty()) {
                return Err(EngineError::Config(
                    "anticensorship.domain_fronting_rules[*].front_domains contains empty domain"
                        .to_owned(),
                ));
            }
            if rule.real_host.trim().is_empty() {
                return Err(EngineError::Config(
                    "anticensorship.domain_fronting_rules[*].real_host is empty".to_owned(),
                ));
            }
        }

        if self.anticensorship.dns_fallback_chain.is_empty() {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain must not be empty".to_owned(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for kind in &self.anticensorship.dns_fallback_chain {
            if !seen.insert(kind) {
                return Err(EngineError::Config(
                    "anticensorship.dns_fallback_chain contains duplicate entries".to_owned(),
                ));
            }
        }
        if !self.anticensorship.doh_enabled
            && self
                .anticensorship
                .dns_fallback_chain
                .contains(&DnsResolverKind::Doh)
        {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain includes doh but doh_enabled=false".to_owned(),
            ));
        }
        if !self.anticensorship.dot_enabled
            && self
                .anticensorship
                .dns_fallback_chain
                .contains(&DnsResolverKind::Dot)
        {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain includes dot but dot_enabled=false".to_owned(),
            ));
        }
        if self.anticensorship.dot_enabled && self.anticensorship.dot_servers.is_empty() {
            return Err(EngineError::Config(
                "anticensorship.dot_servers must not be empty when dot_enabled=true".to_owned(),
            ));
        }
        if !self.anticensorship.doq_enabled
            && self
                .anticensorship
                .dns_fallback_chain
                .contains(&DnsResolverKind::Doq)
        {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain includes doq but doq_enabled=false".to_owned(),
            ));
        }
        if self.anticensorship.doq_enabled && self.anticensorship.doq_servers.is_empty() {
            return Err(EngineError::Config(
                "anticensorship.doq_servers must not be empty when doq_enabled=true".to_owned(),
            ));
        }
        if !self.anticensorship.system_dns_enabled
            && self
                .anticensorship
                .dns_fallback_chain
                .contains(&DnsResolverKind::System)
        {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain includes system but system_dns_enabled=false"
                    .to_owned(),
            ));
        }
        if self.blocklist.update_interval_hours == 0 {
            return Err(EngineError::Config(
                "blocklist.update_interval_hours must be > 0".to_owned(),
            ));
        }
        if self.system_proxy.pac_port == 0 {
            return Err(EngineError::Config(
                "system_proxy.pac_port must be in 1..=65535".to_owned(),
            ));
        }
        if !is_host_port_endpoint(&self.system_proxy.socks_endpoint) {
            return Err(EngineError::Config(
                "system_proxy.socks_endpoint must be 'host:port' (IPv6: '[::1]:port')".to_owned(),
            ));
        }
        if self.updater.check_interval_hours == 0 {
            return Err(EngineError::Config(
                "updater.check_interval_hours must be > 0".to_owned(),
            ));
        }
        if !is_valid_repo_slug(&self.updater.repo) {
            return Err(EngineError::Config(
                "updater.repo must be 'owner/name'".to_owned(),
            ));
        }
        for domain in &self.privacy.referer.search_engine_domains {
            if normalize_domain(domain).is_none() {
                return Err(EngineError::Config(
                    "privacy.referer.search_engine_domains must contain valid domains".to_owned(),
                ));
            }
        }
        for domain in &self.privacy.tracker_blocker.allowlist {
            if normalize_domain(domain).is_none() {
                return Err(EngineError::Config(
                    "privacy.tracker_blocker.allowlist must contain valid domains".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn tls_version_rank(v: crate::tls::TlsVersion) -> u8 {
    match v {
        crate::tls::TlsVersion::Tls1_0 => 10,
        crate::tls::TlsVersion::Tls1_1 => 11,
        crate::tls::TlsVersion::Tls1_2 => 12,
        crate::tls::TlsVersion::Tls1_3 => 13,
    }
}

fn is_host_port_endpoint(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }

    if let Some(rest) = v.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return false;
        };
        if host.trim().is_empty() {
            return false;
        }
        let Some(port) = tail.strip_prefix(':') else {
            return false;
        };
        return port.trim().parse::<u16>().map(|p| p > 0).unwrap_or(false);
    }

    let Some((host, port)) = v.rsplit_once(':') else {
        return false;
    };
    if host.trim().is_empty() {
        return false;
    }
    port.trim().parse::<u16>().map(|p| p > 0).unwrap_or(false)
}

fn is_valid_repo_slug(value: &str) -> bool {
    let mut parts = value.trim().split('/');
    let Some(owner) = parts.next() else {
        return false;
    };
    let Some(name) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if owner.is_empty() || name.is_empty() {
        return false;
    }
    let valid = |seg: &str| {
        seg.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    valid(owner) && valid(name)
}

fn normalize_domain(value: &str) -> Option<String> {
    let v = value.trim().trim_start_matches("*.").trim_end_matches('.');
    if v.is_empty() || !v.contains('.') {
        return None;
    }
    if v.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    {
        Some(v.to_ascii_lowercase())
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadConfig {
    pub initial_concurrency: usize,
    pub max_concurrency: usize,
    pub chunk_size_mb: usize,
    pub max_retries: usize,
    pub adaptive_enabled: bool,
    pub adaptive_threshold_mbps: f64,
    pub request_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub max_idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    /// Best-effort protection for problematic servers during high-concurrency HTTP/2 downloads.
    ///
    /// Reqwest does not currently expose hyper's `http2_max_concurrent_reset_streams` knob. In this build,
    /// the value is used to limit internal probe operations that may cause stream resets.
    #[serde(default)]
    pub http2_max_concurrent_reset_streams: Option<usize>,
    /// Optional integrity verification for downloads.
    ///
    /// Supported values:
    /// - "sha256:<64-hex>" to verify against an explicit digest
    /// - "auto" to read expected digest from a sibling "<file>.sha256" file
    #[serde(default)]
    pub verify_hash: Option<String>,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            initial_concurrency: 4,
            max_concurrency: 16,
            chunk_size_mb: 4,
            max_retries: 2,
            adaptive_enabled: true,
            adaptive_threshold_mbps: 25.0,
            request_timeout_secs: 30,
            connect_timeout_secs: 10,
            max_idle_per_host: 16,
            pool_idle_timeout_secs: 30,
            http2_max_concurrent_reset_streams: None,
            verify_hash: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCensorshipConfig {
    pub doh_enabled: bool,
    pub doh_providers: Vec<String>,
    pub doh_cache_ttl_secs: u64,
    #[serde(default)]
    pub bootstrap_ips: Vec<IpAddr>,
    #[serde(default)]
    pub dnssec_enabled: bool,
    #[serde(default = "default_dns_cache_size")]
    pub dns_cache_size: usize,
    #[serde(default = "default_dns_timeout_secs")]
    pub dns_query_timeout_secs: u64,
    #[serde(default = "default_dns_attempts")]
    pub dns_attempts: usize,
    #[serde(default)]
    pub dot_enabled: bool,
    #[serde(default)]
    pub dot_servers: Vec<String>,
    #[serde(default = "default_dot_sni")]
    pub dot_sni: String,
    #[serde(default)]
    pub doq_enabled: bool,
    #[serde(default)]
    pub doq_servers: Vec<String>,
    #[serde(default = "default_doq_sni")]
    pub doq_sni: String,
    #[serde(default)]
    pub dns_fallback_chain: Vec<DnsResolverKind>,
    #[serde(default)]
    pub system_dns_enabled: bool,
    /// Preferred ECH behavior.
    ///
    /// If set, it enables ECH and overrides legacy `ech_enabled`.
    #[serde(default)]
    pub ech_mode: Option<EchMode>,
    /// Legacy switch for enabling ECH GREASE (placeholder). Prefer `ech_mode`.
    #[serde(default)]
    pub ech_enabled: bool,
    pub domain_fronting_enabled: bool,
    #[serde(default)]
    pub domain_fronting_rules: Vec<DomainFrontingRule>,
    /// Cache TTL for dynamic fronting probe results.
    #[serde(default = "default_fronting_probe_ttl_secs")]
    pub fronting_probe_ttl_secs: u64,
    /// Timeout for the dynamic fronting availability probe (HEAD request).
    #[serde(default = "default_fronting_probe_timeout_secs")]
    pub fronting_probe_timeout_secs: u64,
    pub tls_randomization_enabled: bool,
}

impl Default for AntiCensorshipConfig {
    fn default() -> Self {
        Self {
            doh_enabled: true,
            doh_providers: vec![
                "adguard".to_owned(),
                "google".to_owned(),
                "quad9".to_owned(),
            ],
            doh_cache_ttl_secs: 300,
            bootstrap_ips: Vec::new(),
            dnssec_enabled: true,
            dns_cache_size: default_dns_cache_size(),
            dns_query_timeout_secs: default_dns_timeout_secs(),
            dns_attempts: default_dns_attempts(),
            dot_enabled: false,
            dot_servers: vec![
                "94.140.14.14:853".to_owned(),
                "94.140.15.15:853".to_owned(),
                "8.8.8.8:853".to_owned(),
                "8.8.4.4:853".to_owned(),
            ],
            dot_sni: default_dot_sni(),
            doq_enabled: false,
            doq_servers: vec!["94.140.14.14:784".to_owned(), "94.140.15.15:784".to_owned()],
            doq_sni: default_doq_sni(),
            dns_fallback_chain: vec![DnsResolverKind::Doh, DnsResolverKind::System],
            system_dns_enabled: true,
            ech_mode: None,
            ech_enabled: false,
            domain_fronting_enabled: false,
            domain_fronting_rules: Vec::new(),
            fronting_probe_ttl_secs: default_fronting_probe_ttl_secs(),
            fronting_probe_timeout_secs: default_fronting_probe_timeout_secs(),
            tls_randomization_enabled: true,
        }
    }
}

fn default_fronting_probe_ttl_secs() -> u64 {
    600
}

fn default_fronting_probe_timeout_secs() -> u64 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EchMode {
    Grease,
    Real,
    Auto,
}

impl AntiCensorshipConfig {
    /// Returns the effective ECH behavior.
    ///
    /// - If `ech_mode` is set, it enables ECH and selects the specified mode.
    /// - Else if legacy `ech_enabled=true`, it enables ECH GREASE.
    pub fn effective_ech_mode(&self) -> Option<EchMode> {
        if let Some(m) = &self.ech_mode {
            return Some(m.clone());
        }
        if self.ech_enabled {
            return Some(EchMode::Grease);
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum DnsResolverKind {
    Doh,
    Dot,
    Doq,
    System,
}

fn default_dns_cache_size() -> usize {
    4096
}

fn default_dns_timeout_secs() -> u64 {
    5
}

fn default_dns_attempts() -> usize {
    2
}

fn default_dot_sni() -> String {
    "dns.adguard-dns.com".to_owned()
}

