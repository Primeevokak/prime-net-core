use tracing::info;

impl EngineConfig {
    pub fn builder() -> EngineConfigBuilder {
        EngineConfigBuilder::new()
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        if content.trim().is_empty() {
            let mut config = EngineConfig::default();
            let _ = config.apply_compat_repairs();
            config.validate()?;
            return Ok(config);
        }
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
                serde_yaml_ng::from_str(&content).map_err(|e| EngineError::Config(e.to_string()))?
            }
            _ => toml::from_str(&content)
                .or_else(|_| serde_json::from_str(&content))
                .or_else(|_| serde_yaml_ng::from_str(&content))
                .map_err(|e| EngineError::Config(e.to_string()))?,
        };
        let notes = config.apply_compat_repairs();
        for note in notes {
            info!("Config migration: {note}");
        }
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
        if self.privacy.ip_spoof.enabled {
            let ip = self.privacy.ip_spoof.spoofed_ip.trim();
            if ip.is_empty() {
                return Err(EngineError::Config("privacy.ip_spoof.spoofed_ip must not be empty when enabled".to_owned()));
            }
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err(EngineError::Config(format!("privacy.ip_spoof.spoofed_ip is not a valid IP: {ip}")));
            }
        }
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
                    if t.password.trim().len() < 8 {
                        return Err(EngineError::Config(
                            "pt.trojan.password must be at least 8 characters long".to_owned(),
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
                    if s.password.trim().len() < 8 {
                        return Err(EngineError::Config(
                            "pt.shadowsocks.password must be at least 8 characters long".to_owned(),
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
                            "pt.obfs4.cert must not be empty (required for obfs4 handshake)".to_owned(),
                        ));
                    }
                    if o.tor_bin.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.obfs4.tor_bin must not be empty".to_owned(),
                        ));
                    }
                    if o.obfs4proxy_bin.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.obfs4.obfs4proxy_bin must not be empty".to_owned(),
                        ));
                    }
                }
                PluggableTransportKind::Snowflake => {
                    let s = pt.snowflake.as_ref().ok_or_else(|| {
                        EngineError::Config("pt.kind=snowflake requires [pt].snowflake".to_owned())
                    })?;
                    if s.tor_bin.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.snowflake.tor_bin must not be empty".to_owned(),
                        ));
                    }
                    if s.snowflake_bin.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.snowflake.snowflake_bin must not be empty".to_owned(),
                        ));
                    }
                }
            }
        }
        if let Some(v) = self.evasion.tls_record_max_fragment_size {
            if v == 0 || v > 16_384 {
                return Err(EngineError::Config(
                    "evasion.tls_record_max_fragment_size must be in 1..=16384".to_owned(),
                ));
            }
        }
        if self.evasion.classifier_cache_path.trim().is_empty() {
            return Err(EngineError::Config(
                "evasion.classifier_cache_path must not be empty".to_owned(),
            ));
        }
        if let Some(v) = self.download.http2_max_concurrent_reset_streams {
            if v == 0 {
                return Err(EngineError::Config(
                    "download.http2_max_concurrent_reset_streams must be > 0".to_owned(),
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
            match kind {
                DnsResolverKind::Doh if !self.anticensorship.doh_enabled => {
                    return Err(EngineError::Config("anticensorship.dns_fallback_chain includes doh but doh_enabled=false".to_owned()));
                }
                DnsResolverKind::Dot if !self.anticensorship.dot_enabled => {
                    return Err(EngineError::Config("anticensorship.dns_fallback_chain includes dot but dot_enabled=false".to_owned()));
                }
                DnsResolverKind::Doq if !self.anticensorship.doq_enabled => {
                    return Err(EngineError::Config("anticensorship.dns_fallback_chain includes doq but doq_enabled=false".to_owned()));
                }
                DnsResolverKind::System if !self.anticensorship.system_dns_enabled => {
                    return Err(EngineError::Config("anticensorship.dns_fallback_chain includes system but system_dns_enabled=false".to_owned()));
                }
                _ => {}
            }
        }

        if self.system_proxy.pac_port == 0 {
            return Err(EngineError::Config(
                "system_proxy.pac_port must be in 1..=65535".to_owned(),
            ));
        }
        {
            let ep = self.system_proxy.socks_endpoint.trim();
            if ep.is_empty() {
                return Err(EngineError::Config(
                    "system_proxy.socks_endpoint must not be empty".to_owned(),
                ));
            }
            if ep.parse::<std::net::SocketAddr>().is_err() {
                return Err(EngineError::Config(format!(
                    "system_proxy.socks_endpoint is not a valid socket address: {ep}"
                )));
            }
        }
        if self.updater.check_interval_hours == 0 {
            return Err(EngineError::Config(
                "updater.check_interval_hours must be > 0".to_owned(),
            ));
        }
        {
            let repo = self.updater.repo.trim();
            if !repo.is_empty() {
                let parts: Vec<&str> = repo.splitn(2, '/').collect();
                let valid = parts.len() == 2
                    && !parts[0].is_empty()
                    && !parts[1].is_empty()
                    && parts[1] != "/";
                if !valid {
                    return Err(EngineError::Config(format!(
                        "updater.repo must be in 'owner/repo' format, got: {repo}"
                    )));
                }
            }
        }
        for (domain, arm) in &self.routing.domain_profiles {
            if domain.trim().is_empty() {
                return Err(EngineError::Config(
                    "routing.domain_profiles contains an empty domain key".to_owned(),
                ));
            }
            if arm.trim().is_empty() {
                return Err(EngineError::Config(format!(
                    "routing.domain_profiles[{domain}]: route arm must not be empty"
                )));
            }
            if arm != "direct" && !arm.starts_with("bypass:") {
                return Err(EngineError::Config(format!(
                    "routing.domain_profiles[{domain}]: invalid route arm '{arm}'; must be 'direct' or 'bypass:N'"
                )));
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
