pub struct EngineConfigBuilder {
    config: EngineConfig,
}

impl EngineConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: EngineConfig::default(),
        }
    }

    pub fn download(mut self, cfg: DownloadConfig) -> Self {
        self.config.download = cfg;
        self
    }

    pub fn anticensorship(mut self, cfg: AntiCensorshipConfig) -> Self {
        self.config.anticensorship = cfg;
        self
    }

    pub fn evasion(mut self, cfg: EvasionConfig) -> Self {
        self.config.evasion = cfg;
        self
    }

    pub fn privacy(mut self, cfg: PrivacyConfig) -> Self {
        self.config.privacy = cfg;
        self
    }

    pub fn proxy(mut self, cfg: ProxyConfig) -> Self {
        self.config.proxy = Some(cfg);
        self
    }

    pub fn pt(mut self, cfg: PluggableTransportConfig) -> Self {
        self.config.pt = Some(cfg);
        self
    }

    pub fn transport(mut self, cfg: TransportConfig) -> Self {
        self.config.transport = cfg;
        self
    }

    pub fn tls(mut self, cfg: TlsConfig) -> Self {
        self.config.tls = cfg;
        self
    }

    pub fn build(self) -> Result<EngineConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for EngineConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = EngineConfig::default();
        if let Err(e) = cfg.validate() {
            panic!("Default config validation failed: {e}");
        }
    }

    #[test]
    fn invalid_concurrency_fails_validation() {
        let mut cfg = EngineConfig::default();
        cfg.download.initial_concurrency = 8;
        cfg.download.max_concurrency = 2;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dns_chain_must_not_have_duplicates() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh, DnsResolverKind::Doh];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dns_chain_cannot_include_disabled_doh() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.doh_enabled = false;
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dns_chain_cannot_include_disabled_system() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.system_dns_enabled = false;
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::System];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn compat_repair_disables_empty_fronting() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.domain_fronting_enabled = true;
        cfg.anticensorship.domain_fronting_rules.clear();
        let notes = cfg.apply_compat_repairs();
        assert!(!cfg.anticensorship.domain_fronting_enabled);
        assert_eq!(notes.len(), 1);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn compat_repair_removes_disabled_dns_resolvers_from_chain() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.system_dns_enabled = false;
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh, DnsResolverKind::System];
        let notes = cfg.apply_compat_repairs();
        assert_eq!(
            cfg.anticensorship.dns_fallback_chain,
            vec![DnsResolverKind::Doh]
        );
        assert!(!notes.is_empty());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn zero_system_proxy_pac_port_fails_validation() {
        let mut cfg = EngineConfig::default();
        cfg.system_proxy.pac_port = 0;
        assert!(cfg.validate().is_err());
    }
}
