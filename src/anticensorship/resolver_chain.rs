use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{AntiCensorshipConfig, DnsResolverKind};
use crate::error::{EngineError, Result};

#[cfg(feature = "hickory-dns")]
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
#[cfg(feature = "hickory-dns")]
use hickory_resolver::name_server::TokioConnectionProvider;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::rr::{RData, RecordType};
#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::xfer::Protocol;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::TokioResolver;

#[cfg(feature = "hickory-dns")]
#[derive(Debug, Default)]
struct ResolverState {
    doh: Option<TokioResolver>,
    dot: Option<TokioResolver>,
    doq: Option<TokioResolver>,
    system: Option<TokioResolver>,
}

#[derive(Debug, Clone)]
/// DNS resolver chain used by the anti-censorship flows.
///
/// Resolution is attempted in the order configured in `dns_fallback_chain`.
/// The first resolver that returns a non-empty set of IPs wins.
pub struct ResolverChain {
    chain: Vec<DnsResolverKind>,
    cfg: AntiCensorshipConfig,
    #[cfg(feature = "hickory-dns")]
    state: std::sync::Arc<parking_lot::Mutex<ResolverState>>,
}

impl ResolverChain {
    /// Builds a resolver chain from the anti-censorship configuration.
    pub fn from_config(cfg: &AntiCensorshipConfig) -> Result<Self> {
        Ok(Self {
            chain: cfg.dns_fallback_chain.clone(),
            cfg: cfg.clone(),
            #[cfg(feature = "hickory-dns")]
            state: std::sync::Arc::new(parking_lot::Mutex::new(ResolverState::default())),
        })
    }

    /// Resolves `domain` to a set of IP addresses.
    ///
    /// If `domain` is an IP literal, it is returned as-is without any network I/O.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        // Privacy guardrail: never race System DNS against encrypted resolvers.
        // Otherwise System often wins first and leaks the query to the ISP.
        if self.cfg.dns_parallel_racing && self.chain.len() > 1 && !self.parallel_race_leaks_dns() {
            return self.resolve_parallel(domain).await;
        }

        let mut last_err: Option<EngineError> = None;
        for kind in &self.chain {
            match self.resolve_kind(kind, domain).await {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => {
                    last_err = Some(EngineError::Internal(format!(
                        "{} returned no addresses for '{domain}'",
                        kind_name(kind)
                    )));
                }
                Err(e) => last_err = Some(e),
            };
        }

        match last_err {
            Some(e) => Err(e),
            None => Err(EngineError::Config(
                "dns_fallback_chain is empty: no resolvers to try".to_owned(),
            )),
        }
    }

    fn parallel_race_leaks_dns(&self) -> bool {
        let has_system = self
            .chain
            .iter()
            .any(|k| matches!(k, DnsResolverKind::System));
        let has_encrypted = self
            .chain
            .iter()
            .any(|k| matches!(k, DnsResolverKind::Doh | DnsResolverKind::Dot | DnsResolverKind::Doq));
        has_system && has_encrypted
    }

    async fn resolve_parallel(&self, domain: &str) -> Result<Vec<IpAddr>> {
        use tokio::task::JoinSet;
        use tokio::time::{Duration, Instant};
        const DNS_PARALLEL_COLLECT_WINDOW_MS: u64 = 250;
        let mut set = JoinSet::new();

        for kind in &self.chain {
            let self_clone = self.clone();
            let kind = kind.clone();
            let domain = domain.to_owned();
            set.spawn(async move {
                let res = self_clone.resolve_kind(&kind, &domain).await;
                (kind, res)
            });
        }

        let mut last_err: Option<EngineError> = None;
        let mut merged_ips: Vec<IpAddr> = Vec::new();
        let mut collect_deadline: Option<Instant> = None;

        loop {
            let joined = if let Some(deadline) = collect_deadline {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => {
                        break;
                    }
                    joined = set.join_next() => joined,
                }
            } else {
                set.join_next().await
            };

            let Some(joined) = joined else {
                break;
            };

            match joined {
                Ok((_kind, Ok(ips))) if !ips.is_empty() => {
                    merged_ips.extend(ips);
                    if collect_deadline.is_none() {
                        collect_deadline = Some(
                            Instant::now() + Duration::from_millis(DNS_PARALLEL_COLLECT_WINDOW_MS),
                        );
                    }
                }
                Ok((kind, Ok(_))) => {
                    last_err = Some(EngineError::Internal(format!(
                        "{} returned no addresses for '{domain}'",
                        kind_name(&kind)
                    )));
                }
                Ok((_, Err(e))) => last_err = Some(e),
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!("DNS race task error: {e}")));
                }
            }
        }

        if !merged_ips.is_empty() {
            set.abort_all();
            merged_ips.sort_unstable();
            merged_ips.dedup();
            return Ok(merged_ips);
        }

        Err(last_err.unwrap_or_else(|| {
            EngineError::Internal(format!("DNS parallel resolution failed for {domain}"))
        }))
    }

    /// Best-effort fetch of ECHConfigList bytes for `domain` via DNS HTTPS RR.
    ///
    /// The lookup follows the same configured resolver chain order as `resolve()`.
    /// Returns `Ok(None)` if no ECH config list was published (or no resolver succeeded).
    pub async fn lookup_ech_config_list(&self, domain: &str) -> Result<Option<Vec<u8>>> {
        #[cfg(feature = "hickory-dns")]
        {
            let domain = domain.trim().to_ascii_lowercase();
            if domain.is_empty() {
                return Err(EngineError::InvalidInput("domain is empty".to_owned()));
            }

            let mut last_err: Option<EngineError> = None;
            for kind in &self.chain {
                let res = match kind {
                    DnsResolverKind::Doh => {
                        if !self.cfg.doh_enabled {
                            Err(EngineError::Config(
                                "dns_fallback_chain contains 'doh' but doh_enabled=false"
                                    .to_owned(),
                            ))
                        } else {
                            let r = self.get_or_init_doh_resolver().await?;
                            lookup_ech_https_rr(&r, &domain).await
                        }
                    }
                    DnsResolverKind::Dot => {
                        if !self.cfg.dot_enabled {
                            Err(EngineError::Config(
                                "dns_fallback_chain contains 'dot' but dot_enabled=false"
                                    .to_owned(),
                            ))
                        } else {
                            let r = self.get_or_init_dot_resolver()?;
                            lookup_ech_https_rr(&r, &domain).await
                        }
                    }
                    DnsResolverKind::Doq => {
                        if !self.cfg.doq_enabled {
                            Err(EngineError::Config(
                                "dns_fallback_chain contains 'doq' but doq_enabled=false"
                                    .to_owned(),
                            ))
                        } else {
                            let r = self.get_or_init_doq_resolver()?;
                            lookup_ech_https_rr(&r, &domain).await
                        }
                    }
                    DnsResolverKind::System => {
                        if !self.cfg.system_dns_enabled {
                            Err(EngineError::Config(
                                "dns_fallback_chain contains 'system' but system_dns_enabled=false"
                                    .to_owned(),
                            ))
                        } else {
                            let r = self.get_or_init_system_resolver()?;
                            lookup_ech_https_rr(&r, &domain).await
                        }
                    }
                };

                match res {
                    Ok(Some(bytes)) => return Ok(Some(bytes)),
                    Ok(None) => {}
                    Err(e) => last_err = Some(e),
                }
            }

            // Best-effort: if nothing succeeded, treat as "no ECH".
            let _ = last_err;
            Ok(None)
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            let _ = domain;
            Err(EngineError::Internal(
                "ECH config lookup requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    async fn resolve_kind(&self, kind: &DnsResolverKind, domain: &str) -> Result<Vec<IpAddr>> {
        match kind {
            DnsResolverKind::Doh => self.resolve_doh(domain).await,
            DnsResolverKind::Dot => self.resolve_dot(domain).await,
            DnsResolverKind::Doq => self.resolve_doq(domain).await,
            DnsResolverKind::System => self.resolve_system(domain).await,
        }
    }

    async fn resolve_system(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.cfg.system_dns_enabled {
            return Err(EngineError::Config(
                "dns_fallback_chain contains 'system' but system_dns_enabled=false".to_owned(),
            ));
        }

        #[cfg(feature = "hickory-dns")]
        {
            let resolver = self.get_or_init_system_resolver()?;
            return lookup_ips(&resolver, domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            system_resolve(domain).await
        }
    }

    async fn resolve_doh(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.cfg.doh_enabled {
            return Err(EngineError::Config(
                "dns_fallback_chain contains 'doh' but doh_enabled=false".to_owned(),
            ));
        }

        #[cfg(feature = "hickory-dns")]
        {
            let resolver = self.get_or_init_doh_resolver().await?;
            return lookup_ips(&resolver, domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Config(
                "DoH requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    async fn resolve_dot(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.cfg.dot_enabled {
            return Err(EngineError::Config(
                "dns_fallback_chain contains 'dot' but dot_enabled=false".to_owned(),
            ));
        }

        #[cfg(feature = "hickory-dns")]
        {
            let resolver = self.get_or_init_dot_resolver()?;
            return lookup_ips(&resolver, domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Config(
                "DoT requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    async fn resolve_doq(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.cfg.doq_enabled {
            return Err(EngineError::Config(
                "dns_fallback_chain contains 'doq' but doq_enabled=false".to_owned(),
            ));
        }

        #[cfg(feature = "hickory-dns")]
        {
            let resolver = self.get_or_init_doq_resolver()?;
            return lookup_ips(&resolver, domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Config(
                "DoQ requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    #[cfg(feature = "hickory-dns")]
    fn base_opts(&self) -> ResolverOpts {
        let mut opts = ResolverOpts::default();
        opts.cache_size = self.cfg.dns_cache_size;
        opts.timeout = std::time::Duration::from_secs(self.cfg.dns_query_timeout_secs.max(1));
        opts.attempts = self.cfg.dns_attempts.max(1);
        // Hickory is built without DNSSEC validation features in this project.
        // Enabling `validate` here produces runtime warnings for every lookup.
        opts.validate = false;
        // Back-compat: reuse doh_cache_ttl_secs as a hard upper-bound for cached answers.
        // (Hickory cache is shared across all upstream protocols).
        let max_ttl = std::time::Duration::from_secs(self.cfg.doh_cache_ttl_secs.max(30));
        opts.positive_max_ttl = Some(max_ttl);
        opts.negative_max_ttl = Some(max_ttl);
        opts
    }

    #[cfg(feature = "hickory-dns")]
    fn get_or_init_system_resolver(&self) -> Result<TokioResolver> {
        if let Some(r) = self.state.lock().system.clone() {
            return Ok(r);
        }

        let mut builder = TokioResolver::builder_tokio().map_err(|e| {
            EngineError::Internal(format!("system resolver builder init failed: {e}"))
        })?;
        *builder.options_mut() = self.base_opts();
        let resolver = builder.build();
        self.state.lock().system = Some(resolver.clone());
        Ok(resolver)
    }

    #[cfg(feature = "hickory-dns")]
    async fn get_or_init_doh_resolver(&self) -> Result<TokioResolver> {
        if let Some(r) = self.state.lock().doh.clone() {
            return Ok(r);
        }

        let mut group = NameServerConfigGroup::new();
        let opts = self.base_opts();

        for provider in &self.cfg.doh_providers {
            let host = doh_host_for_provider(provider);
            if host.trim().is_empty() {
                continue;
            }

            let mut provider_bootstrap_ips = self.cfg.bootstrap_ips.clone();
            if provider_bootstrap_ips.is_empty() {
                provider_bootstrap_ips.extend(known_doh_provider_bootstrap_ips(&host));
            }
            if provider_bootstrap_ips.is_empty() {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    provider_bootstrap_ips.push(ip);
                }
            }

            if !provider_bootstrap_ips.is_empty() {
                // Prefer explicit bootstrap IPs to avoid leaking upstream resolution to system DNS.
                for ip in provider_bootstrap_ips.iter().copied() {
                    let mut ns =
                        NameServerConfig::new(std::net::SocketAddr::new(ip, 443), Protocol::Https);
                    ns.tls_dns_name = Some(host.clone());
                    // Default http_endpoint is /dns-query when None.
                    group.push(ns);
                }
                continue;
            }

            return Err(EngineError::Config(format!(
                "DoH provider '{host}' requires bootstrap_ips to avoid system DNS leak"
            )));
        }

        if group.is_empty() {
            return Err(EngineError::Config(
                "no DoH name servers configured (doh_providers empty?)".to_owned(),
            ));
        }

        let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
        let resolver = hickory_resolver::Resolver::builder_with_config(
            cfg,
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build();

        // Avoid racing initialization: if another task has already installed a resolver, reuse it.
        let mut state = self.state.lock();
        if let Some(r) = state.doh.clone() {
            return Ok(r);
        }
        state.doh = Some(resolver.clone());
        Ok(resolver)
    }

    #[cfg(feature = "hickory-dns")]
    fn get_or_init_dot_resolver(&self) -> Result<TokioResolver> {
        if let Some(r) = self.state.lock().dot.clone() {
            return Ok(r);
        }

        let mut group = NameServerConfigGroup::new();
        let opts = self.base_opts();
        let sni = if self.cfg.dot_sni.trim().is_empty() {
            None
        } else {
            Some(self.cfg.dot_sni.clone())
        };

        for server in &self.cfg.dot_servers {
            let sa = parse_socket_addr(server, 853)?;
            let mut ns = NameServerConfig::new(sa, Protocol::Tls);
            ns.tls_dns_name = sni.clone();
            group.push(ns);
        }
        if group.is_empty() {
            return Err(EngineError::Config(
                "dot_enabled=true but dot_servers is empty".to_owned(),
            ));
        }

        let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
        let resolver = hickory_resolver::Resolver::builder_with_config(
            cfg,
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build();
        let mut state = self.state.lock();
        if let Some(r) = state.dot.clone() {
            return Ok(r);
        }
        state.dot = Some(resolver.clone());
        Ok(resolver)
    }

    #[cfg(feature = "hickory-dns")]
    fn get_or_init_doq_resolver(&self) -> Result<TokioResolver> {
        if let Some(r) = self.state.lock().doq.clone() {
            return Ok(r);
        }

        let mut group = NameServerConfigGroup::new();
        let opts = self.base_opts();
        let sni = if self.cfg.doq_sni.trim().is_empty() {
            None
        } else {
            Some(self.cfg.doq_sni.clone())
        };

        for server in &self.cfg.doq_servers {
            let sa = parse_socket_addr(server, 784)?;
            let mut ns = NameServerConfig::new(sa, Protocol::Quic);
            ns.tls_dns_name = sni.clone();
            group.push(ns);
        }
        if group.is_empty() {
            return Err(EngineError::Config(
                "doq_enabled=true but doq_servers is empty".to_owned(),
            ));
        }

        let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
        let resolver = hickory_resolver::Resolver::builder_with_config(
            cfg,
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build();
        let mut state = self.state.lock();
        if let Some(r) = state.doq.clone() {
            return Ok(r);
        }
        state.doq = Some(resolver.clone());
        Ok(resolver)
    }
}

#[cfg(feature = "hickory-dns")]
async fn lookup_ips(resolver: &TokioResolver, domain: &str) -> Result<Vec<IpAddr>> {
    let lookup = resolver
        .lookup_ip(domain)
        .await
        .map_err(|e| EngineError::Internal(format!("dns lookup failed for '{domain}': {e}")))?;
    let mut ips: Vec<IpAddr> = lookup.iter().collect();
    ips.sort_unstable();
    ips.dedup();
    sanitize_resolved_ips(domain, ips)
}

#[cfg(feature = "hickory-dns")]
async fn lookup_ech_https_rr(resolver: &TokioResolver, domain: &str) -> Result<Option<Vec<u8>>> {
    let lookup = resolver
        .lookup(domain, RecordType::HTTPS)
        .await
        .map_err(|e| EngineError::Internal(format!("HTTPS lookup failed for {domain}: {e}")))?;

    // Pick the first HTTPS/SVCB record that contains an ECH config list.
    // If multiple are present, prefer the lowest SvcPriority.
    let mut best: Option<(u16, Vec<u8>)> = None;
    for r in lookup.iter() {
        let RData::HTTPS(https) = r else { continue };
        let prio = https.svc_priority();
        for (_, v) in https.svc_params() {
            if let SvcParamValue::EchConfigList(ech) = v {
                let value = (prio, ech.0.clone());
                match &best {
                    None => best = Some(value),
                    Some((best_prio, _)) if prio < *best_prio => best = Some(value),
                    _ => {}
                }
            }
        }
    }

    Ok(best.map(|(_, bytes)| bytes))
}

#[cfg(not(feature = "hickory-dns"))]
async fn system_resolve(domain: &str) -> Result<Vec<IpAddr>> {
    let result = tokio::net::lookup_host((domain, 443)).await.map_err(|e| {
        EngineError::Internal(format!("system DNS lookup failed for '{domain}': {e}"))
    })?;
    let mut ips: Vec<IpAddr> = result.map(|addr| addr.ip()).collect();
    ips.sort_unstable();
    ips.dedup();
    sanitize_resolved_ips(domain, ips)
}

fn sanitize_resolved_ips(domain: &str, mut ips: Vec<IpAddr>) -> Result<Vec<IpAddr>> {
    if should_filter_poisoned_ips(domain) {
        ips.retain(|ip| !ip.is_unspecified() && !ip.is_loopback());
        if ips.is_empty() {
            return Err(EngineError::InvalidInput(format!(
                "dns resolver returned only unspecified/sinkhole IPs for '{domain}'"
            )));
        }
    }
    Ok(ips)
}

fn should_filter_poisoned_ips(domain: &str) -> bool {
    let host = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    if host == "localhost" || host.ends_with(".local") {
        return false;
    }
    true
}

#[cfg(feature = "hickory-dns")]
fn fallback_ipv4s(addrs: &[[u8; 4]]) -> Vec<IpAddr> {
    addrs
        .iter()
        .copied()
        .map(|octets| IpAddr::V4(Ipv4Addr::from(octets)))
        .collect()
}

#[cfg(feature = "hickory-dns")]
fn fallback_ipv6s(addrs: &[[u16; 8]]) -> Vec<IpAddr> {
    addrs
        .iter()
        .copied()
        .map(|segments| IpAddr::V6(Ipv6Addr::from(segments)))
        .collect()
}

#[cfg(feature = "hickory-dns")]
fn known_doh_provider_bootstrap_ips(host: &str) -> Vec<IpAddr> {
    match host.trim().to_ascii_lowercase().as_str() {
        "dns.google" => {
            let mut out = fallback_ipv4s(&[[8, 8, 8, 8], [8, 8, 4, 4]]);
            out.extend(fallback_ipv6s(&[
                [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888],
                [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844],
            ]));
            out
        }
        "cloudflare-dns.com" => {
            let mut out = fallback_ipv4s(&[[1, 1, 1, 1], [1, 0, 0, 1]]);
            out.extend(fallback_ipv6s(&[
                [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111],
                [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001],
            ]));
            out
        }
        "dns.quad9.net" => {
            let mut out = fallback_ipv4s(&[[9, 9, 9, 9], [149, 112, 112, 112]]);
            out.extend(fallback_ipv6s(&[
                [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe],
                [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009],
            ]));
            out
        }
        "dns.adguard.com" => {
            let mut out = fallback_ipv4s(&[[94, 140, 14, 14], [94, 140, 15, 15]]);
            out.extend(fallback_ipv6s(&[
                [0x2a10, 0x50c0, 0, 0, 0, 0, 0, 0x0ad1],
                [0x2a10, 0x50c0, 0, 0, 0, 0, 0, 0x0ad2],
            ]));
            out
        }
        "doh.mullvad.net" => fallback_ipv4s(&[[194, 242, 2, 2]]),
        "doh.opendns.com" => fallback_ipv4s(&[[208, 67, 222, 222], [208, 67, 220, 220]]),
        _ => Vec::new(),
    }
}

#[cfg(feature = "hickory-dns")]
fn doh_host_for_provider(provider: &str) -> String {
    let v = provider.trim();
    if v.contains("://") {
        if let Ok(url) = url::Url::parse(v) {
            if let Some(host) = url.host_str() {
                return host.to_owned();
            }
        }
        return v.to_owned();
    }

    let key = v.to_ascii_lowercase();
    match key.as_str() {
        "cloudflare"
        | "cloudflare-security"
        | "cloudflare_security"
        | "cloudflare-family"
        | "cloudflare_family" => "cloudflare-dns.com".to_owned(),
        "google" => "dns.google".to_owned(),
        "quad9" | "quad9-secured" | "quad9_secured" => "dns.quad9.net".to_owned(),
        "adguard" | "adguard-family" | "adguard_family" => "dns.adguard.com".to_owned(),
        "mullvad" | "mullvaddns" | "mullvad-dns" | "mullvad_dns" => "doh.mullvad.net".to_owned(),
        "opendns" | "opendns-family" | "opendns_family" => "doh.opendns.com".to_owned(),
        _ => v.to_owned(),
    }
}

fn kind_name(kind: &DnsResolverKind) -> &'static str {
    match kind {
        DnsResolverKind::Doh => "DoH",
        DnsResolverKind::Dot => "DoT",
        DnsResolverKind::Doq => "DoQ",
        DnsResolverKind::System => "System DNS",
    }
}

#[cfg(feature = "hickory-dns")]
fn parse_socket_addr(value: &str, default_port: u16) -> Result<std::net::SocketAddr> {
    let v = value.trim();
    if v.is_empty() {
        return Err(EngineError::Config("empty DNS server address".to_owned()));
    }
    let with_port = if v.contains(':') && v.rfind(':') != v.find(':') && !v.contains(']') {
        // Likely raw IPv6 without brackets and without port; bracket it.
        format!("[{v}]:{default_port}")
    } else if v.contains(':') && v.contains(']') {
        // [IPv6]:port or [IPv6]
        if v.contains("]:") {
            v.to_owned()
        } else {
            format!("{v}:{default_port}")
        }
    } else if v.contains(':') {
        // host:port or ipv4:port
        v.to_owned()
    } else {
        format!("{v}:{default_port}")
    };
    with_port
        .parse::<std::net::SocketAddr>()
        .map_err(|e| EngineError::Config(format!("invalid socket addr '{value}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EngineConfig;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn chain_with_only_system_resolves_localhost() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.doh_enabled = false;
        cfg.anticensorship.dot_enabled = false;
        cfg.anticensorship.doq_enabled = false;
        cfg.anticensorship.system_dns_enabled = true;
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::System];
        let chain = ResolverChain::from_config(&cfg.anticensorship).expect("build chain");
        let ips = chain.resolve("localhost").await.expect("resolve localhost");
        assert!(!ips.is_empty());
    }

    #[tokio::test]
    async fn fallback_chain_reports_last_error_when_all_resolvers_fail() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.doh_enabled = false;
        cfg.anticensorship.dot_enabled = false;
        cfg.anticensorship.doq_enabled = false;
        cfg.anticensorship.system_dns_enabled = false;
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh, DnsResolverKind::System];
        let chain = ResolverChain::from_config(&cfg.anticensorship).expect("build chain");

        let err = chain.resolve("example.com").await.expect_err("must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("system_dns_enabled=false"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn empty_chain_returns_config_error() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.dns_fallback_chain.clear();
        let chain = ResolverChain::from_config(&cfg.anticensorship).expect("build chain");

        let err = chain.resolve("example.com").await.expect_err("must fail");
        assert!(err.to_string().contains("dns_fallback_chain is empty"));
    }

    #[tokio::test]
    async fn ip_literal_bypasses_chain_and_network() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.doh_enabled = false;
        cfg.anticensorship.dot_enabled = false;
        cfg.anticensorship.doq_enabled = false;
        cfg.anticensorship.system_dns_enabled = false;
        cfg.anticensorship.dns_fallback_chain.clear();
        let chain = ResolverChain::from_config(&cfg.anticensorship).expect("build chain");

        let ips = chain.resolve("1.2.3.4").await.expect("ip literal");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn parallel_race_is_disabled_when_system_and_encrypted_mix() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.dns_fallback_chain =
            vec![DnsResolverKind::Doh, DnsResolverKind::System];
        let chain = ResolverChain::from_config(&cfg.anticensorship).expect("build chain");
        assert!(chain.parallel_race_leaks_dns());
    }

    #[cfg(feature = "hickory-dns")]
    #[test]
    fn known_doh_providers_have_ipv6_bootstrap() {
        let google = known_doh_provider_bootstrap_ips("dns.google");
        assert!(google.iter().any(IpAddr::is_ipv6));
        let cloudflare = known_doh_provider_bootstrap_ips("cloudflare-dns.com");
        assert!(cloudflare.iter().any(IpAddr::is_ipv6));
    }

    #[cfg(feature = "hickory-dns")]
    #[tokio::test]
    async fn custom_doh_without_bootstrap_fails_closed() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.doh_enabled = true;
        cfg.anticensorship.dns_parallel_racing = false;
        cfg.anticensorship.bootstrap_ips.clear();
        cfg.anticensorship.doh_providers = vec!["https://my.custom.doh.example/dns-query".into()];
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh];
        let chain = ResolverChain::from_config(&cfg.anticensorship).expect("build chain");

        let err = chain.resolve("example.com").await.expect_err("must fail closed");
        assert!(err.to_string().contains("requires bootstrap_ips"));
    }

    #[test]
    fn sanitize_resolved_ips_filters_sinkhole_for_public_domains() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(157, 240, 30, 63)),
        ];

        let sanitized = sanitize_resolved_ips("www.instagram.com", ips).expect("sanitized");
        assert_eq!(sanitized, vec![IpAddr::V4(Ipv4Addr::new(157, 240, 30, 63))]);
    }

    #[test]
    fn sanitize_resolved_ips_keeps_localhost_loopback() {
        let ips = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        let sanitized = sanitize_resolved_ips("localhost", ips).expect("localhost must pass");
        assert_eq!(sanitized, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    }
}
