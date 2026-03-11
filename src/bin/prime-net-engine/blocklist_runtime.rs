use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prime_net_engine_core::blocklist::{
    expand_tilde, looks_like_domain, update_blocklist, BlocklistCache, DomainBloom,
};
use prime_net_engine_core::config::BlocklistConfig;
use prime_net_engine_core::error::Result;
use tracing::{info, warn};

use crate::blocklist_builtin;

const PT_TOOLS_DOMAIN_FILE: &str = "blocked-domains.txt";
static RUNTIME_MATCHER: OnceLock<DomainMatcher> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct RuntimeBlocklistStats {
    pub enabled: bool,
    pub source: String,
    pub domains_loaded: usize,
    pub ips_loaded: usize,
    pub cache_updated: bool,
    pub pt_tools_path: Option<PathBuf>,
}

#[derive(Default)]
struct DomainMatcher {
    bloom: DomainBloom,
    ips: HashSet<String>,
}

impl DomainMatcher {
    fn from_entities(domains: &[String], ips: &[String]) -> Self {
        let mut bloom = DomainBloom::new();
        for domain in domains {
            let normalized = normalize_domain(domain);
            if !normalized.is_empty() && looks_like_domain(&normalized) {
                bloom.insert(&normalized);
            }
        }
        let mut i_set = HashSet::with_capacity(ips.len());
        for ip in ips {
            let trimmed = ip.trim();
            if !trimmed.is_empty() && trimmed.parse::<std::net::IpAddr>().is_ok() {
                i_set.insert(trimmed.to_owned());
            }
        }
        Self { bloom, ips: i_set }
    }

    fn contains_host_or_suffix(&self, host: &str) -> bool {
        let clean_host = host.trim().trim_start_matches("*.").trim_end_matches('.');
        if clean_host.is_empty() {
            return false;
        }
        // IP literal: check exact IP set
        if clean_host.parse::<std::net::IpAddr>().is_ok() {
            return self.ips.contains(clean_host);
        }
        // Domain: use bloom filter (already lowercase in 99% of browser traffic)
        if clean_host.bytes().all(|b| !b.is_ascii_uppercase()) {
            self.bloom.contains_host_or_suffix(clean_host)
        } else {
            self.bloom
                .contains_host_or_suffix(&clean_host.to_ascii_lowercase())
        }
    }
}

pub async fn initialize_runtime_blocklist(cfg: &BlocklistConfig) -> Result<RuntimeBlocklistStats> {
    if !cfg.enabled {
        let _ = RUNTIME_MATCHER.set(DomainMatcher::default());
        return Ok(RuntimeBlocklistStats {
            enabled: false,
            source: cfg.source.clone(),
            domains_loaded: 0,
            ips_loaded: 0,
            cache_updated: false,
            pt_tools_path: None,
        });
    }

    let cache_path = expand_tilde(&cfg.cache_path);
    let mut cache = BlocklistCache::status(&cache_path)?;

    // Invalidate suspiciously small cache for large known sources
    if let Some(ref c) = cache {
        if c.domains.len() < 5000 && (c.source.contains("zapret-info") || c.source.contains("z-i"))
        {
            warn!(target: "socks_cmd", domains = c.domains.len(), "cached blocklist is suspiciously small; invalidating to force full re-parse");
            cache = None;
        }
    }

    let mut cache_updated = false;

    let mut source = cfg.source.clone();
    if source.contains("zapret-info") || source.contains("z-i") {
        source = prime_net_engine_core::blocklist::DEFAULT_BLOCKLIST_SOURCE.to_owned();
    }

    if cfg.auto_update && should_refresh_cache(cache.as_ref(), cfg.update_interval_hours) {
        match update_blocklist(&source, &cache_path).await {
            Ok(updated) => {
                cache = Some(updated);
                cache_updated = true;
            }
            Err(e) => {
                warn!(
                    target: "socks_cmd",
                    error = %e,
                    source = %source,
                    cache = %cache_path.display(),
                    "failed to auto-update blocklist feed; continuing with cached domains"
                );
            }
        }
    }

    let (mut domains, mut ips) = cache
        .as_ref()
        .map(|c| (c.domains.clone(), c.ips.clone()))
        .unwrap_or_default();

    if domains.is_empty() && ips.is_empty() {
        domains = load_domains_from_pt_tools().unwrap_or_default();
    }
    domains.sort();
    domains.dedup();
    ips.sort();
    ips.dedup();

    let matcher = DomainMatcher::from_entities(&domains, &ips);
    let domains_loaded = matcher.bloom.count;
    let ips_loaded = matcher.ips.len();

    // Populate engine global bloom for routing (built from same domain list, zero extra memory)
    let mut global_bloom = DomainBloom::new();
    for domain in &domains {
        let normalized = normalize_domain(domain);
        if !normalized.is_empty() && looks_like_domain(&normalized) {
            global_bloom.insert(&normalized);
        }
    }
    let _ = prime_net_engine_core::pt::socks5_server::BLOCKLIST_DOMAINS.set(global_bloom);

    let _ = RUNTIME_MATCHER.set(matcher);

    let pt_tools_path = if domains.is_empty() {
        None
    } else {
        match sync_domains_to_pt_tools(&domains) {
            Ok(path) => path,
            Err(e) => {
                warn!(
                    target: "socks_cmd",
                    error = %e,
                    "failed to sync parsed blocked domains into pt-tools"
                );
                None
            }
        }
    };

    Ok(RuntimeBlocklistStats {
        enabled: true,
        source,
        domains_loaded,
        ips_loaded,
        cache_updated,
        pt_tools_path,
    })
}

pub fn is_bypass_domain_runtime(host: &str) -> bool {
    if blocklist_builtin::is_bypass_domain(host) {
        return true;
    }
    RUNTIME_MATCHER
        .get()
        .is_some_and(|matcher| matcher.contains_host_or_suffix(host))
}

pub fn sync_domains_to_pt_tools(domains: &[String]) -> Result<Option<PathBuf>> {
    let Some(path) = pt_tools_blocked_domains_path() else {
        return Ok(None);
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = String::new();
    for domain in domains {
        let normalized = normalize_domain(domain);
        if !normalized.is_empty() && looks_like_domain(&normalized) {
            out.push_str(&normalized);
            out.push('\n');
        }
    }
    fs::write(&path, out)?;
    Ok(Some(path))
}

fn load_domains_from_pt_tools() -> Option<Vec<String>> {
    let path = pt_tools_blocked_domains_path()?;
    let body = fs::read_to_string(path).ok()?;
    let mut out = Vec::new();
    for line in body.lines() {
        let domain = normalize_domain(line);
        if !domain.is_empty() && looks_like_domain(&domain) {
            out.push(domain);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn pt_tools_blocked_domains_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let parent = exe.parent()?;
    Some(parent.join("pt-tools").join(PT_TOOLS_DOMAIN_FILE))
}

fn normalize_domain(host: &str) -> String {
    host.trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn should_refresh_cache(cache: Option<&BlocklistCache>, interval_hours: u64) -> bool {
    let Some(cache) = cache else {
        return true;
    };
    if cache.updated_at_unix == 0 {
        return true;
    }
    let updated = UNIX_EPOCH + Duration::from_secs(cache.updated_at_unix);
    let age = SystemTime::now()
        .duration_since(updated)
        .unwrap_or_else(|_| Duration::from_secs(0));
    age > Duration::from_secs(interval_hours.saturating_mul(3600))
}

pub fn log_runtime_blocklist_stats(stats: &RuntimeBlocklistStats) {
    if !stats.enabled {
        info!(
            target: "socks_cmd",
            "blocklist feed is disabled; using built-in + adaptive classifier routes"
        );
        return;
    }
    info!(
        target: "socks_cmd",
        source = %stats.source,
        domains = stats.domains_loaded,
        ips = stats.ips_loaded,
        cache_updated = stats.cache_updated,
        pt_tools = stats.pt_tools_path.as_ref().map(|p| p.display().to_string()),
        "runtime blocklist feed loaded"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_checks_exact_and_suffix() {
        let domains = vec![
            "example.com".to_owned(),
            "*.foo.bar".to_owned(),
            "discord.gg".to_owned(),
        ];
        let ips = vec!["1.1.1.1".to_owned()];
        let matcher = DomainMatcher::from_entities(&domains, &ips);
        assert!(matcher.contains_host_or_suffix("example.com"));
        assert!(matcher.contains_host_or_suffix("api.example.com"));
        assert!(matcher.contains_host_or_suffix("a.b.foo.bar"));
        assert!(matcher.contains_host_or_suffix("gateway.discord.gg"));
        assert!(matcher.contains_host_or_suffix("1.1.1.1"));
        assert!(!matcher.contains_host_or_suffix("example.org"));
        assert!(!matcher.contains_host_or_suffix("8.8.8.8"));
    }

    #[test]
    fn normalize_domain_handles_wildcards_and_case() {
        assert_eq!(normalize_domain("*.Example.COM."), "example.com");
        assert_eq!(normalize_domain("  'Discord.GG' "), "discord.gg");
    }
}
