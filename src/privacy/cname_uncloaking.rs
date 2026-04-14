//! CNAME-based first-party tracker detection.
//!
//! Some trackers disguise themselves as first-party by using CNAME records
//! that resolve a subdomain of the visited site to a tracker-owned domain.
//! This module detects such CNAME cloaking by resolving DNS CNAME chains
//! and matching against known tracker suffixes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};

/// Configuration for CNAME uncloaking.
///
/// When enabled, the engine resolves CNAME records for request domains
/// and checks whether the canonical name points to a known tracker.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CnameUncloakingConfig {
    /// Master switch — when `false`, no CNAME resolution is performed.
    pub enabled: bool,
    /// Additional known CNAME tracker entries beyond the built-in list.
    pub known_cname_trackers: Vec<CnameTrackerEntry>,
}

/// A mapping from a CNAME suffix to the tracker company that operates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnameTrackerEntry {
    /// The CNAME suffix to match (e.g. `"adobedc.net"`).
    pub cname_suffix: String,
    /// Human-readable name of the tracker company (e.g. `"Adobe"`).
    pub tracker_company: String,
}

/// Built-in CNAME tracker suffix database.
///
/// Each entry maps a DNS suffix used by known CNAME cloaking services
/// to the company operating the tracker infrastructure.
const BUILTIN_CNAME_TRACKERS: &[(&str, &str)] = &[
    ("adobedc.net", "Adobe"),
    ("omtrdc.net", "Adobe"),
    ("at-o.net", "AT Internet"),
    ("keycdn.com", "KeyCDN"),
    ("trafficmanager.net", "Microsoft"),
    ("azurewebsites.net", "Microsoft"),
    ("eulerian.net", "Eulerian"),
    ("dnspod.net", "Tencent"),
    ("snigelweb.com", "Snigel"),
    ("parastorage.com", "Wix"),
];

/// TTL for cached CNAME resolution results (10 minutes).
const CNAME_CACHE_TTL: Duration = Duration::from_secs(600);

/// Cached CNAME resolution result with expiry time.
struct CnameEntry {
    /// The resolved canonical name, or `None` if resolution failed/returned nothing.
    cname: Option<String>,
    /// When this cache entry expires.
    expires_at: Instant,
}

/// Thread-safe CNAME resolution cache with TTL-based expiry.
///
/// Stores resolved CNAME results keyed by the queried domain name.
/// Entries are lazily evicted when accessed after their TTL expires.
pub struct CnameCache {
    /// Map from queried domain -> cached CNAME result.
    entries: Arc<DashMap<String, CnameEntry>>,
}

impl Default for CnameCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CnameCache {
    /// Create a new empty CNAME cache.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
        }
    }

    /// Look up a cached CNAME for `domain`, returning `None` if absent or expired.
    pub fn get(&self, domain: &str) -> Option<Option<String>> {
        let key = domain.to_ascii_lowercase();
        if let Some(entry) = self.entries.get(&key) {
            if Instant::now() < entry.expires_at {
                return Some(entry.cname.clone());
            }
            drop(entry);
            self.entries.remove(&key);
        }
        None
    }

    /// Insert a CNAME resolution result into the cache.
    pub fn insert(&self, domain: &str, cname: Option<String>) {
        let key = domain.to_ascii_lowercase();
        self.entries.insert(
            key,
            CnameEntry {
                cname,
                expires_at: Instant::now() + CNAME_CACHE_TTL,
            },
        );
    }

    /// Remove expired entries from the cache.
    ///
    /// Call periodically (e.g. every few minutes) to bound memory usage.
    pub fn prune_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, v| v.expires_at > now);
    }

    /// Return the number of entries currently in the cache.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache contains no entries.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Check whether a resolved CNAME matches a known tracker suffix.
///
/// Returns the tracker company name if the CNAME matches a built-in or
/// user-configured tracker suffix, or `None` if it does not match.
pub fn is_cname_tracker<'a>(cname: &str, cfg: &'a CnameUncloakingConfig) -> Option<&'a str> {
    if !cfg.enabled {
        return None;
    }

    let cname_lower = cname.to_ascii_lowercase();

    for &(suffix, company) in BUILTIN_CNAME_TRACKERS {
        if cname_lower == suffix || cname_lower.ends_with(&format!(".{suffix}")) {
            return Some(company);
        }
    }

    for entry in &cfg.known_cname_trackers {
        let suffix = entry.cname_suffix.to_ascii_lowercase();
        if cname_lower == suffix || cname_lower.ends_with(&format!(".{suffix}")) {
            return Some(&entry.tracker_company);
        }
    }

    None
}

/// Resolve the CNAME for `domain` and check whether it points to a known tracker.
///
/// Uses the provided `resolver` function to perform DNS CNAME lookups.
/// Results are cached in `cache` to avoid repeated DNS queries.
///
/// Returns the tracker company name if the resolved CNAME matches, or `None`.
pub async fn resolve_and_check(
    domain: &str,
    resolver: &dyn Fn(&str) -> BoxFuture<'_, Option<String>>,
    cfg: &CnameUncloakingConfig,
    cache: &CnameCache,
) -> Option<String> {
    if !cfg.enabled {
        return None;
    }

    // Check cache first.
    if let Some(cached_cname) = cache.get(domain) {
        return match cached_cname {
            Some(cname) => is_cname_tracker(&cname, cfg).map(|c| c.to_owned()),
            None => None,
        };
    }

    // Resolve CNAME.
    let cname = resolver(domain).await;
    cache.insert(domain, cname.clone());

    match cname {
        Some(resolved) => is_cname_tracker(&resolved, cfg).map(|c| c.to_owned()),
        None => None,
    }
}

#[cfg(test)]
mod cname_uncloaking_tests {
    use super::*;

    fn enabled_config() -> CnameUncloakingConfig {
        CnameUncloakingConfig {
            enabled: true,
            known_cname_trackers: vec![CnameTrackerEntry {
                cname_suffix: "custom-tracker.io".to_owned(),
                tracker_company: "CustomCo".to_owned(),
            }],
        }
    }

    #[test]
    fn disabled_config_returns_none() {
        let cfg = CnameUncloakingConfig::default();
        assert!(is_cname_tracker("tracking.adobedc.net", &cfg).is_none());
    }

    #[test]
    fn detects_builtin_adobe_tracker() {
        let cfg = enabled_config();
        assert_eq!(is_cname_tracker("metrics.adobedc.net", &cfg), Some("Adobe"),);
    }

    #[test]
    fn detects_builtin_omtrdc() {
        let cfg = enabled_config();
        assert_eq!(
            is_cname_tracker("mysite.sc.omtrdc.net", &cfg),
            Some("Adobe"),
        );
    }

    #[test]
    fn detects_at_internet() {
        let cfg = enabled_config();
        assert_eq!(is_cname_tracker("xiti.at-o.net", &cfg), Some("AT Internet"),);
    }

    #[test]
    fn detects_microsoft_traffic_manager() {
        let cfg = enabled_config();
        assert_eq!(
            is_cname_tracker("app.trafficmanager.net", &cfg),
            Some("Microsoft"),
        );
    }

    #[test]
    fn detects_custom_tracker() {
        let cfg = enabled_config();
        assert_eq!(
            is_cname_tracker("cdn.custom-tracker.io", &cfg),
            Some("CustomCo"),
        );
    }

    #[test]
    fn exact_suffix_match() {
        let cfg = enabled_config();
        assert_eq!(is_cname_tracker("adobedc.net", &cfg), Some("Adobe"));
    }

    #[test]
    fn no_match_for_safe_domain() {
        let cfg = enabled_config();
        assert!(is_cname_tracker("cdn.cloudflare.com", &cfg).is_none());
    }

    #[test]
    fn no_partial_suffix_match() {
        let cfg = enabled_config();
        // "notadobedc.net" should NOT match "adobedc.net".
        assert!(is_cname_tracker("notadobedc.net", &cfg).is_none());
    }

    #[test]
    fn cache_stores_and_retrieves() {
        let cache = CnameCache::new();
        cache.insert("example.com", Some("cdn.adobedc.net".to_owned()));

        let result = cache.get("example.com");
        assert_eq!(result, Some(Some("cdn.adobedc.net".to_owned())));
    }

    #[test]
    fn cache_stores_none_result() {
        let cache = CnameCache::new();
        cache.insert("safe.com", None);

        let result = cache.get("safe.com");
        assert_eq!(result, Some(None));
    }

    #[test]
    fn cache_miss_returns_none() {
        let cache = CnameCache::new();
        assert!(cache.get("unknown.com").is_none());
    }

    #[test]
    fn cache_prune_removes_expired() {
        let cache = CnameCache::new();
        cache.entries.insert(
            "old.com".to_owned(),
            CnameEntry {
                cname: Some("tracker.adobedc.net".to_owned()),
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        cache.insert("fresh.com", Some("cdn.example.com".to_owned()));

        assert_eq!(cache.len(), 2);
        cache.prune_expired();
        assert_eq!(cache.len(), 1);
        assert!(cache.get("old.com").is_none());
        assert!(cache.get("fresh.com").is_some());
    }

    #[tokio::test]
    async fn resolve_and_check_with_tracker_cname() {
        let cfg = enabled_config();
        let cache = CnameCache::new();

        let result = resolve_and_check(
            "track.mysite.com",
            &|_domain: &str| Box::pin(async { Some("metrics.adobedc.net".to_owned()) }),
            &cfg,
            &cache,
        )
        .await;

        assert_eq!(result, Some("Adobe".to_owned()));

        // Second call should hit the cache.
        let cached = resolve_and_check(
            "track.mysite.com",
            &|_domain: &str| Box::pin(async { panic!("should not be called — cached") }),
            &cfg,
            &cache,
        )
        .await;
        assert_eq!(cached, Some("Adobe".to_owned()));
    }

    #[tokio::test]
    async fn resolve_and_check_with_safe_cname() {
        let cfg = enabled_config();
        let cache = CnameCache::new();

        let result = resolve_and_check(
            "cdn.mysite.com",
            &|_domain: &str| Box::pin(async { Some("cdn.cloudflare.com".to_owned()) }),
            &cfg,
            &cache,
        )
        .await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_and_check_no_cname() {
        let cfg = enabled_config();
        let cache = CnameCache::new();

        let result = resolve_and_check(
            "plain.mysite.com",
            &|_domain: &str| Box::pin(async { None }),
            &cfg,
            &cache,
        )
        .await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn resolve_and_check_disabled() {
        let cfg = CnameUncloakingConfig::default();
        let cache = CnameCache::new();

        let result = resolve_and_check(
            "track.mysite.com",
            &|_domain: &str| Box::pin(async { Some("metrics.adobedc.net".to_owned()) }),
            &cfg,
            &cache,
        )
        .await;

        assert!(result.is_none());
    }
}
