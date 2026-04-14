//! Force HTTP to HTTPS upgrade at the proxy level.
//!
//! Rewrites `http://` URLs to `https://` before the request leaves the engine,
//! with a configurable exclusion list for domains that break on HTTPS.

use serde::{Deserialize, Serialize};

/// Configuration for automatic HTTP-to-HTTPS upgrading.
///
/// When enabled, all `http://` requests are rewritten to `https://`
/// unless the target domain appears in the exclusion list.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HttpsUpgradeConfig {
    /// Master switch — when `false`, no URLs are upgraded.
    pub enabled: bool,
    /// Domains excluded from HTTPS upgrade (e.g. internal/legacy sites).
    pub exclude_domains: Vec<String>,
    /// When `true`, excluding `example.com` also excludes `sub.example.com`.
    pub include_subdomains: bool,
}

/// Outcome of evaluating a URL for HTTPS upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeDecision {
    /// URL was upgraded from `http://` to `https://`.
    Upgraded,
    /// URL was already `https://` — no action needed.
    AlreadyHttps,
    /// URL's domain is in the exclusion list — upgrade skipped.
    Excluded,
    /// URL is not an HTTP(S) URL (e.g. `ftp://`, empty) — not applicable.
    NotApplicable,
}

/// Determine whether a URL should be upgraded to HTTPS.
///
/// Does not mutate the URL; call [`upgrade_url`] to obtain the rewritten string.
pub fn should_upgrade(url: &str, cfg: &HttpsUpgradeConfig) -> UpgradeDecision {
    if !cfg.enabled {
        return UpgradeDecision::NotApplicable;
    }

    let trimmed = url.trim();

    if trimmed.starts_with("https://") || trimmed.starts_with("HTTPS://") {
        return UpgradeDecision::AlreadyHttps;
    }

    if !trimmed.starts_with("http://") && !trimmed.starts_with("HTTP://") {
        return UpgradeDecision::NotApplicable;
    }

    let host = extract_host(trimmed);
    if host.is_empty() {
        return UpgradeDecision::NotApplicable;
    }

    if is_excluded(&host, cfg) {
        return UpgradeDecision::Excluded;
    }

    UpgradeDecision::Upgraded
}

/// Rewrite an `http://` URL to `https://`, preserving the path, query, and fragment.
///
/// Returns `None` if the URL does not start with `http://`.
pub fn upgrade_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("HTTP://"))
        .map(|rest| format!("https://{rest}"))
}

/// Extract the host portion from an HTTP URL for exclusion matching.
fn extract_host(url: &str) -> String {
    let without_scheme = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("HTTP://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("HTTPS://") {
        rest
    } else {
        return String::new();
    };

    // Take everything before the first `/`, `?`, or `#`.
    let host_port = without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("");

    // Strip port number.
    let host = if let Some(bracket_end) = host_port.find(']') {
        // IPv6: [::1]:8080
        &host_port[..=bracket_end]
    } else if let Some(colon) = host_port.rfind(':') {
        &host_port[..colon]
    } else {
        host_port
    };

    host.to_ascii_lowercase()
}

/// Check whether `host` appears in the exclusion list, respecting `include_subdomains`.
fn is_excluded(host: &str, cfg: &HttpsUpgradeConfig) -> bool {
    let host_lower = host.to_ascii_lowercase();

    for excluded in &cfg.exclude_domains {
        let ex = excluded.trim().to_ascii_lowercase();
        if ex.is_empty() {
            continue;
        }

        if host_lower == ex {
            return true;
        }

        if cfg.include_subdomains && host_lower.ends_with(&format!(".{ex}")) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod https_upgrade_tests {
    use super::*;

    fn basic_config() -> HttpsUpgradeConfig {
        HttpsUpgradeConfig {
            enabled: true,
            exclude_domains: vec!["legacy.internal.corp".to_owned()],
            include_subdomains: true,
        }
    }

    #[test]
    fn disabled_returns_not_applicable() {
        let cfg = HttpsUpgradeConfig::default();
        assert_eq!(
            should_upgrade("http://example.com", &cfg),
            UpgradeDecision::NotApplicable,
        );
    }

    #[test]
    fn already_https() {
        let cfg = basic_config();
        assert_eq!(
            should_upgrade("https://example.com/path", &cfg),
            UpgradeDecision::AlreadyHttps,
        );
    }

    #[test]
    fn upgrades_http() {
        let cfg = basic_config();
        assert_eq!(
            should_upgrade("http://example.com/path?q=1", &cfg),
            UpgradeDecision::Upgraded,
        );
    }

    #[test]
    fn excluded_domain_not_upgraded() {
        let cfg = basic_config();
        assert_eq!(
            should_upgrade("http://legacy.internal.corp/api", &cfg),
            UpgradeDecision::Excluded,
        );
    }

    #[test]
    fn excluded_subdomain_when_enabled() {
        let cfg = basic_config();
        assert_eq!(
            should_upgrade("http://sub.legacy.internal.corp/api", &cfg),
            UpgradeDecision::Excluded,
        );
    }

    #[test]
    fn excluded_subdomain_when_disabled() {
        let cfg = HttpsUpgradeConfig {
            enabled: true,
            exclude_domains: vec!["legacy.internal.corp".to_owned()],
            include_subdomains: false,
        };
        assert_eq!(
            should_upgrade("http://sub.legacy.internal.corp/api", &cfg),
            UpgradeDecision::Upgraded,
        );
    }

    #[test]
    fn non_http_url_not_applicable() {
        let cfg = basic_config();
        assert_eq!(
            should_upgrade("ftp://files.example.com", &cfg),
            UpgradeDecision::NotApplicable,
        );
    }

    #[test]
    fn upgrade_url_rewrites_scheme() {
        assert_eq!(
            upgrade_url("http://example.com/path?q=1#frag"),
            Some("https://example.com/path?q=1#frag".to_owned()),
        );
    }

    #[test]
    fn upgrade_url_uppercase() {
        assert_eq!(
            upgrade_url("HTTP://EXAMPLE.COM"),
            Some("https://EXAMPLE.COM".to_owned()),
        );
    }

    #[test]
    fn upgrade_url_returns_none_for_https() {
        assert_eq!(upgrade_url("https://example.com"), None);
    }

    #[test]
    fn upgrade_url_returns_none_for_non_http() {
        assert_eq!(upgrade_url("ftp://example.com"), None);
    }

    #[test]
    fn extract_host_strips_port() {
        assert_eq!(extract_host("http://example.com:8080/path"), "example.com");
    }

    #[test]
    fn extract_host_ipv6() {
        assert_eq!(extract_host("http://[::1]:8080/path"), "[::1]");
    }
}
