//! Third-party cookie blocking at the proxy level.
//!
//! Filters `Cookie` and `Set-Cookie` headers to block third-party cookies,
//! strip known tracking cookies, and cap cookie lifetimes.

use serde::{Deserialize, Serialize};

/// Configuration for cookie filtering policy.
///
/// Applied to both outgoing `Cookie` headers and incoming `Set-Cookie`
/// headers passing through the SOCKS5 proxy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CookiePolicyConfig {
    /// Master switch — when `false`, no cookie filtering is applied.
    pub enabled: bool,
    /// Block cookies whose domain does not match the request's registrable domain.
    pub block_third_party: bool,
    /// Block cookies with names matching known tracking identifiers.
    pub block_tracking_cookies: bool,
    /// Cap cookie lifetime to this many days (rewrite `Max-Age` / `Expires`).
    pub max_cookie_lifetime_days: Option<u32>,
}

/// Outcome of evaluating a single cookie against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieDecision {
    /// Cookie was allowed through unmodified.
    Allow,
    /// Cookie was blocked because its domain is third-party.
    BlockThirdParty,
    /// Cookie was blocked because its name matches a known tracker.
    BlockTracking,
    /// Cookie lifetime was capped from `original_days` down to `capped_days`.
    LifetimeCapped {
        /// Original lifetime in days before capping.
        original_days: u32,
        /// Lifetime in days after capping.
        capped_days: u32,
    },
}

/// Well-known tracking cookie names used by major analytics/ad platforms.
const KNOWN_TRACKING_COOKIES: &[&str] = &[
    "_ga", "_gid", "_fbp", "_fbc", "__gads", "IDE", "DSID", "FLC", "AID", "TAID", "__utma",
    "__utmb", "__utmc", "__utmz", "_gcl_au",
];

/// Extract the registrable domain (eTLD+1 approximation) from a hostname.
///
/// Uses a simple two-label heuristic: `"sub.example.com"` -> `"example.com"`.
/// This is intentionally simple to avoid pulling in a full PSL dependency.
fn registrable_domain(host: &str) -> &str {
    let host = host.trim().trim_end_matches('.');
    let parts: Vec<&str> = host.rsplit('.').collect();
    if parts.len() >= 2 {
        let start = host.len() - parts[0].len() - 1 - parts[1].len();
        &host[start..]
    } else {
        host
    }
}

/// Returns `true` if `cookie_domain` is third-party relative to `request_domain`.
fn is_third_party(request_domain: &str, cookie_domain: &str) -> bool {
    let req_lower = request_domain.to_ascii_lowercase();
    let req_reg = registrable_domain(&req_lower);
    let cookie_cleaned = cookie_domain
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    let cookie_reg = registrable_domain(&cookie_cleaned);
    !req_reg.eq_ignore_ascii_case(cookie_reg)
}

/// Returns `true` if `name` matches a known tracking cookie identifier.
fn is_tracking_cookie(name: &str) -> bool {
    KNOWN_TRACKING_COOKIES
        .iter()
        .any(|&t| t.eq_ignore_ascii_case(name))
}

/// Filter outgoing `Cookie` request headers.
///
/// Removes individual cookies from `Cookie: name=val; name2=val2` headers
/// that are blocked by the policy. Returns a decision for each cookie evaluated.
pub fn filter_request_cookies(
    request_domain: &str,
    cookie_domain: &str,
    headers: &mut Vec<(String, String)>,
    cfg: &CookiePolicyConfig,
) -> Vec<CookieDecision> {
    let mut decisions = Vec::new();

    if !cfg.enabled {
        return decisions;
    }

    let mut i = 0;
    while i < headers.len() {
        if !headers[i].0.eq_ignore_ascii_case("cookie") {
            i += 1;
            continue;
        }

        let original = headers[i].1.clone();
        let mut kept_parts = Vec::new();

        for part in original.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let name = part.split('=').next().unwrap_or("").trim();

            if cfg.block_third_party && is_third_party(request_domain, cookie_domain) {
                decisions.push(CookieDecision::BlockThirdParty);
                continue;
            }

            if cfg.block_tracking_cookies && is_tracking_cookie(name) {
                decisions.push(CookieDecision::BlockTracking);
                continue;
            }

            decisions.push(CookieDecision::Allow);
            kept_parts.push(part.to_owned());
        }

        if kept_parts.is_empty() {
            headers.remove(i);
        } else {
            headers[i].1 = kept_parts.join("; ");
            i += 1;
        }
    }

    decisions
}

/// Filter incoming `Set-Cookie` response headers.
///
/// Removes or modifies `Set-Cookie` headers based on the cookie policy.
/// Returns a decision for each `Set-Cookie` header evaluated.
pub fn filter_response_cookies(
    request_domain: &str,
    headers: &mut Vec<(String, String)>,
    cfg: &CookiePolicyConfig,
) -> Vec<CookieDecision> {
    let mut decisions = Vec::new();

    if !cfg.enabled {
        return decisions;
    }

    let mut i = 0;
    while i < headers.len() {
        if !headers[i].0.eq_ignore_ascii_case("set-cookie") {
            i += 1;
            continue;
        }

        let value = headers[i].1.clone();
        let cookie_name = extract_cookie_name(&value);
        let cookie_domain = extract_set_cookie_domain(&value);

        // Third-party check.
        if cfg.block_third_party {
            let domain_to_check = cookie_domain.as_deref().unwrap_or(request_domain);
            if is_third_party(request_domain, domain_to_check) {
                decisions.push(CookieDecision::BlockThirdParty);
                headers.remove(i);
                continue;
            }
        }

        // Tracking cookie check.
        if cfg.block_tracking_cookies && is_tracking_cookie(&cookie_name) {
            decisions.push(CookieDecision::BlockTracking);
            headers.remove(i);
            continue;
        }

        // Lifetime cap.
        if let Some(max_days) = cfg.max_cookie_lifetime_days {
            if let Some(original_days) = extract_lifetime_days(&value) {
                if original_days > max_days {
                    let capped = cap_cookie_lifetime(&value, max_days);
                    headers[i].1 = capped;
                    decisions.push(CookieDecision::LifetimeCapped {
                        original_days,
                        capped_days: max_days,
                    });
                    i += 1;
                    continue;
                }
            }
        }

        decisions.push(CookieDecision::Allow);
        i += 1;
    }

    decisions
}

/// Extract the cookie name from the first `name=value` pair in a Set-Cookie header.
fn extract_cookie_name(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap_or("")
        .split('=')
        .next()
        .unwrap_or("")
        .trim()
        .to_owned()
}

/// Extract the `Domain=...` attribute from a Set-Cookie header value.
fn extract_set_cookie_domain(set_cookie: &str) -> Option<String> {
    for part in set_cookie.split(';').skip(1) {
        let part = part.trim();
        let lower = part.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("domain=") {
            let domain = val.trim().trim_start_matches('.').to_owned();
            if !domain.is_empty() {
                return Some(domain);
            }
        }
    }
    None
}

/// Extract the cookie lifetime in days from `Max-Age` (preferred) or heuristic.
///
/// Returns `None` if no `Max-Age` attribute is present.
fn extract_lifetime_days(set_cookie: &str) -> Option<u32> {
    for part in set_cookie.split(';').skip(1) {
        let part = part.trim();
        let lower = part.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("max-age=") {
            if let Ok(seconds) = val.trim().parse::<u64>() {
                return Some((seconds / 86400) as u32);
            }
        }
    }
    None
}

/// Rewrite the `Max-Age` attribute in a Set-Cookie header to cap at `max_days`.
fn cap_cookie_lifetime(set_cookie: &str, max_days: u32) -> String {
    let max_seconds = (max_days as u64) * 86400;
    let mut parts: Vec<String> = Vec::new();

    for (idx, part) in set_cookie.split(';').enumerate() {
        let trimmed = part.trim().to_ascii_lowercase();
        if idx > 0 && trimmed.starts_with("max-age=") {
            parts.push(format!(" Max-Age={max_seconds}"));
        } else if idx > 0 && trimmed.starts_with("expires=") {
            // Drop Expires when we cap Max-Age — Max-Age takes precedence per RFC 6265.
            continue;
        } else {
            parts.push(part.to_owned());
        }
    }

    parts.join(";")
}

#[cfg(test)]
mod cookie_policy_tests {
    use super::*;

    fn blocking_config() -> CookiePolicyConfig {
        CookiePolicyConfig {
            enabled: true,
            block_third_party: true,
            block_tracking_cookies: true,
            max_cookie_lifetime_days: Some(7),
        }
    }

    #[test]
    fn disabled_config_passes_everything() {
        let cfg = CookiePolicyConfig::default();
        let mut headers = vec![(
            "Set-Cookie".to_owned(),
            "_ga=GA1.2.123; Domain=.google-analytics.com; Max-Age=63072000".to_owned(),
        )];
        let decisions = filter_response_cookies("example.com", &mut headers, &cfg);
        assert!(decisions.is_empty());
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn blocks_third_party_set_cookie() {
        let cfg = blocking_config();
        let mut headers = vec![(
            "Set-Cookie".to_owned(),
            "tracker=1; Domain=.adnetwork.com; Path=/".to_owned(),
        )];
        let decisions = filter_response_cookies("example.com", &mut headers, &cfg);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0], CookieDecision::BlockThirdParty);
        assert!(headers.is_empty());
    }

    #[test]
    fn allows_first_party_set_cookie() {
        let cfg = blocking_config();
        let mut headers = vec![(
            "Set-Cookie".to_owned(),
            "session=abc; Domain=.example.com; Max-Age=3600".to_owned(),
        )];
        let decisions = filter_response_cookies("www.example.com", &mut headers, &cfg);
        assert!(decisions.iter().all(|d| matches!(
            d,
            CookieDecision::Allow | CookieDecision::LifetimeCapped { .. }
        )));
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn blocks_tracking_cookie_by_name() {
        let cfg = CookiePolicyConfig {
            enabled: true,
            block_third_party: false,
            block_tracking_cookies: true,
            max_cookie_lifetime_days: None,
        };
        let mut headers = vec![(
            "Set-Cookie".to_owned(),
            "_ga=GA1.2.123456; Path=/; Max-Age=63072000".to_owned(),
        )];
        let decisions = filter_response_cookies("example.com", &mut headers, &cfg);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0], CookieDecision::BlockTracking);
        assert!(headers.is_empty());
    }

    #[test]
    fn caps_cookie_lifetime() {
        let cfg = CookiePolicyConfig {
            enabled: true,
            block_third_party: false,
            block_tracking_cookies: false,
            max_cookie_lifetime_days: Some(7),
        };
        // 730 days = 63072000 seconds
        let mut headers = vec![(
            "Set-Cookie".to_owned(),
            "sid=abc; Max-Age=63072000; Path=/".to_owned(),
        )];
        let decisions = filter_response_cookies("example.com", &mut headers, &cfg);
        assert_eq!(decisions.len(), 1);
        assert!(matches!(
            decisions[0],
            CookieDecision::LifetimeCapped {
                original_days: 730,
                capped_days: 7,
            }
        ));
        assert!(headers[0].1.contains("Max-Age=604800"));
    }

    #[test]
    fn filter_request_blocks_third_party() {
        let cfg = blocking_config();
        let mut headers = vec![("Cookie".to_owned(), "session=abc; _ga=GA1.2.123".to_owned())];
        let decisions = filter_request_cookies("example.com", "adnetwork.com", &mut headers, &cfg);
        assert!(decisions
            .iter()
            .all(|d| matches!(d, CookieDecision::BlockThirdParty)));
        assert!(headers.is_empty());
    }

    #[test]
    fn filter_request_blocks_tracking_first_party() {
        let cfg = CookiePolicyConfig {
            enabled: true,
            block_third_party: false,
            block_tracking_cookies: true,
            max_cookie_lifetime_days: None,
        };
        let mut headers = vec![(
            "Cookie".to_owned(),
            "session=abc; _ga=GA1.2.123; _fbp=fb.1.456".to_owned(),
        )];
        let decisions = filter_request_cookies("example.com", "example.com", &mut headers, &cfg);
        let allowed = decisions
            .iter()
            .filter(|d| matches!(d, CookieDecision::Allow))
            .count();
        let blocked = decisions
            .iter()
            .filter(|d| matches!(d, CookieDecision::BlockTracking))
            .count();
        assert_eq!(allowed, 1);
        assert_eq!(blocked, 2);
        assert!(headers[0].1.contains("session=abc"));
        assert!(!headers[0].1.contains("_ga"));
    }

    #[test]
    fn registrable_domain_extraction() {
        assert_eq!(registrable_domain("www.example.com"), "example.com");
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("a.b.c.example.com"), "example.com");
        assert_eq!(registrable_domain("localhost"), "localhost");
    }

    #[test]
    fn third_party_detection() {
        assert!(is_third_party("example.com", "adnetwork.com"));
        assert!(!is_third_party("www.example.com", "example.com"));
        assert!(!is_third_party("sub.example.com", ".example.com"));
        assert!(is_third_party("example.com", "tracker.evil.com"));
    }
}
