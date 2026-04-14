use std::collections::HashMap;

use crate::adblock::filter_rule::{ContentTypeMask, FilterPattern, NetworkRule};

/// Content type of the resource being loaded — passed to the engine for
/// rule matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// `<script>` tags, inline scripts, JS imports.
    Script,
    /// `<img>`, CSS background-image, favicon.
    Image,
    /// `<link rel=stylesheet>`.
    Stylesheet,
    /// `<object>`, `<embed>`.
    Object,
    /// `XMLHttpRequest` / `fetch()`.
    Xmlhttprequest,
    /// `<iframe>`, `<frame>`.
    Subdocument,
    /// `@font-face`.
    Font,
    /// `<audio>`, `<video>`.
    Media,
    /// `WebSocket`.
    Websocket,
    /// `window.open` / `target=_blank`.
    Popup,
    /// Main document load.
    Document,
    /// Anything else.
    Other,
}

impl ContentType {
    /// Convert to the corresponding bitmask value.
    pub fn to_mask(self) -> ContentTypeMask {
        match self {
            Self::Script => ContentTypeMask::SCRIPT,
            Self::Image => ContentTypeMask::IMAGE,
            Self::Stylesheet => ContentTypeMask::STYLESHEET,
            Self::Object => ContentTypeMask::OBJECT,
            Self::Xmlhttprequest => ContentTypeMask::XMLHTTPREQUEST,
            Self::Subdocument => ContentTypeMask::SUBDOCUMENT,
            Self::Font => ContentTypeMask::FONT,
            Self::Media => ContentTypeMask::MEDIA,
            Self::Websocket => ContentTypeMask::WEBSOCKET,
            Self::Popup => ContentTypeMask::POPUP,
            Self::Document => ContentTypeMask::DOCUMENT,
            Self::Other => ContentTypeMask::OTHER,
        }
    }
}

/// Result of checking a URL against the filter engine.
#[derive(Debug, Clone, Default)]
pub struct FilterResult {
    /// Whether the URL should be blocked.
    pub blocked: bool,
    /// The exception rule that un-blocked this URL (if any).
    pub exception_raw: Option<String>,
    /// The blocking rule that matched (if any).
    pub matched_rule_raw: Option<String>,
    /// Redirect resource name from `$redirect` (if any).
    pub redirect: Option<String>,
    /// Query parameter to strip from the URL via `$removeparam`.
    pub removeparam: Option<String>,
}

/// Fast URL-matching engine built from a list of parsed [`NetworkRule`]s.
///
/// Internally indexes rules by domain-anchor for O(1) lookups on the hot path,
/// with fallback linear scans for wildcard/regex rules.
pub struct FilterEngine {
    /// Rules indexed by their domain-anchor (lowercase).
    domain_index: HashMap<String, Vec<NetworkRule>>,
    /// Rules that cannot be indexed by domain (wildcards, regex, plain).
    generic_rules: Vec<NetworkRule>,
    /// Total number of rules loaded.
    pub rule_count: usize,
}

impl FilterEngine {
    /// Build a new engine from a list of parsed network rules.
    pub fn new(rules: Vec<NetworkRule>) -> Self {
        let rule_count = rules.len();
        let mut domain_index: HashMap<String, Vec<NetworkRule>> = HashMap::new();
        let mut generic_rules: Vec<NetworkRule> = Vec::new();

        for rule in rules {
            match &rule.pattern {
                FilterPattern::DomainAnchor(domain) => {
                    domain_index.entry(domain.clone()).or_default().push(rule);
                }
                _ => {
                    generic_rules.push(rule);
                }
            }
        }

        Self {
            domain_index,
            generic_rules,
            rule_count,
        }
    }

    /// Check a URL against all loaded rules.
    ///
    /// `url` is the full request URL.  `source_domain` is the domain of the
    /// page that initiated the request (for `$domain` and `$third-party`
    /// checks).  `content_type` is the resource type being loaded.
    pub fn check_url(
        &self,
        url: &str,
        source_domain: &str,
        content_type: ContentType,
    ) -> FilterResult {
        let url_lower = url.to_ascii_lowercase();
        let url_host = extract_host(&url_lower);
        let ct_mask = content_type.to_mask();
        let is_third_party = !is_same_party(source_domain, url_host);

        let mut best_block: Option<&NetworkRule> = None;
        let mut best_exception: Option<&NetworkRule> = None;

        // --- Phase 1: Domain-indexed rules (fast path) ---
        let mut host = url_host.to_owned();
        loop {
            if let Some(rules) = self.domain_index.get(&host) {
                for rule in rules {
                    if !rule_matches(rule, url, url_host, ct_mask, source_domain, is_third_party) {
                        continue;
                    }
                    if rule.is_exception {
                        if best_exception.is_none()
                            || rule.options.important
                                && !best_exception.as_ref().is_some_and(|e| e.options.important)
                        {
                            best_exception = Some(rule);
                        }
                    } else if best_block.is_none()
                        || rule.options.important
                            && !best_block.as_ref().is_some_and(|b| b.options.important)
                    {
                        best_block = Some(rule);
                    }
                }
            }

            // Walk up the domain hierarchy: sub.example.com → example.com → com
            if let Some(dot) = host.find('.') {
                host = host[dot + 1..].to_owned();
            } else {
                break;
            }
        }

        // --- Phase 2: Generic (non-indexed) rules ---
        for rule in &self.generic_rules {
            if !rule_matches(rule, url, url_host, ct_mask, source_domain, is_third_party) {
                continue;
            }
            if rule.is_exception {
                if best_exception.is_none()
                    || rule.options.important
                        && !best_exception.as_ref().is_some_and(|e| e.options.important)
                {
                    best_exception = Some(rule);
                }
            } else if best_block.is_none()
                || rule.options.important
                    && !best_block.as_ref().is_some_and(|b| b.options.important)
            {
                best_block = Some(rule);
            }
        }

        // --- Decision logic ---
        // $important blocking > $important exception > regular exception > regular blocking
        let blocked = match (best_block, best_exception) {
            (Some(blk), Some(exc)) => {
                if blk.options.important && !exc.options.important {
                    true // $important block wins
                } else {
                    false // exception wins
                }
            }
            (Some(_), None) => true,
            _ => false,
        };

        let redirect = if blocked {
            best_block.and_then(|r| r.options.redirect.clone())
        } else {
            None
        };

        let removeparam = best_block
            .and_then(|r| r.options.removeparam.clone())
            .or_else(|| best_exception.and_then(|r| r.options.removeparam.clone()));

        FilterResult {
            blocked,
            exception_raw: best_exception.map(|r| r.raw.clone()),
            matched_rule_raw: best_block.map(|r| r.raw.clone()),
            redirect,
            removeparam,
        }
    }
}

/// Check if a single rule matches the given URL context.
fn rule_matches(
    rule: &NetworkRule,
    url: &str,
    url_host: &str,
    ct_mask: ContentTypeMask,
    source_domain: &str,
    is_third_party: bool,
) -> bool {
    // Content-type check.
    if !rule.options.content_type.matches(ct_mask) {
        return false;
    }

    // Third-party check.
    if let Some(tp) = rule.options.third_party {
        if tp != is_third_party {
            return false;
        }
    }

    // Domain constraint.
    if let Some(ref dc) = rule.options.domains {
        if !dc.matches(source_domain) {
            return false;
        }
    }

    // Pattern match.
    rule.pattern.matches(url, url_host)
}

/// Extract the host portion from a URL string.
fn extract_host(url: &str) -> &str {
    let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
    let before_path = after_scheme
        .find('/')
        .map(|i| &after_scheme[..i])
        .unwrap_or(after_scheme);
    before_path
        .rfind(':')
        .map(|i| &before_path[..i])
        .unwrap_or(before_path)
}

/// Check if two domains belong to the same party (same registrable domain).
fn is_same_party(domain_a: &str, domain_b: &str) -> bool {
    let a = registrable_domain(domain_a);
    let b = registrable_domain(domain_b);
    a.eq_ignore_ascii_case(b)
}

/// Simplified registrable domain extraction (last two labels).
fn registrable_domain(domain: &str) -> &str {
    let labels: Vec<&str> = domain.rsplit('.').collect();
    if labels.len() <= 2 {
        return domain;
    }
    let start = domain.len() - labels[0].len() - labels[1].len() - 1;
    &domain[start..]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod filter_engine_tests {
    use super::*;
    use crate::adblock::filter_parser::parse_filter_list;

    fn build_engine(filters: &str) -> FilterEngine {
        let result = parse_filter_list(filters);
        FilterEngine::new(result.network_rules)
    }

    #[test]
    fn blocks_domain_anchor() {
        let engine = build_engine("||ads.example.com^\n");
        let result = engine.check_url(
            "https://ads.example.com/banner.js",
            "example.com",
            ContentType::Script,
        );
        assert!(result.blocked);
    }

    #[test]
    fn exception_overrides_block() {
        let engine = build_engine("||ads.example.com^\n@@||ads.example.com^$document\n");
        let result = engine.check_url(
            "https://ads.example.com/page",
            "example.com",
            ContentType::Document,
        );
        assert!(!result.blocked);
        assert!(result.exception_raw.is_some());
    }

    #[test]
    fn important_overrides_exception() {
        let engine = build_engine("||ads.example.com^$important\n@@||ads.example.com^\n");
        let result = engine.check_url(
            "https://ads.example.com/banner.js",
            "example.com",
            ContentType::Script,
        );
        assert!(result.blocked);
    }

    #[test]
    fn third_party_filter() {
        let engine = build_engine("||tracker.com^$third-party\n");
        // Third-party request → should block.
        let r1 = engine.check_url(
            "https://tracker.com/pixel.gif",
            "example.com",
            ContentType::Image,
        );
        assert!(r1.blocked);
        // First-party request → should NOT block.
        let r2 = engine.check_url(
            "https://tracker.com/pixel.gif",
            "tracker.com",
            ContentType::Image,
        );
        assert!(!r2.blocked);
    }

    #[test]
    fn removeparam_rule() {
        let engine = build_engine("||example.com^$removeparam=utm_source\n");
        let result = engine.check_url(
            "https://example.com/page?utm_source=google",
            "example.com",
            ContentType::Document,
        );
        assert_eq!(result.removeparam.as_deref(), Some("utm_source"));
    }

    #[test]
    fn subdomain_matching() {
        let engine = build_engine("||ads.com^\n");
        let result = engine.check_url(
            "https://cdn.ads.com/thing.js",
            "example.com",
            ContentType::Script,
        );
        assert!(result.blocked);
    }

    #[test]
    fn extract_host_works() {
        assert_eq!(extract_host("https://example.com/path"), "example.com");
        assert_eq!(
            extract_host("http://sub.example.com:8080/path"),
            "sub.example.com"
        );
    }

    #[test]
    fn registrable_domain_basics() {
        assert_eq!(registrable_domain("www.example.com"), "example.com");
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("a.b.c.example.com"), "example.com");
    }
}
