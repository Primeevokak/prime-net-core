use std::collections::HashSet;

use crate::adblock::filter_rule::{FilterPattern, NetworkRule};
use crate::blocklist::DomainBloom;

/// DNS-level ad-blocking engine built from network filter rules.
///
/// Extracts pure domain-anchor rules (like `||ads.example.com^`) and builds
/// a fast bloom filter + HashSet for DNS query interception.  Respects
/// exception rules at the DNS level.
pub struct DnsInterceptor {
    /// Bloom filter for fast negative lookups (~0.1% FPR).
    bloom: DomainBloom,
    /// Exact domain set for confirmation after bloom hit.
    domains: HashSet<String>,
    /// Exception domains that must never be blocked.
    exceptions: HashSet<String>,
}

impl DnsInterceptor {
    /// Build a DNS interceptor from a set of parsed network rules.
    ///
    /// Only rules that are pure domain anchors (no wildcards, no
    /// content-type restrictions, no `$domain` constraints) are included.
    pub fn from_rules(rules: &[NetworkRule]) -> Self {
        let mut bloom = DomainBloom::new();
        let mut domains = HashSet::new();
        let mut exceptions = HashSet::new();

        for rule in rules {
            let domain = match &rule.pattern {
                FilterPattern::DomainAnchor(d) => d,
                _ => continue,
            };

            // Skip rules with content-type or domain constraints — they
            // cannot be reliably enforced at DNS level.
            if !rule.options.content_type.is_empty()
                || rule.options.domains.is_some()
                || rule.options.third_party.is_some()
            {
                continue;
            }

            if rule.is_exception {
                exceptions.insert(domain.clone());
            } else {
                bloom.insert(domain);
                domains.insert(domain.clone());
            }
        }

        Self {
            bloom,
            domains,
            exceptions,
        }
    }

    /// Check if a DNS query for `domain` should be blocked.
    ///
    /// Tests the domain and all of its parent suffixes against the rule set.
    /// Returns `true` when the domain matches a blocking rule and no
    /// exception rule exists for it.
    pub fn should_block_dns(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();

        // Fast negative check via bloom filter.
        if !self.bloom.contains_host_or_suffix(&domain) {
            return false;
        }

        // Confirm in the exact set and check exceptions.
        if self.exceptions.contains(&domain) {
            return false;
        }
        if self.domains.contains(&domain) {
            return true;
        }

        // Walk parent suffixes.
        let mut rest = domain.as_str();
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            if self.exceptions.contains(rest) {
                return false;
            }
            if self.domains.contains(rest) {
                return true;
            }
        }

        false
    }

    /// Number of blocking domains loaded.
    pub fn blocking_count(&self) -> usize {
        self.domains.len()
    }

    /// Number of exception domains loaded.
    pub fn exception_count(&self) -> usize {
        self.exceptions.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod dns_interceptor_tests {
    use super::*;
    use crate::adblock::filter_parser::parse_filter_list;

    fn build_interceptor(filters: &str) -> DnsInterceptor {
        let result = parse_filter_list(filters);
        DnsInterceptor::from_rules(&result.network_rules)
    }

    #[test]
    fn blocks_exact_domain() {
        let dns = build_interceptor("||ads.example.com^\n");
        assert!(dns.should_block_dns("ads.example.com"));
    }

    #[test]
    fn blocks_subdomain() {
        let dns = build_interceptor("||ads.com^\n");
        assert!(dns.should_block_dns("cdn.ads.com"));
        assert!(dns.should_block_dns("a.b.ads.com"));
    }

    #[test]
    fn does_not_block_unrelated() {
        let dns = build_interceptor("||ads.com^\n");
        assert!(!dns.should_block_dns("example.com"));
        assert!(!dns.should_block_dns("myads.com"));
    }

    #[test]
    fn exception_prevents_block() {
        let dns = build_interceptor("||ads.com^\n@@||ads.com^\n");
        assert!(!dns.should_block_dns("ads.com"));
    }

    #[test]
    fn skips_rules_with_options() {
        // Rules with $script or $domain should NOT be DNS-blockable.
        let dns = build_interceptor("||tracker.com^$script\n");
        assert!(!dns.should_block_dns("tracker.com"));
    }

    #[test]
    fn counts() {
        let dns = build_interceptor("||a.com^\n||b.com^\n@@||c.com^\n");
        assert_eq!(dns.blocking_count(), 2);
        assert_eq!(dns.exception_count(), 1);
    }
}
