use crate::adblock::filter_rule::DomainConstraint;

/// A CSS cosmetic rule parsed from adblock filter list syntax.
///
/// Cosmetic rules inject CSS to hide page elements matching `selector`.
/// They use `##` (blocking) or `#@#` (exception) syntax and may be
/// restricted to specific domains.
///
/// Example: `example.com##.ad-banner` hides all `.ad-banner` elements
/// on `example.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmeticRule {
    /// CSS selector string to inject (e.g. `.ad-banner`, `#sidebar-ad`).
    pub selector: String,
    /// `true` for exception cosmetic rules (`#@#`).
    pub is_exception: bool,
    /// Optional domain restrictions.
    pub domains: Option<DomainConstraint>,
    /// Original raw filter text.
    pub raw: String,
}

/// A scriptlet injection rule parsed from adblock filter list syntax.
///
/// Scriptlet rules inject small JavaScript snippets to neutralise
/// anti-adblock scripts or prevent tracking.  Uses AdGuard
/// `#%#//scriptlet(name, arg1, ...)` syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptletRule {
    /// Scriptlet function name (e.g. `abort-on-property-read`).
    pub name: String,
    /// Positional arguments passed to the scriptlet.
    pub args: Vec<String>,
    /// Optional domain restrictions.
    pub domains: Option<DomainConstraint>,
    /// Original raw filter text.
    pub raw: String,
}

/// Applies matching cosmetic rules to produce CSS injection content.
///
/// Returns a combined CSS string that should be injected into the page
/// `<head>` as a `<style>` block.  Exception rules cancel out blocking
/// rules for the same selector.
pub fn build_cosmetic_css(rules: &[CosmeticRule], page_domain: &str) -> String {
    let mut selectors: Vec<&str> = Vec::new();
    let mut exceptions: Vec<&str> = Vec::new();

    for rule in rules {
        let domain_ok = rule
            .domains
            .as_ref()
            .is_none_or(|dc| dc.matches(page_domain));
        if !domain_ok {
            continue;
        }
        if rule.is_exception {
            exceptions.push(&rule.selector);
        } else {
            selectors.push(&rule.selector);
        }
    }

    // Remove selectors that have a matching exception.
    selectors.retain(|sel| !exceptions.contains(sel));

    if selectors.is_empty() {
        return String::new();
    }

    // Produce a single CSS rule that hides all matched selectors.
    let joined = selectors.join(",\n");
    format!("{joined} {{ display: none !important; }}")
}

#[cfg(test)]
mod cosmetic_tests {
    use super::*;

    #[test]
    fn build_css_hides_matching_selectors() {
        let rules = vec![
            CosmeticRule {
                selector: ".ad-banner".to_owned(),
                is_exception: false,
                domains: None,
                raw: "##.ad-banner".to_owned(),
            },
            CosmeticRule {
                selector: "#sidebar-ad".to_owned(),
                is_exception: false,
                domains: None,
                raw: "###sidebar-ad".to_owned(),
            },
        ];
        let css = build_cosmetic_css(&rules, "example.com");
        assert!(css.contains(".ad-banner"));
        assert!(css.contains("#sidebar-ad"));
        assert!(css.contains("display: none !important"));
    }

    #[test]
    fn exception_cancels_blocker() {
        let rules = vec![
            CosmeticRule {
                selector: ".ad".to_owned(),
                is_exception: false,
                domains: None,
                raw: "##.ad".to_owned(),
            },
            CosmeticRule {
                selector: ".ad".to_owned(),
                is_exception: true,
                domains: None,
                raw: "#@#.ad".to_owned(),
            },
        ];
        let css = build_cosmetic_css(&rules, "example.com");
        assert!(css.is_empty());
    }

    #[test]
    fn domain_restriction_applies() {
        let rules = vec![CosmeticRule {
            selector: ".promo".to_owned(),
            is_exception: false,
            domains: Some(DomainConstraint {
                include: vec!["example.com".to_owned()],
                exclude: Vec::new(),
            }),
            raw: "example.com##.promo".to_owned(),
        }];
        assert!(!build_cosmetic_css(&rules, "example.com").is_empty());
        assert!(build_cosmetic_css(&rules, "other.org").is_empty());
    }
}
