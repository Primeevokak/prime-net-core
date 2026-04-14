use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Content-type bitmask
// ---------------------------------------------------------------------------

/// Bitmask of HTTP content types a network rule applies to.
///
/// When no type bits are set the rule applies to all types (default behaviour
/// in EasyList/AdGuard syntax).  Individual bits can be combined with `|`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ContentTypeMask(pub u32);

impl ContentTypeMask {
    /// Script resources (`$script`).
    pub const SCRIPT: Self = Self(1 << 0);
    /// Image resources (`$image`).
    pub const IMAGE: Self = Self(1 << 1);
    /// Stylesheet resources (`$stylesheet`).
    pub const STYLESHEET: Self = Self(1 << 2);
    /// Object/embed resources (`$object`).
    pub const OBJECT: Self = Self(1 << 3);
    /// XMLHttpRequest / fetch (`$xmlhttprequest`).
    pub const XMLHTTPREQUEST: Self = Self(1 << 4);
    /// Sub-document / iframe (`$subdocument`).
    pub const SUBDOCUMENT: Self = Self(1 << 5);
    /// Web fonts (`$font`).
    pub const FONT: Self = Self(1 << 6);
    /// Audio/video media (`$media`).
    pub const MEDIA: Self = Self(1 << 7);
    /// WebSocket connections (`$websocket`).
    pub const WEBSOCKET: Self = Self(1 << 8);
    /// Popup windows (`$popup`).
    pub const POPUP: Self = Self(1 << 9);
    /// Top-level document (`$document`).
    pub const DOCUMENT: Self = Self(1 << 10);
    /// Any other resource type (`$other`).
    pub const OTHER: Self = Self(1 << 11);
    /// Matches all types (empty mask semantics).
    pub const ALL: Self = Self(0xFFFF_FFFF);
    /// No types — used as a zero value before OR-ing bits in.
    pub const NONE: Self = Self(0);

    /// Returns `true` when the mask has no bits set (matches everything).
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` when `self` contains all bits present in `other`.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if the mask matches `query` — either no bits are set
    /// (wildcard) or `query` overlaps with the set bits.
    pub fn matches(self, query: Self) -> bool {
        self.is_empty() || (self.0 & query.0) != 0
    }
}

impl std::ops::BitOr for ContentTypeMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ContentTypeMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ---------------------------------------------------------------------------
// Domain constraint
// ---------------------------------------------------------------------------

/// Domain include/exclude list for a rule (`$domain=a.com|~b.com`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainConstraint {
    /// Domains the rule applies to (empty = all domains).
    pub include: Vec<String>,
    /// Domains the rule does NOT apply to.
    pub exclude: Vec<String>,
}

impl DomainConstraint {
    /// Check whether a request from `source_domain` satisfies this constraint.
    pub fn matches(&self, source_domain: &str) -> bool {
        let src = source_domain.to_ascii_lowercase();

        // Exclusions take priority.
        for ex in &self.exclude {
            if domain_matches(&src, ex) {
                return false;
            }
        }

        // If include list is empty, all non-excluded domains match.
        if self.include.is_empty() {
            return true;
        }

        for inc in &self.include {
            if domain_matches(&src, inc) {
                return true;
            }
        }
        false
    }
}

/// Returns `true` when `host` equals `pattern` or is a subdomain of it.
fn domain_matches(host: &str, pattern: &str) -> bool {
    if host == pattern {
        return true;
    }
    host.ends_with(pattern) && host.as_bytes().get(host.len() - pattern.len() - 1) == Some(&b'.')
}

// ---------------------------------------------------------------------------
// Wildcard pattern
// ---------------------------------------------------------------------------

/// Part of a compiled wildcard filter pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WildcardPart {
    /// Literal byte sequence that must appear verbatim.
    Literal(String),
    /// Matches any sequence of characters (`*`).
    Wildcard,
    /// Matches a single separator character — anything that is not alphanumeric,
    /// `-`, `.`, or `%` (EasyList `^` semantics).
    Separator,
}

/// A compiled wildcard pattern built from EasyList filter syntax.
///
/// Supports `*` (any chars) and `^` (separator) placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WildcardPattern {
    /// Ordered parts of the pattern.
    pub parts: Vec<WildcardPart>,
}

impl WildcardPattern {
    /// Compile a raw filter pattern string into a [`WildcardPattern`].
    pub fn compile(raw: &str) -> Self {
        let mut parts = Vec::new();
        let mut buf = String::new();

        for ch in raw.chars() {
            match ch {
                '*' => {
                    if !buf.is_empty() {
                        parts.push(WildcardPart::Literal(std::mem::take(&mut buf)));
                    }
                    // Collapse consecutive wildcards.
                    if !matches!(parts.last(), Some(WildcardPart::Wildcard)) {
                        parts.push(WildcardPart::Wildcard);
                    }
                }
                '^' => {
                    if !buf.is_empty() {
                        parts.push(WildcardPart::Literal(std::mem::take(&mut buf)));
                    }
                    parts.push(WildcardPart::Separator);
                }
                other => buf.push(other),
            }
        }
        if !buf.is_empty() {
            parts.push(WildcardPart::Literal(buf));
        }

        Self { parts }
    }

    /// Test whether `input` matches this pattern.
    pub fn matches(&self, input: &str) -> bool {
        match_parts(&self.parts, input)
    }
}

/// Recursive matcher for wildcard parts against an input string.
fn match_parts(parts: &[WildcardPart], input: &str) -> bool {
    if parts.is_empty() {
        return true; // pattern exhausted — match
    }

    match &parts[0] {
        WildcardPart::Literal(lit) => {
            if let Some(pos) = input.find(lit.as_str()) {
                // For the very first literal we allow a match anywhere (substring).
                // Subsequent literals must follow in order.
                match_parts(&parts[1..], &input[pos + lit.len()..])
            } else {
                false
            }
        }
        WildcardPart::Wildcard => {
            // Try matching rest starting from every possible offset.
            for i in 0..=input.len() {
                if match_parts(&parts[1..], &input[i..]) {
                    return true;
                }
            }
            false
        }
        WildcardPart::Separator => {
            if input.is_empty() {
                // End of URL counts as separator.
                return match_parts(&parts[1..], input);
            }
            let first = input.as_bytes()[0];
            if is_separator(first) {
                match_parts(&parts[1..], &input[1..])
            } else {
                false
            }
        }
    }
}

/// EasyList separator: anything that is NOT `[a-zA-Z0-9_-.%]`.
fn is_separator(b: u8) -> bool {
    !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'%'))
}

// ---------------------------------------------------------------------------
// Filter pattern
// ---------------------------------------------------------------------------

/// Compiled representation of the URL-matching part of a network rule.
#[derive(Debug, Clone)]
pub enum FilterPattern {
    /// Plain case-insensitive substring match.
    Plain(String),
    /// Domain anchor (`||example.com^`) — matches if the URL's hostname
    /// equals or is a subdomain of the anchor domain.
    DomainAnchor(String),
    /// Compiled regex (`/regex/`).
    Regex(regex::Regex),
    /// Pattern containing `*` or `^` wildcards.
    Wildcard(WildcardPattern),
}

impl PartialEq for FilterPattern {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Plain(a), Self::Plain(b)) => a == b,
            (Self::DomainAnchor(a), Self::DomainAnchor(b)) => a == b,
            (Self::Regex(a), Self::Regex(b)) => a.as_str() == b.as_str(),
            (Self::Wildcard(a), Self::Wildcard(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for FilterPattern {}

impl FilterPattern {
    /// Test whether `url` matches this pattern.
    ///
    /// For [`DomainAnchor`] the comparison is done against the URL's host
    /// portion.  For all other variants the full URL string is tested.
    pub fn matches(&self, url: &str, url_host: &str) -> bool {
        match self {
            Self::Plain(s) => url.to_ascii_lowercase().contains(&s.to_ascii_lowercase()),
            Self::DomainAnchor(domain) => {
                let host = url_host.to_ascii_lowercase();
                let d = domain.to_ascii_lowercase();
                host == d || host.ends_with(&format!(".{d}"))
            }
            Self::Regex(re) => re.is_match(url),
            Self::Wildcard(wp) => wp.matches(url),
        }
    }
}

// ---------------------------------------------------------------------------
// Rule options
// ---------------------------------------------------------------------------

/// Parsed modifier options attached to a network rule (`$opt1,opt2,...`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleOptions {
    /// Bitmask of content types the rule applies to.
    pub content_type: ContentTypeMask,
    /// Domain constraints (`$domain=...`).
    pub domains: Option<DomainConstraint>,
    /// `$important` — overrides exception rules.
    pub important: bool,
    /// `$redirect=resource` — serve a replacement resource instead of blocking.
    pub redirect: Option<String>,
    /// `$removeparam=name` — strip a query parameter from the URL.
    pub removeparam: Option<String>,
    /// Third-party constraint: `Some(true)` = third-party only,
    /// `Some(false)` = first-party only, `None` = any.
    pub third_party: Option<bool>,
    /// `$csp=directive` — inject a Content-Security-Policy header.
    pub csp: Option<String>,
    /// `$match-case` — pattern matching is case-sensitive.
    pub match_case: bool,
}

// ---------------------------------------------------------------------------
// Network rule
// ---------------------------------------------------------------------------

/// A single network filter rule parsed from adblock filter list syntax.
///
/// Covers both blocking and exception (`@@`) rules.  The rule stores the
/// compiled URL pattern, modifier options, and the original raw text for
/// debugging/export.
#[derive(Debug, Clone)]
pub struct NetworkRule {
    /// Monotonic rule identifier (unique within one [`FilterEngine`]).
    pub id: u32,
    /// Compiled URL-matching pattern.
    pub pattern: FilterPattern,
    /// `true` for exception rules (`@@||...`).
    pub is_exception: bool,
    /// Modifier options parsed from `$opt,...`.
    pub options: RuleOptions,
    /// Original raw filter text.
    pub raw: String,
}

impl fmt::Display for NetworkRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod filter_rule_tests {
    use super::*;

    #[test]
    fn content_type_mask_basics() {
        let mask = ContentTypeMask::SCRIPT | ContentTypeMask::IMAGE;
        assert!(mask.contains(ContentTypeMask::SCRIPT));
        assert!(mask.matches(ContentTypeMask::IMAGE));
        assert!(!mask.matches(ContentTypeMask::FONT));
        assert!(ContentTypeMask::NONE.matches(ContentTypeMask::FONT)); // empty = all
    }

    #[test]
    fn domain_constraint_matching() {
        let dc = DomainConstraint {
            include: vec!["example.com".to_owned()],
            exclude: vec!["sub.example.com".to_owned()],
        };
        assert!(dc.matches("example.com"));
        assert!(dc.matches("www.example.com"));
        assert!(!dc.matches("sub.example.com"));
        assert!(!dc.matches("other.org"));
    }

    #[test]
    fn wildcard_pattern_star_and_separator() {
        let pat = WildcardPattern::compile("ad*tracker^");
        // `.` is NOT a separator in EasyList terms; `/` IS a separator.
        assert!(pat.matches("https://example.com/adXXtracker/rest"));
        assert!(pat.matches("https://example.com/adXXtracker?q=1"));
        assert!(!pat.matches("https://example.com/admirable"));
        // `tracker.com` — after "tracker" comes `.` which is not a separator.
        assert!(!pat.matches("https://adtracker.com/page"));
    }

    #[test]
    fn domain_anchor_matching() {
        let fp = FilterPattern::DomainAnchor("ads.example.com".to_owned());
        assert!(fp.matches("https://ads.example.com/banner.js", "ads.example.com"));
        assert!(fp.matches("https://cdn.ads.example.com/img.png", "cdn.ads.example.com"));
        assert!(!fp.matches("https://example.com/ads", "example.com"));
    }

    #[test]
    fn plain_substring_match() {
        let fp = FilterPattern::Plain("doubleclick".to_owned());
        assert!(fp.matches("https://ad.doubleclick.net/pagead", "ad.doubleclick.net"));
        assert!(!fp.matches("https://example.com/page", "example.com"));
    }
}
