use tracing::debug;

use crate::adblock::cosmetic::{CosmeticRule, ScriptletRule};
use crate::adblock::filter_rule::{
    ContentTypeMask, DomainConstraint, FilterPattern, NetworkRule, RuleOptions, WildcardPattern,
};

/// A single parse error with the offending line number and message.
#[derive(Debug, Clone)]
pub struct ParseError {
    /// 1-based line number within the filter list source.
    pub line: usize,
    /// Human-readable description of the error.
    pub message: String,
}

/// Result of parsing a complete filter list.
#[derive(Debug, Default)]
pub struct ParseResult {
    /// Successfully parsed network (URL blocking/exception) rules.
    pub network_rules: Vec<NetworkRule>,
    /// CSS cosmetic hiding rules.
    pub cosmetic_rules: Vec<CosmeticRule>,
    /// JavaScript scriptlet injection rules.
    pub scriptlet_rules: Vec<ScriptletRule>,
    /// Lines that could not be parsed.
    pub errors: Vec<ParseError>,
}

/// Parse a raw filter list string (EasyList / AdGuard syntax) into typed rules.
///
/// Handles comments (`!`, `[Adblock`), network rules (`||`, `@@||`),
/// cosmetic rules (`##`, `#@#`), and scriptlet rules (`#%#//scriptlet`).
pub fn parse_filter_list(raw: &str) -> ParseResult {
    let mut result = ParseResult::default();
    let mut next_id: u32 = 1;

    for (idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Comments and header lines.
        if line.starts_with('!') || line.starts_with('[') {
            continue;
        }

        // Scriptlet rules: `domain#%#//scriptlet(name, args...)`
        if let Some(rule) = try_parse_scriptlet(line) {
            result.scriptlet_rules.push(rule);
            continue;
        }

        // Cosmetic rules: `domain##selector` or `domain#@#selector`
        if let Some(rule) = try_parse_cosmetic(line) {
            result.cosmetic_rules.push(rule);
            continue;
        }

        // Network rules (blocking + exceptions).
        match parse_network_rule(line, next_id) {
            Ok(rule) => {
                next_id = next_id.wrapping_add(1);
                result.network_rules.push(rule);
            }
            Err(msg) => {
                debug!(line_no = idx + 1, raw = line, "adblock parse skip: {msg}");
                result.errors.push(ParseError {
                    line: idx + 1,
                    message: msg,
                });
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Cosmetic rule parser
// ---------------------------------------------------------------------------

/// Try to parse a cosmetic hiding rule.
fn try_parse_cosmetic(line: &str) -> Option<CosmeticRule> {
    // Exception cosmetic: `domains#@#selector`
    if let Some((domains_part, selector)) = line.split_once("#@#") {
        let domains = parse_cosmetic_domains(domains_part);
        return Some(CosmeticRule {
            selector: selector.to_owned(),
            is_exception: true,
            domains,
            raw: line.to_owned(),
        });
    }

    // Blocking cosmetic: `domains##selector`
    if let Some((domains_part, selector)) = line.split_once("##") {
        // Avoid matching scriptlet or other special comment markers.
        if selector.starts_with('#') || selector.starts_with('%') {
            return None;
        }
        let domains = parse_cosmetic_domains(domains_part);
        return Some(CosmeticRule {
            selector: selector.to_owned(),
            is_exception: false,
            domains,
            raw: line.to_owned(),
        });
    }

    None
}

/// Parse comma-separated domain list before `##`/`#@#`.
fn parse_cosmetic_domains(raw: &str) -> Option<DomainConstraint> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let mut include = Vec::new();
    let mut exclude = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(stripped) = part.strip_prefix('~') {
            exclude.push(stripped.to_ascii_lowercase());
        } else {
            include.push(part.to_ascii_lowercase());
        }
    }
    if include.is_empty() && exclude.is_empty() {
        return None;
    }
    Some(DomainConstraint { include, exclude })
}

// ---------------------------------------------------------------------------
// Scriptlet rule parser
// ---------------------------------------------------------------------------

/// Try to parse a scriptlet injection rule.
fn try_parse_scriptlet(line: &str) -> Option<ScriptletRule> {
    // Format: `domains#%#//scriptlet(name, arg1, arg2, ...)`
    let (domains_part, rest) = line.split_once("#%#")?;
    let body = rest.trim();
    let inner = body.strip_prefix("//scriptlet(")?;
    let inner = inner.strip_suffix(')')?;

    let args: Vec<String> = inner
        .split(',')
        .map(|a| a.trim().trim_matches('\'').trim_matches('"').to_owned())
        .collect();

    let name = args.first()?.clone();
    let fn_args = if args.len() > 1 {
        args[1..].to_vec()
    } else {
        Vec::new()
    };
    let domains = parse_cosmetic_domains(domains_part);

    Some(ScriptletRule {
        name,
        args: fn_args,
        domains,
        raw: line.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Network rule parser
// ---------------------------------------------------------------------------

/// Parse a single network rule line.
fn parse_network_rule(line: &str, id: u32) -> Result<NetworkRule, String> {
    let raw = line.to_owned();

    // Exception prefix.
    let (is_exception, rest) = if let Some(stripped) = line.strip_prefix("@@") {
        (true, stripped)
    } else {
        (false, line)
    };

    // Split pattern from options at the last unescaped `$`.
    let (pattern_str, options_str) = split_pattern_options(rest);

    let options = if options_str.is_empty() {
        RuleOptions::default()
    } else {
        parse_options(options_str)?
    };

    let pattern = compile_pattern(pattern_str)?;

    Ok(NetworkRule {
        id,
        pattern,
        is_exception,
        options,
        raw,
    })
}

/// Split the filter line into (pattern, options) at the *last* `$` that is
/// not inside a regex.
fn split_pattern_options(input: &str) -> (&str, &str) {
    // Regex rules are enclosed in `/…/` — do not split inside them.
    if input.starts_with('/') && input.contains("$/") {
        return (input, "");
    }

    if let Some(pos) = input.rfind('$') {
        // Make sure we don't split inside a regex.
        if input.starts_with('/') {
            return (input, "");
        }
        (&input[..pos], &input[pos + 1..])
    } else {
        (input, "")
    }
}

/// Compile a pattern string into a [`FilterPattern`].
fn compile_pattern(pat: &str) -> Result<FilterPattern, String> {
    if pat.is_empty() {
        return Ok(FilterPattern::Plain(String::new()));
    }

    // Regex: `/pattern/`
    if pat.starts_with('/') && pat.ends_with('/') && pat.len() > 2 {
        let inner = &pat[1..pat.len() - 1];
        let re = regex::Regex::new(inner).map_err(|e| format!("invalid regex '{inner}': {e}"))?;
        return Ok(FilterPattern::Regex(re));
    }

    // Domain anchor: `||domain.com^` (with optional trailing `^` or path).
    if let Some(stripped) = pat.strip_prefix("||") {
        let domain = stripped
            .trim_end_matches('^')
            .trim_end_matches('*')
            .trim_end_matches('/');
        if !domain.is_empty() && !domain.contains('*') && !domain.contains('^') {
            return Ok(FilterPattern::DomainAnchor(domain.to_ascii_lowercase()));
        }
        // Fall through to wildcard if the pattern is more complex.
    }

    // Wildcard / separator patterns.
    if pat.contains('*') || pat.contains('^') {
        return Ok(FilterPattern::Wildcard(WildcardPattern::compile(pat)));
    }

    // Plain substring.
    Ok(FilterPattern::Plain(pat.to_owned()))
}

/// Parse the `$option1,option2,...` part of a network rule.
fn parse_options(opts: &str) -> Result<RuleOptions, String> {
    let mut result = RuleOptions::default();
    let mut has_type_option = false;

    for opt in opts.split(',') {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }

        if let Some(val) = opt.strip_prefix("domain=") {
            result.domains = Some(parse_domain_option(val));
            continue;
        }
        if let Some(val) = opt.strip_prefix("redirect=") {
            result.redirect = Some(val.to_owned());
            continue;
        }
        if let Some(val) = opt.strip_prefix("removeparam=") {
            result.removeparam = Some(val.to_owned());
            continue;
        }
        if let Some(val) = opt.strip_prefix("csp=") {
            result.csp = Some(val.to_owned());
            continue;
        }

        match opt {
            "important" => result.important = true,
            "match-case" => result.match_case = true,
            "third-party" | "3p" => result.third_party = Some(true),
            "~third-party" | "~3p" | "first-party" | "1p" => result.third_party = Some(false),
            "script" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::SCRIPT;
            }
            "~script" => {
                result.content_type =
                    ContentTypeMask(result.content_type.0 & !ContentTypeMask::SCRIPT.0);
            }
            "image" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::IMAGE;
            }
            "~image" => {
                result.content_type =
                    ContentTypeMask(result.content_type.0 & !ContentTypeMask::IMAGE.0);
            }
            "stylesheet" | "css" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::STYLESHEET;
            }
            "object" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::OBJECT;
            }
            "xmlhttprequest" | "xhr" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::XMLHTTPREQUEST;
            }
            "subdocument" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::SUBDOCUMENT;
            }
            "font" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::FONT;
            }
            "media" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::MEDIA;
            }
            "websocket" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::WEBSOCKET;
            }
            "popup" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::POPUP;
            }
            "document" | "doc" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::DOCUMENT;
            }
            "other" => {
                has_type_option = true;
                result.content_type |= ContentTypeMask::OTHER;
            }
            _ => {
                // Skip unknown options silently — forward-compatible.
                debug!(option = opt, "adblock: unknown rule option, skipping");
            }
        }
    }

    // If no content-type options were specified, the rule matches all types.
    if !has_type_option && result.content_type.is_empty() {
        result.content_type = ContentTypeMask::NONE; // empty = matches all
    }

    Ok(result)
}

/// Parse `domain=example.com|~sub.example.com|other.org`.
fn parse_domain_option(val: &str) -> DomainConstraint {
    let mut include = Vec::new();
    let mut exclude = Vec::new();
    for part in val.split('|') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(stripped) = part.strip_prefix('~') {
            exclude.push(stripped.to_ascii_lowercase());
        } else {
            include.push(part.to_ascii_lowercase());
        }
    }
    DomainConstraint { include, exclude }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod filter_parser_tests {
    use super::*;

    #[test]
    fn parse_basic_blocking_rule() {
        let result = parse_filter_list("||ads.example.com^\n");
        assert_eq!(result.network_rules.len(), 1);
        let rule = &result.network_rules[0];
        assert!(!rule.is_exception);
        assert!(
            matches!(rule.pattern, FilterPattern::DomainAnchor(ref d) if d == "ads.example.com")
        );
    }

    #[test]
    fn parse_exception_rule() {
        let result = parse_filter_list("@@||example.com^$document\n");
        assert_eq!(result.network_rules.len(), 1);
        let rule = &result.network_rules[0];
        assert!(rule.is_exception);
        assert!(rule
            .options
            .content_type
            .contains(ContentTypeMask::DOCUMENT));
    }

    #[test]
    fn parse_options_third_party_domain() {
        let result =
            parse_filter_list("||tracker.com^$third-party,domain=example.com|~sub.example.com\n");
        assert_eq!(result.network_rules.len(), 1);
        let rule = &result.network_rules[0];
        assert_eq!(rule.options.third_party, Some(true));
        let dc = rule.options.domains.as_ref().expect("domains");
        assert_eq!(dc.include, vec!["example.com"]);
        assert_eq!(dc.exclude, vec!["sub.example.com"]);
    }

    #[test]
    fn parse_cosmetic_rule() {
        let result = parse_filter_list("example.com##.ad-banner\n");
        assert_eq!(result.cosmetic_rules.len(), 1);
        let rule = &result.cosmetic_rules[0];
        assert_eq!(rule.selector, ".ad-banner");
        assert!(!rule.is_exception);
        let dc = rule.domains.as_ref().expect("domains");
        assert_eq!(dc.include, vec!["example.com"]);
    }

    #[test]
    fn parse_cosmetic_exception() {
        let result = parse_filter_list("example.com#@#.ad-banner\n");
        assert_eq!(result.cosmetic_rules.len(), 1);
        assert!(result.cosmetic_rules[0].is_exception);
    }

    #[test]
    fn parse_scriptlet_rule() {
        let result = parse_filter_list(
            "example.com#%#//scriptlet('abort-on-property-read', 'adBlockDetected')\n",
        );
        assert_eq!(result.scriptlet_rules.len(), 1);
        let rule = &result.scriptlet_rules[0];
        assert_eq!(rule.name, "abort-on-property-read");
        assert_eq!(rule.args, vec!["adBlockDetected"]);
    }

    #[test]
    fn skip_comments_and_headers() {
        let input = "! comment line\n[Adblock Plus 2.0]\n||ads.com^\n";
        let result = parse_filter_list(input);
        assert_eq!(result.network_rules.len(), 1);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn parse_wildcard_rule() {
        let result = parse_filter_list("/ads/banner*\n");
        assert_eq!(result.network_rules.len(), 1);
        assert!(matches!(
            result.network_rules[0].pattern,
            FilterPattern::Wildcard(_)
        ));
    }

    #[test]
    fn parse_regex_rule() {
        let result = parse_filter_list("/\\.ads\\./\n");
        assert_eq!(result.network_rules.len(), 1);
        assert!(matches!(
            result.network_rules[0].pattern,
            FilterPattern::Regex(_)
        ));
    }

    #[test]
    fn parse_important_and_redirect() {
        let result = parse_filter_list("||cdn.ads.com^$important,redirect=noop-1s.mp4\n");
        assert_eq!(result.network_rules.len(), 1);
        let rule = &result.network_rules[0];
        assert!(rule.options.important);
        assert_eq!(rule.options.redirect.as_deref(), Some("noop-1s.mp4"));
    }

    #[test]
    fn parse_removeparam() {
        let result = parse_filter_list("||example.com^$removeparam=utm_source\n");
        let rule = &result.network_rules[0];
        assert_eq!(rule.options.removeparam.as_deref(), Some("utm_source"));
    }

    #[test]
    fn parse_multi_content_types() {
        let result = parse_filter_list("||ads.com^$script,image,xhr\n");
        let ct = result.network_rules[0].options.content_type;
        assert!(ct.contains(ContentTypeMask::SCRIPT));
        assert!(ct.contains(ContentTypeMask::IMAGE));
        assert!(ct.contains(ContentTypeMask::XMLHTTPREQUEST));
        assert!(!ct.contains(ContentTypeMask::FONT));
    }
}
