//! Built-in domains that require packet-level bypass (ciadpi).
//! No external dependencies, network access, or filesystem access.

/// Returns true when the domain should be routed through packet bypass.
/// Matching rules: exact + suffix (`youtube.com` matches `www.youtube.com`).
/// No heap allocations on the hot path.
pub fn is_bypass_domain(host: &str) -> bool {
    const BLOCKED: &[&str] = &[];
    let host = host.trim_end_matches('.');
    for &blocked in BLOCKED {
        if host.eq_ignore_ascii_case(blocked) {
            return true;
        }
        let suffix_len = blocked.len() + 1;
        if host.len() > suffix_len {
            let dot_pos = host.len() - suffix_len;
            if host.as_bytes()[dot_pos] == b'.' && host[dot_pos + 1..].eq_ignore_ascii_case(blocked)
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_empty() {
        assert!(!is_bypass_domain("youtube.com"));
        assert!(!is_bypass_domain("google.com"));
        assert!(!is_bypass_domain("discord.gg"));
    }

    #[test]
    fn no_false_positives() {
        assert!(!is_bypass_domain("habr.com"));
        assert!(!is_bypass_domain(""));
    }
}
