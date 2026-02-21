//! Built-in domains that require packet-level bypass (ciadpi).
//! No external dependencies, network access, or filesystem access.

/// Returns true when the domain should be routed through packet bypass.
/// Matching rules: exact + suffix (`youtube.com` matches `www.youtube.com`).
/// No heap allocations on the hot path.
pub fn is_bypass_domain(host: &str) -> bool {
    const BLOCKED: &[&str] = &[
        "youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com",
        "yt3.ggpht.com",
        "ggpht.com",
        "googleapis.com",
        "google.com",
        "gstatic.com",
        "googleusercontent.com",
        "instagram.com",
        "cdninstagram.com",
        "fbcdn.net",
        "facebook.com",
        "twitter.com",
        "twimg.com",
        "x.com",
        "t.co",
        "tiktok.com",
        "discord.com",
        "discord.gg",
        "discordapp.com",
        "discordapp.net",
        "discordcdn.com",
        "discord.media",
        "discord.dev",
    ];
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
    fn exact_match() {
        assert!(is_bypass_domain("youtube.com"));
        assert!(is_bypass_domain("YOUTUBE.COM"));
    }

    #[test]
    fn suffix_match() {
        assert!(is_bypass_domain("www.youtube.com"));
        assert!(is_bypass_domain("rr3---sn-ab5l6ne7.googlevideo.com"));
        assert!(is_bypass_domain("gateway.discord.gg"));
        assert!(is_bypass_domain("cdn.discord.media"));
    }

    #[test]
    fn no_false_positives() {
        assert!(!is_bypass_domain("notyoutube.com"));
        assert!(!is_bypass_domain("habr.com"));
        assert!(!is_bypass_domain(""));
    }
}
