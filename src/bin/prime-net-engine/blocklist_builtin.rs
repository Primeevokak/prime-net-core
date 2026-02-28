//! Built-in domains that require packet-level bypass (ciadpi).
//! No external dependencies, network access, or filesystem access.

use std::collections::HashSet;
use std::sync::OnceLock;

/// Returns true when the domain should be routed through packet bypass.
/// Matching rules: exact + suffix (`youtube.com` matches `www.youtube.com`).
/// No heap allocations on the hot path after initialization.
pub fn is_bypass_domain(host: &str) -> bool {
    static BYPASS_SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    let set = BYPASS_SET.get_or_init(|| {
        [
            // === Video & Streaming (Censored) ===
            "youtube.com",
            "youtu.be",
            "ytimg.com",
            "googlevideo.com",
            "ggpht.com",
            "youtubei.googleapis.com",
            "youtube-nocookie.com",
            "twitch.tv",
            "ttvnw.net",
            "jtvnw.net",
            // === Gaming (Censored) ===
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
            "discord-attachments.net",
            "steamcommunity.com",
            // === Social Media & Messengers (Censored) ===
            "instagram.com",
            "cdninstagram.com",
            "facebook.com",
            "fbcdn.net",
            "fbsbx.com",
            "x.com",
            "twitter.com",
            "twimg.com",
            "linkedin.com",
            "snapchat.com",
            "whatsapp.com",
            "whatsapp.net",
            "viber.com",
            "signal.org",
            "patreon.com",
            // === Media & Audio (Censored) ===
            "soundcloud.com",
            "sndcdn.com",
            // === News & Information (Censored) ===
            "bbc.com",
            "bbc.co.uk",
            "cnn.com",
            "dw.com",
            "voanews.com",
            "spiegel.de",
            "zeit.de",
            "lemonde.fr",
            "liberation.fr",
            "politico.eu",
            "meduza.io",
            "zona.media",
            "tvrain.tv",
            "themoscowtimes.com",
            // === Privacy & Infrastructure (Censored) ===
            "proton.me",
            "protonmail.com",
            "torproject.org",
            "archive.org",
            "rutracker.org",
            "nnmclub.to",
        ]
        .into_iter()
        .collect()
    });

    let host = host.trim_end_matches('.');
    if set.contains(host) {
        return true;
    }

    // Exact match (case insensitive check if set contains lowercase only)
    for &domain in set {
        if host.eq_ignore_ascii_case(domain) {
            return true;
        }
    }

    // Check suffix match: e.g. host "www.youtube.com", set contains "youtube.com"
    for &domain in set {
        let suffix_len = domain.len();
        if host.len() > suffix_len {
            let dot_pos = host.len() - suffix_len - 1;
            if host.as_bytes()[dot_pos] == b'.' && host[dot_pos + 1..].eq_ignore_ascii_case(domain)
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
    fn list_has_core_domains() {
        assert!(is_bypass_domain("youtube.com"));
        assert!(is_bypass_domain("gateway.discord.gg"));
    }

    #[test]
    fn no_false_positives() {
        assert!(!is_bypass_domain("habr.com"));
        assert!(!is_bypass_domain(""));
    }
}
