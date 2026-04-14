//! HTTP header normalization to reduce browser fingerprinting surface.
//!
//! Strips or normalizes headers that DPI or remote servers
//! can use to fingerprint a specific browser/OS/locale combination.

use serde::{Deserialize, Serialize};

/// Configuration for HTTP header normalization.
///
/// When enabled, rewrites or removes headers that DPI or remote servers
/// can use to fingerprint a specific browser/OS/locale combination.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HeaderNormalizerConfig {
    /// Master switch — when `false`, no headers are modified.
    pub enabled: bool,
    /// Strip all Client-Hints (`Sec-CH-UA-*`, `Device-Memory`, `DPR`, etc.).
    pub strip_client_hints: bool,
    /// Replace `Accept-Language` with a generic `en-US,en;q=0.9` value.
    pub normalize_accept_language: bool,
    /// Strip the `Via` header added by intermediate proxies.
    pub strip_via: bool,
    /// Strip `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`.
    pub strip_x_forwarded: bool,
    /// Strip the `X-Real-IP` header.
    pub strip_x_real_ip: bool,
}

/// Client-Hints header names that reveal browser/OS/device details.
const CLIENT_HINTS_HEADERS: &[&str] = &[
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-platform-version",
    "device-memory",
    "downlink",
    "ect",
    "rtt",
    "save-data",
    "viewport-width",
    "width",
    "dpr",
];

/// Proxy-forwarding header names that reveal network topology.
const X_FORWARDED_HEADERS: &[&str] = &["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"];

/// Generic Accept-Language value used as a replacement to hide the real locale.
const NORMALIZED_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";

/// Normalize HTTP headers in-place according to the provided configuration.
///
/// Returns the number of individual header modifications performed
/// (removals + replacements).
pub fn normalize_headers(headers: &mut Vec<(String, String)>, cfg: &HeaderNormalizerConfig) -> u32 {
    if !cfg.enabled {
        return 0;
    }

    let mut count: u32 = 0;

    if cfg.strip_client_hints {
        let before = headers.len();
        headers.retain(|(k, _)| {
            let lower = k.to_ascii_lowercase();
            !CLIENT_HINTS_HEADERS.contains(&lower.as_str())
        });
        count += (before - headers.len()) as u32;
    }

    if cfg.normalize_accept_language {
        for (k, v) in headers.iter_mut() {
            if k.eq_ignore_ascii_case("accept-language") && v != NORMALIZED_ACCEPT_LANGUAGE {
                *v = NORMALIZED_ACCEPT_LANGUAGE.to_owned();
                count += 1;
            }
        }
    }

    if cfg.strip_via {
        let before = headers.len();
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("via"));
        count += (before - headers.len()) as u32;
    }

    if cfg.strip_x_forwarded {
        let before = headers.len();
        headers.retain(|(k, _)| {
            let lower = k.to_ascii_lowercase();
            !X_FORWARDED_HEADERS.contains(&lower.as_str())
        });
        count += (before - headers.len()) as u32;
    }

    if cfg.strip_x_real_ip {
        let before = headers.len();
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("x-real-ip"));
        count += (before - headers.len()) as u32;
    }

    count
}

#[cfg(test)]
mod header_normalizer_tests {
    use super::*;

    fn all_enabled_config() -> HeaderNormalizerConfig {
        HeaderNormalizerConfig {
            enabled: true,
            strip_client_hints: true,
            normalize_accept_language: true,
            strip_via: true,
            strip_x_forwarded: true,
            strip_x_real_ip: true,
        }
    }

    #[test]
    fn disabled_config_does_nothing() {
        let cfg = HeaderNormalizerConfig::default();
        let mut headers = vec![
            ("Sec-CH-UA".to_owned(), "Chromium".to_owned()),
            ("Via".to_owned(), "1.1 proxy".to_owned()),
        ];
        let count = normalize_headers(&mut headers, &cfg);
        assert_eq!(count, 0);
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn strips_all_client_hints() {
        let cfg = all_enabled_config();
        let mut headers = vec![
            ("Sec-CH-UA".to_owned(), "\"Chromium\"".to_owned()),
            ("Sec-CH-UA-Mobile".to_owned(), "?0".to_owned()),
            ("Sec-CH-UA-Platform".to_owned(), "\"Windows\"".to_owned()),
            ("Device-Memory".to_owned(), "8".to_owned()),
            ("DPR".to_owned(), "2".to_owned()),
            ("Host".to_owned(), "example.com".to_owned()),
        ];
        let count = normalize_headers(&mut headers, &cfg);
        assert!(count >= 5);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Host");
    }

    #[test]
    fn normalizes_accept_language() {
        let cfg = all_enabled_config();
        let mut headers = vec![(
            "Accept-Language".to_owned(),
            "ru-RU,ru;q=0.9,en-US;q=0.8".to_owned(),
        )];
        let count = normalize_headers(&mut headers, &cfg);
        assert_eq!(count, 1);
        assert_eq!(headers[0].1, "en-US,en;q=0.9");
    }

    #[test]
    fn already_normalized_accept_language_not_counted() {
        let cfg = all_enabled_config();
        let mut headers = vec![("Accept-Language".to_owned(), "en-US,en;q=0.9".to_owned())];
        let count = normalize_headers(&mut headers, &cfg);
        assert_eq!(count, 0);
    }

    #[test]
    fn strips_via_and_forwarding_headers() {
        let cfg = all_enabled_config();
        let mut headers = vec![
            ("Via".to_owned(), "1.1 proxy.example.com".to_owned()),
            ("X-Forwarded-For".to_owned(), "192.168.1.1".to_owned()),
            ("X-Forwarded-Host".to_owned(), "original.com".to_owned()),
            ("X-Forwarded-Proto".to_owned(), "https".to_owned()),
            ("X-Real-IP".to_owned(), "10.0.0.1".to_owned()),
            ("Content-Type".to_owned(), "text/html".to_owned()),
        ];
        let count = normalize_headers(&mut headers, &cfg);
        assert_eq!(count, 5);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
    }

    #[test]
    fn selective_options_only_strips_via() {
        let cfg = HeaderNormalizerConfig {
            enabled: true,
            strip_client_hints: false,
            normalize_accept_language: false,
            strip_via: true,
            strip_x_forwarded: false,
            strip_x_real_ip: false,
        };
        let mut headers = vec![
            ("Sec-CH-UA".to_owned(), "test".to_owned()),
            ("Via".to_owned(), "proxy".to_owned()),
            ("X-Forwarded-For".to_owned(), "1.2.3.4".to_owned()),
        ];
        let count = normalize_headers(&mut headers, &cfg);
        assert_eq!(count, 1);
        assert_eq!(headers.len(), 2);
    }
}
