use crate::config::PrivacySignalsConfig;

pub fn apply_signals(headers: &mut Vec<(String, String)>, cfg: &PrivacySignalsConfig) -> bool {
    let mut changed = false;

    if cfg.send_dnt && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("dnt")) {
        headers.push(("DNT".to_owned(), "1".to_owned()));
        changed = true;
    }

    if cfg.send_gpc
        && !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("sec-gpc"))
    {
        headers.push(("Sec-GPC".to_owned(), "1".to_owned()));
        changed = true;
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_dnt_and_gpc() {
        let cfg = PrivacySignalsConfig {
            send_dnt: true,
            send_gpc: true,
        };
        let mut headers = Vec::new();
        assert!(apply_signals(&mut headers, &cfg));
        assert!(headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("dnt") && v == "1"));
        assert!(headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("sec-gpc") && v == "1"));
    }
}
