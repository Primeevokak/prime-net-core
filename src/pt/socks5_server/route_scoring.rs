use crate::config::EngineConfig;
use crate::pt::socks5_server::*;

pub fn route_health_score(
    route_key: &str,
    candidate: &RouteCandidate,
    now: u64,
    cfg: &EngineConfig,
) -> i64 {
    let route_id = candidate.route_id();
    let mut bonus = 0i64;
    if candidate.kind == RouteKind::Bypass || candidate.kind == RouteKind::Native {
        let bucket = host_service_bucket(route_key, cfg);
        bonus += bypass_bucket_bonus(&bucket, candidate, cfg);
    }
    let local_score = {
        let map = DEST_ROUTE_HEALTH.get_or_init(dashmap::DashMap::new);
        if let Some(per_route) = map.get(route_key) {
            if let Some(health) = per_route.get(&route_id) {
                let mut score = (health.successes as i64 * 3) - (health.failures as i64 * 4);
                if health.weak_until_unix > now {
                    score -= 10_000;
                }
                score
            } else {
                0
            }
        } else {
            0
        }
    };
    local_score + global_bypass_profile_score(candidate, now, cfg) + bonus
}

pub fn global_bypass_profile_score(
    candidate: &RouteCandidate,
    now: u64,
    cfg: &EngineConfig,
) -> i64 {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") && !route_id.starts_with("native:") {
        return 0;
    }
    let primary_key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(dashmap::DashMap::new);
    if let Some(health) = map.get(&primary_key) {
        if should_reset_bypass_profile_health(&health, now, cfg) {
            drop(health);
            map.remove(&primary_key);
            return 0;
        }
        return bypass_profile_score_from_health(&health, now, cfg);
    }
    0
}

pub fn bypass_profile_score_from_health(
    health: &BypassProfileHealth,
    now: u64,
    _cfg: &EngineConfig,
) -> i64 {
    let mut score = (health.successes as i64 * 5) - (health.failures as i64 * 6);
    if health.last_success_unix > 0 && now.saturating_sub(health.last_success_unix) <= 300 {
        score += 3;
    }
    score
}

pub fn should_reset_bypass_profile_health(
    health: &BypassProfileHealth,
    now: u64,
    _cfg: &EngineConfig,
) -> bool {
    health.successes == 0
        && health.failures > 20
        && now.saturating_sub(health.last_failure_unix) > 600
}

fn bypass_bucket_bonus(bucket: &str, candidate: &RouteCandidate, _cfg: &EngineConfig) -> i64 {
    if candidate.kind != RouteKind::Bypass && candidate.kind != RouteKind::Native {
        return 0;
    }
    match bucket {
        "meta-group:youtube" | "meta-group:discord" => {
            if candidate.bypass_profile_idx == 1 {
                8_000
            } else {
                4_000
            }
        }
        _ => 0,
    }
}

pub fn ordered_route_candidates(
    route_key: &str,
    candidates: Vec<RouteCandidate>,
    cfg: &EngineConfig,
) -> Vec<RouteCandidate> {
    let now = now_unix_secs();
    let mut filtered = candidates;
    filtered.sort_by(|a, b| {
        let a_score = route_health_score(route_key, a, now, cfg);
        let b_score = route_health_score(route_key, b, now, cfg);
        b_score
            .cmp(&a_score)
            .then_with(|| a.kind_rank().cmp(&b.kind_rank()))
    });
    filtered
}

pub fn is_censored_domain(domain: &str, _relay_opts: &RelayOptions, cfg: &EngineConfig) -> bool {
    let dest_lower = domain.to_lowercase();
    let group_key = route_destination_key(&dest_lower);
    let now = now_unix_secs();

    // 0. CHECK LEARNED WINNERS: If we have a cached winner for this domain/group, use it
    if let Some(winners) = DEST_ROUTE_WINNER.get() {
        for key in [&dest_lower, group_key] {
            if let Some(winner) = winners.get(key) {
                if winner.route_id.starts_with("bypass:") || winner.route_id.starts_with("native:")
                {
                    return true;
                }
            }
        }
    }

    // 1. DYNAMIC LEARNING: Check classifier for persistent signals
    if let Some(classifier) = DEST_CLASSIFIER.get() {
        for key in [&dest_lower, group_key] {
            if let Some(stats) = classifier.get(key) {
                if let Some(ref winner) = stats.winner {
                    if winner.route_id.starts_with("bypass:")
                        || winner.route_id.starts_with("native:")
                    {
                        return true;
                    }
                }

                // SENSITIVE DETECTION: Switch to bypass if we have ANY resets or ANY timeouts and no recent successes
                if stats.successes == 0
                    && (stats.resets > 0 || stats.timeouts > 0)
                    && now.saturating_sub(stats.last_seen_unix) < 86400
                {
                    return true;
                }
            }
        }
    }

    // 2. Check global engine blocklist
    if let Some(bloom) = BLOCKLIST_DOMAINS.get() {
        if bloom.contains_host_or_suffix(&dest_lower) {
            return true;
        }
    }

    // 3. Custom check function fallback
    if let Some(check_fn) = _relay_opts.bypass_domain_check {
        if check_fn(domain) {
            return true;
        }
    }

    // 4. Config groups
    let raw_bucket = host_service_bucket(group_key, cfg);
    cfg.routing
        .censored_groups
        .keys()
        .any(|g| raw_bucket == *g || raw_bucket == format!("meta-group:{}", g))
}

pub fn route_race_decision(
    _port: u16,
    _rk: &str,
    candidates: &[RouteCandidate],
    _cfg: &EngineConfig,
) -> (bool, RouteRaceReason) {
    if candidates.len() < 2 {
        return (false, RouteRaceReason::SingleCandidate);
    }
    (true, RouteRaceReason::NoWinner)
}

pub fn record_route_success_sync(route_key: &str, candidate: &RouteCandidate, cfg: &EngineConfig) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    {
        let map = DEST_ROUTE_HEALTH.get_or_init(dashmap::DashMap::new);
        let per_route = map.entry(route_key.to_owned()).or_default();
        let mut health = per_route.entry(route_id.clone()).or_default();
        health.successes += 1;
        health.consecutive_failures = 0;
        health.last_success_unix = now;
    }
    record_global_bypass_profile_success_sync(candidate, cfg);
}

pub fn record_route_failure_sync(
    route_key: &str,
    candidate: &RouteCandidate,
    reason: &'static str,
    cfg: &EngineConfig,
) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();

    // NUCLEAR PENALTY: If we get a Connection Reset or a DPI Signal (Alert/HTTP), it's a strong block signal.
    let is_reset =
        reason.contains("reset") || reason.contains("10054") || reason.contains("BrokenPipe");
    let is_dpi_signal = reason.contains("dpi-signal");

    {
        let map = DEST_ROUTE_HEALTH.get_or_init(dashmap::DashMap::new);
        let per_route = map.entry(route_key.to_owned()).or_default();
        let mut health = per_route.entry(route_id.clone()).or_default();
        health.failures += 1;
        health.consecutive_failures += 1;
        health.last_failure_unix = now;

        if is_reset || is_dpi_signal || health.consecutive_failures >= ROUTE_FAILS_BEFORE_WEAK {
            // Mark as weak for 10 minutes (600s) on DPI signal, 5 mins on reset, or 60s on normal failure
            let penalty_secs = if is_dpi_signal {
                600
            } else if is_reset {
                300
            } else {
                60
            };
            health.weak_until_unix = now + penalty_secs;

            // Force a rotation for the whole domain group
            if (is_reset || is_dpi_signal)
                && (candidate.kind == RouteKind::Bypass || candidate.kind == RouteKind::Native)
            {
                record_bypass_profile_failure(
                    route_key,
                    candidate.bypass_profile_idx,
                    candidate.bypass_profile_total,
                    reason,
                    cfg,
                );
            }
        }
    }
    record_global_bypass_profile_failure_sync(candidate, reason, now, cfg);
}

pub fn record_global_bypass_profile_success_sync(candidate: &RouteCandidate, _cfg: &EngineConfig) {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") && !route_id.starts_with("native:") {
        return;
    }
    let key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(dashmap::DashMap::new);
    let mut entry = map.entry(key).or_default();
    entry.successes += 1;
    entry.last_success_unix = now_unix_secs();
}

pub fn record_global_bypass_profile_failure_sync(
    candidate: &RouteCandidate,
    reason: &'static str,
    now: u64,
    _cfg: &EngineConfig,
) {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") && !route_id.starts_with("native:") {
        return;
    }
    let key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(dashmap::DashMap::new);
    let mut entry = map.entry(key).or_default();
    entry.failures += 1;
    entry.last_failure_unix = now;
    if reason == "connect-failed" {
        entry.connect_failures += 1;
    }
}

pub fn select_route_candidates(
    relay_opts: &RelayOptions,
    target: &crate::pt::TargetAddr,
    port: u16,
    destination: &str,
    cfg: &EngineConfig,
) -> Vec<RouteCandidate> {
    let mut out = Vec::new();
    let is_blocked = is_censored_domain(destination, relay_opts, cfg);
    let family = route_family_for_target(target);

    if port == 443 || port == 80 || port == 6443 || (5000..=9000).contains(&port) {
        let bypass_cands = select_bypass_candidates(relay_opts, destination, cfg);
        let native_cands = select_native_candidates(relay_opts);

        if is_blocked {
            // PROACTIVE BYPASS: For blocked domains try external bypass FIRST (score 1000),
            // then native desync profiles (score 900), direct is last-resort fallback.
            let mut count = 0;
            for (addr, idx, total) in bypass_cands {
                out.push(RouteCandidate {
                    score: 1000,
                    ..RouteCandidate::bypass_with_family("pool", addr, idx, total, family)
                });
                count += 1;
                if count >= 4 {
                    break;
                }
            }
            let mut native_count = 0;
            for (idx, total) in native_cands {
                out.push(RouteCandidate {
                    score: 900,
                    ..RouteCandidate::native_with_family("engine", idx, total, family)
                });
                native_count += 1;
                if native_count >= 4 {
                    break;
                }
            }
            // Direct is a very late fallback
            out.push(RouteCandidate {
                score: -10000,
                ..RouteCandidate::direct_with_family("adaptive", family)
            });
        } else {
            // Normal domains: Direct first, then bypass pool, then up to 2 native profiles as backup.
            out.push(RouteCandidate {
                score: 100,
                ..RouteCandidate::direct_with_family("adaptive", family)
            });
            for (addr, idx, total) in bypass_cands {
                out.push(RouteCandidate::bypass_with_family(
                    "pool", addr, idx, total, family,
                ));
            }
            let mut native_count = 0;
            for (idx, total) in native_cands {
                out.push(RouteCandidate::native_with_family(
                    "engine", idx, total, family,
                ));
                native_count += 1;
                if native_count >= 2 {
                    break;
                }
            }
        }
    } else {
        out.push(RouteCandidate::direct_with_family("adaptive", family));
    }
    out
}

pub fn host_service_bucket(host: &str, cfg: &EngineConfig) -> String {
    let host = host.to_ascii_lowercase();
    for (group, patterns) in &cfg.routing.censored_groups {
        for p in patterns {
            if host.contains(p) {
                return format!("meta-group:{}", group);
            }
        }
    }
    host
}

pub fn bypass_profile_health_key(route_id: &str, family: RouteIpFamily) -> String {
    if family == RouteIpFamily::Any {
        route_id.to_owned()
    } else {
        format!("{}|{}", route_id, family.label())
    }
}

pub fn select_bypass_candidates(
    relay_opts: &RelayOptions,
    _dest: &str,
    _cfg: &EngineConfig,
) -> Vec<(std::net::SocketAddr, u8, u8)> {
    let mut out = Vec::new();
    for (i, addr) in relay_opts.bypass_socks5_pool.iter().enumerate() {
        out.push((*addr, i as u8, relay_opts.bypass_socks5_pool.len() as u8));
    }
    out
}

/// Returns `(profile_idx, profile_total)` pairs for the in-process native desync engine.
pub fn select_native_candidates(relay_opts: &RelayOptions) -> Vec<(u8, u8)> {
    match relay_opts.native_bypass.as_ref() {
        Some(engine) => {
            let total = engine.profile_count() as u8;
            (0..total).map(|i| (i, total)).collect()
        }
        None => Vec::new(),
    }
}

pub fn route_family_for_target(target: &crate::pt::TargetAddr) -> RouteIpFamily {
    match target {
        crate::pt::TargetAddr::Ip(std::net::IpAddr::V4(_)) => RouteIpFamily::V4,
        crate::pt::TargetAddr::Ip(std::net::IpAddr::V6(_)) => RouteIpFamily::V6,
        _ => RouteIpFamily::Any,
    }
}

pub fn mark_route_capability_healthy(kind: RouteKind, family: RouteIpFamily) {
    if family == RouteIpFamily::Any {
        return;
    }
    let map =
        ROUTE_CAPABILITIES.get_or_init(|| std::sync::RwLock::new(RouteCapabilities::default()));
    if let Ok(mut g) = map.write() {
        match (kind, family) {
            (RouteKind::Direct, RouteIpFamily::V4) => g.direct_v4_weak_until = 0,
            (RouteKind::Direct, RouteIpFamily::V6) => g.direct_v6_weak_until = 0,
            (RouteKind::Bypass, RouteIpFamily::V4) => g.bypass_v4_weak_until = 0,
            (RouteKind::Bypass, RouteIpFamily::V6) => g.bypass_v6_weak_until = 0,
            (RouteKind::Native, RouteIpFamily::V4) => g.native_v4_weak_until = 0,
            (RouteKind::Native, RouteIpFamily::V6) => g.native_v6_weak_until = 0,
            _ => {}
        }
    }
}

pub fn route_capability_is_available(kind: RouteKind, family: RouteIpFamily, now: u64) -> bool {
    if family == RouteIpFamily::Any {
        return true;
    }
    let map =
        ROUTE_CAPABILITIES.get_or_init(|| std::sync::RwLock::new(RouteCapabilities::default()));
    if let Ok(g) = map.read() {
        let until = match (kind, family) {
            (RouteKind::Direct, RouteIpFamily::V4) => g.direct_v4_weak_until,
            (RouteKind::Direct, RouteIpFamily::V6) => g.direct_v6_weak_until,
            (RouteKind::Bypass, RouteIpFamily::V4) => g.bypass_v4_weak_until,
            (RouteKind::Bypass, RouteIpFamily::V6) => g.bypass_v6_weak_until,
            (RouteKind::Native, RouteIpFamily::V4) => g.native_v4_weak_until,
            (RouteKind::Native, RouteIpFamily::V6) => g.native_v6_weak_until,
            _ => 0,
        };
        now >= until
    } else {
        true
    }
}

pub fn route_destination_key(rk: &str) -> &str {
    let host = rk.split('|').next().unwrap_or(rk);
    let host = host.split(':').next().unwrap_or(host);

    // 1. Specialized High-Traffic Groups (keep for stability)
    if host.contains("googlevideo") {
        return "googlevideo.com";
    }
    if host.contains("discord") {
        return "discord.com";
    }
    if host.contains("instagram") || host.contains("fbcdn") {
        return "instagram.com";
    }
    if host.contains("facebook.com") || host.contains("fb.com") || host.contains("messenger.com") {
        return "facebook.com";
    }
    if host.contains("sndcdn") || host.contains("soundcloud") {
        return "soundcloud.com";
    }

    // 2. Generic SLD-based grouping (e.g., sub.example.com -> example.com)
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        let len = parts.len();
        // Return the last two parts as the group key
        let last_two = &host[host.len() - (parts[len - 2].len() + parts[len - 1].len() + 1)..];
        return last_two;
    }

    host
}
pub fn record_bypass_profile_failure(
    destination: &str,
    current_idx: u8,
    total: u8,
    _reason: &'static str,
    _cfg: &EngineConfig,
) {
    if total == 0 {
        return;
    }
    let next_idx = (current_idx + 1) % total;
    let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(dashmap::DashMap::new);
    idx_map.insert(destination.to_owned(), next_idx);
}
pub fn record_route_success(rk: &str, c: &RouteCandidate, cfg: &EngineConfig) {
    record_route_success_sync(rk, c, cfg);
}
pub fn record_route_failure(rk: &str, c: &RouteCandidate, r: &'static str, cfg: &EngineConfig) {
    record_route_failure_sync(rk, c, r, cfg);
}

#[cfg(test)]
mod native_bypass_tests {
    use super::*;
    use crate::evasion::TcpDesyncEngine;
    use std::sync::Arc;

    fn make_relay_opts_with_engine() -> RelayOptions {
        RelayOptions {
            native_bypass: Some(Arc::new(TcpDesyncEngine::with_default_profiles())),
            ..RelayOptions::default()
        }
    }

    // ── RouteKind::Native identity ────────────────────────────────────────────

    #[test]
    fn native_route_id_uses_native_prefix() {
        let c = RouteCandidate::native_with_family("engine", 0, 12, RouteIpFamily::Any);
        assert_eq!(c.route_id(), "native:1");
        let c2 = RouteCandidate::native_with_family("engine", 5, 12, RouteIpFamily::Any);
        assert_eq!(c2.route_id(), "native:6");
    }

    #[test]
    fn native_route_label_includes_source() {
        let c = RouteCandidate::native_with_family("engine", 2, 12, RouteIpFamily::Any);
        assert_eq!(c.route_label(), "native:3:engine");
    }

    #[test]
    fn native_kind_rank_equals_bypass() {
        let native = RouteCandidate::native_with_family("engine", 0, 12, RouteIpFamily::Any);
        let bypass = RouteCandidate::bypass_with_family(
            "pool",
            "127.0.0.1:19080".parse().unwrap(),
            0,
            1,
            RouteIpFamily::Any,
        );
        assert_eq!(native.kind_rank(), bypass.kind_rank());
    }

    // ── select_native_candidates ──────────────────────────────────────────────

    #[test]
    fn select_native_candidates_empty_when_no_engine() {
        let opts = RelayOptions::default(); // native_bypass = None
        let cands = select_native_candidates(&opts);
        assert!(cands.is_empty());
    }

    #[test]
    fn select_native_candidates_returns_all_profiles() {
        let opts = make_relay_opts_with_engine();
        let engine = opts.native_bypass.as_ref().unwrap();
        let total = engine.profile_count();
        let cands = select_native_candidates(&opts);
        assert_eq!(cands.len(), total);
        // Each entry: (idx, total)
        for (i, (idx, t)) in cands.iter().enumerate() {
            assert_eq!(*idx as usize, i);
            assert_eq!(*t as usize, total);
        }
    }

    // ── select_route_candidates with Native ───────────────────────────────────

    #[test]
    fn select_route_candidates_includes_native_for_blocked_domain() {
        let opts = RelayOptions {
            bypass_domain_check: Some(|h| h.contains("censored.example")),
            ..make_relay_opts_with_engine()
        };
        let target = crate::pt::TargetAddr::Domain("censored.example.com".to_owned());
        let cands = select_route_candidates(
            &opts,
            &target,
            443,
            "censored.example.com",
            &EngineConfig::default(),
        );

        let native_count = cands.iter().filter(|c| c.kind == RouteKind::Native).count();
        assert!(
            native_count > 0,
            "blocked domain must have Native candidates"
        );
        // Native score should be 900 for blocked domains
        let native_scores: Vec<_> = cands
            .iter()
            .filter(|c| c.kind == RouteKind::Native)
            .map(|c| c.score)
            .collect();
        assert!(native_scores.iter().all(|&s| s == 900));
    }

    #[test]
    fn select_route_candidates_includes_native_for_normal_domain() {
        let opts = make_relay_opts_with_engine();
        let target = crate::pt::TargetAddr::Domain("example.com".to_owned());
        let cands =
            select_route_candidates(&opts, &target, 443, "example.com", &EngineConfig::default());

        // For normal domains: Direct + up to 2 Native (no bypass pool)
        let native_count = cands.iter().filter(|c| c.kind == RouteKind::Native).count();
        assert!(
            native_count > 0 && native_count <= 2,
            "normal domain: up to 2 native candidates, got {}",
            native_count
        );
        assert!(cands.iter().any(|c| c.kind == RouteKind::Direct));
    }

    #[test]
    fn select_route_candidates_no_native_without_engine() {
        let opts = RelayOptions {
            bypass_socks5_pool: vec!["127.0.0.1:19080".parse().unwrap()],
            ..RelayOptions::default()
        };
        let target = crate::pt::TargetAddr::Domain("example.com".to_owned());
        let cands =
            select_route_candidates(&opts, &target, 443, "example.com", &EngineConfig::default());
        assert!(
            cands.iter().all(|c| c.kind != RouteKind::Native),
            "no engine → no native candidates"
        );
    }

    // ── Scoring: native: prefix handled same as bypass: ──────────────────────

    #[test]
    fn global_bypass_profile_score_applies_to_native_prefix() {
        let key = "native:1";
        let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(dashmap::DashMap::new);
        map.insert(
            key.to_owned(),
            BypassProfileHealth {
                successes: 10,
                failures: 0,
                last_success_unix: now_unix_secs(),
                ..Default::default()
            },
        );

        let candidate = RouteCandidate::native_with_family("engine", 0, 12, RouteIpFamily::Any);
        let score =
            global_bypass_profile_score(&candidate, now_unix_secs(), &EngineConfig::default());
        assert!(
            score > 0,
            "native route with successes should have positive global score"
        );

        map.remove(key);
    }

    #[test]
    fn global_bypass_profile_score_zero_for_direct() {
        let candidate = RouteCandidate::direct_with_family("adaptive", RouteIpFamily::Any);
        let score =
            global_bypass_profile_score(&candidate, now_unix_secs(), &EngineConfig::default());
        assert_eq!(score, 0);
    }

    // ── record success/failure updates native health ──────────────────────────

    #[test]
    fn record_native_success_increments_global_health() {
        let candidate = RouteCandidate::native_with_family("engine", 3, 12, RouteIpFamily::Any);
        let key = bypass_profile_health_key(&candidate.route_id(), candidate.family);
        // Clear state
        let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(dashmap::DashMap::new);
        map.remove(&key);

        record_global_bypass_profile_success_sync(&candidate, &EngineConfig::default());

        let health = map.get(&key).expect("health entry created");
        assert_eq!(health.successes, 1);
        map.remove(&key);
    }

    #[test]
    fn record_native_failure_increments_global_health() {
        let candidate = RouteCandidate::native_with_family("engine", 4, 12, RouteIpFamily::Any);
        let key = bypass_profile_health_key(&candidate.route_id(), candidate.family);
        let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(dashmap::DashMap::new);
        map.remove(&key);

        record_global_bypass_profile_failure_sync(
            &candidate,
            "handshake-io",
            now_unix_secs(),
            &EngineConfig::default(),
        );

        let health = map.get(&key).expect("health entry created");
        assert_eq!(health.failures, 1);
        map.remove(&key);
    }

    // ── Non-TLS port: no native candidates ───────────────────────────────────

    #[test]
    fn select_route_candidates_no_native_for_non_tls_port() {
        let opts = make_relay_opts_with_engine();
        let target = crate::pt::TargetAddr::Domain("example.com".to_owned());
        let cands =
            select_route_candidates(&opts, &target, 22, "example.com", &EngineConfig::default());
        assert!(
            cands.iter().all(|c| c.kind == RouteKind::Direct),
            "port 22 should only use Direct"
        );
    }
}
