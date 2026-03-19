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
        let map = &routing_state().dest_route_health;
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
    let map = &routing_state().global_bypass_profile_health;
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
    {
        let winners = &routing_state().dest_route_winner;
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
    {
        let classifier = &routing_state().dest_classifier;
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

    // Strip port from dest_lower for domain-only lookups (blocklist and bypass check
    // store bare hostnames like "rbc.ru", not "rbc.ru:443").
    let dest_host = dest_lower.split(':').next().unwrap_or(&dest_lower);

    // 2. Check global engine blocklist
    if let Some(bloom) = BLOCKLIST_DOMAINS.get() {
        if bloom.contains_host_or_suffix(dest_host) {
            return true;
        }
    }

    // 3. Custom check function fallback
    if let Some(check_fn) = _relay_opts.bypass_domain_check {
        if check_fn(dest_host) {
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
        let map = &routing_state().dest_route_health;
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
        let map = &routing_state().dest_route_health;
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
    let map = &routing_state().global_bypass_profile_health;
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
    let map = &routing_state().global_bypass_profile_health;
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

    // Native profile pin: skip ML and return exactly the configured profile.
    if let Some(pinned) = select_native_pinned_candidate(destination, relay_opts, cfg, family) {
        out.push(pinned);
        return out;
    }

    if port == 443 || port == 80 || port == 6443 || (5000..=9000).contains(&port) {
        let bypass_cands = select_bypass_candidates(relay_opts, destination, cfg);
        let native_cands = select_native_candidates(relay_opts, destination);

        // ML-rank all native candidates by bandit health score so the profiles the bandit
        // has learned work best enter the first race.  On cold-start every score is 0 and
        // selection falls back to index order — identical to the previous behaviour.
        let route_key = route_destination_key(destination);
        let now = now_unix_secs();
        let mut ranked_native: Vec<RouteCandidate> = native_cands
            .into_iter()
            .map(|(idx, total)| RouteCandidate::native_with_family("engine", idx, total, family))
            .collect();
        ranked_native.sort_by(|a, b| {
            route_health_score(route_key, b, now, cfg)
                .cmp(&route_health_score(route_key, a, now, cfg))
        });

        if is_blocked {
            // PROACTIVE BYPASS: For blocked domains try external bypass FIRST (score 1000),
            // then the top-8 ML-ranked native desync profiles (score 900).
            // Direct is last-resort fallback only.
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
            for cand in ranked_native.into_iter().take(8) {
                out.push(RouteCandidate { score: 900, ..cand });
            }
            // Direct is a very late fallback
            out.push(RouteCandidate {
                score: -10000,
                ..RouteCandidate::direct_with_family("adaptive", family)
            });
        } else {
            // Normal domains: Direct first, then bypass pool, then up to 4 ML-ranked
            // native profiles as backup.
            out.push(RouteCandidate {
                score: 100,
                ..RouteCandidate::direct_with_family("adaptive", family)
            });
            for (addr, idx, total) in bypass_cands {
                out.push(RouteCandidate::bypass_with_family(
                    "pool", addr, idx, total, family,
                ));
            }
            for cand in ranked_native.into_iter().take(4) {
                out.push(cand);
            }
        }
    } else {
        out.push(RouteCandidate::direct_with_family("adaptive", family));
    }
    out
}

/// If `destination` has a `"native:profile_name"` entry in `domain_profiles`, return a
/// pinned [`RouteCandidate`] for exactly that profile, bypassing ML candidate selection.
///
/// Accepts both `"native:profile_name"` (resolved by name) and `"native:N"` (1-based index).
/// Returns `None` if there is no native pin for this destination, or the engine / profile is
/// unavailable.
fn select_native_pinned_candidate(
    destination: &str,
    relay_opts: &RelayOptions,
    cfg: &EngineConfig,
    family: RouteIpFamily,
) -> Option<RouteCandidate> {
    let host = destination
        .split(':')
        .next()
        .unwrap_or(destination)
        .to_ascii_lowercase();

    for (domain, arm) in &cfg.routing.domain_profiles {
        let domain = domain.trim().to_ascii_lowercase();
        if host != domain && !host.ends_with(&format!(".{domain}")) {
            continue;
        }
        let arm = arm.trim();
        let profile_spec = arm.strip_prefix("native:")?;
        let engine = relay_opts.native_bypass.as_ref()?;
        let total = engine.profile_count() as u8;

        // Resolve by profile name first, then by 1-based numeric index.
        let idx = (0..engine.profile_count())
            .find(|&i| engine.profile_name(i) == profile_spec)
            .or_else(|| {
                profile_spec.parse::<usize>().ok().and_then(|n| {
                    let i = n.saturating_sub(1);
                    (i < engine.profile_count()).then_some(i)
                })
            })?;

        return Some(RouteCandidate {
            score: 1000,
            ..RouteCandidate::native_with_family("pinned", idx as u8, total, family)
        });
    }
    None
}

/// Build retry candidates from native profiles that were NOT included in the first race.
///
/// Called after a route race fails entirely.  Returns up to all remaining native profiles
/// as candidates so the caller can attempt a second pass without a full re-race.
pub fn build_native_retry_candidates(
    tried_native_indices: &[u8],
    relay_opts: &RelayOptions,
    family: RouteIpFamily,
) -> Vec<RouteCandidate> {
    let engine = match relay_opts.native_bypass.as_ref() {
        Some(e) => e,
        None => return Vec::new(),
    };
    let tried: std::collections::HashSet<u8> = tried_native_indices.iter().copied().collect();
    let total = engine.profile_count() as u8;
    (0..total)
        .filter(|&i| !tried.contains(&i))
        .map(|i| RouteCandidate {
            score: 500,
            ..RouteCandidate::native_with_family("retry", i, total, family)
        })
        .collect()
}

/// Returns `true` if `destination` has an explicit `"native:..."` pin in `domain_profiles`.
/// Used to suppress automatic profile retries for pinned domains.
pub fn destination_has_native_pin(destination: &str, cfg: &EngineConfig) -> bool {
    let host = destination
        .split(':')
        .next()
        .unwrap_or(destination)
        .to_ascii_lowercase();
    cfg.routing.domain_profiles.iter().any(|(domain, arm)| {
        let domain = domain.trim().to_ascii_lowercase();
        (host == domain || host.ends_with(&format!(".{domain}")))
            && arm.trim().starts_with("native:")
    })
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

/// Returns `true` if the destination host is likely served by Cloudflare.
///
/// Used to exclude `cloudflare_safe: false` native desync profiles that would
/// break connections to these services (disorder, padding, etc.).
fn is_likely_cloudflare_host(dest: &str) -> bool {
    let d = dest.to_ascii_lowercase();
    d.contains("discord")
        || d.contains("cloudflare")
        || d.contains("instagram")
        || d.contains("fbcdn")
        || d.contains("cdninstagram")
        || d.contains("whatsapp")
        || d.contains("fb.com")
        || d.contains("messenger.com")
}

/// Returns `(profile_idx, profile_total)` pairs for the in-process native desync engine.
///
/// When `destination` is a Cloudflare-hosted service, only profiles with
/// `cloudflare_safe: true` are returned.
pub fn select_native_candidates(relay_opts: &RelayOptions, destination: &str) -> Vec<(u8, u8)> {
    match relay_opts.native_bypass.as_ref() {
        Some(engine) => {
            let is_cf = is_likely_cloudflare_host(destination);
            let total = engine.profile_count() as u8;
            (0..total)
                .filter(|&i| !is_cf || engine.is_profile_cloudflare_safe(i as usize))
                .map(|i| (i, total))
                .collect()
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
    let map = &routing_state().route_capabilities;
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
    let map = &routing_state().route_capabilities;
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
    let idx_map = &routing_state().dest_bypass_profile_idx;
    idx_map.insert(destination.to_owned(), next_idx);
}
pub fn record_route_success(rk: &str, c: &RouteCandidate, cfg: &EngineConfig) {
    record_route_success_sync(rk, c, cfg);
}
pub fn record_route_failure(rk: &str, c: &RouteCandidate, r: &'static str, cfg: &EngineConfig) {
    record_route_failure_sync(rk, c, r, cfg);
}

/// TTL (in seconds) for QUIC silent-drop cache entries.
pub(crate) const QUIC_SILENT_DROP_TTL_SECS: u64 = 1800;

/// Returns `true` if `key` (e.g. `"domain.com:443"`) was recently detected as a
/// QUIC silent-drop destination and the entry is still within its TTL.
pub(crate) fn is_quic_silent_drop_cached(key: &str) -> bool {
    routing_state()
        .quic_silent_drop_cache
        .get(key)
        .map(|ts| now_unix_secs().saturating_sub(*ts) < QUIC_SILENT_DROP_TTL_SECS)
        .unwrap_or(false)
}

/// Records `key` as a QUIC silent-drop destination with the current timestamp.
pub(crate) fn record_quic_silent_drop(key: &str) {
    routing_state()
        .quic_silent_drop_cache
        .insert(key.to_owned(), now_unix_secs());
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
        let cands = select_native_candidates(&opts, "example.com");
        assert!(cands.is_empty());
    }

    #[test]
    fn select_native_candidates_returns_all_profiles() {
        let opts = make_relay_opts_with_engine();
        let engine = opts.native_bypass.as_ref().unwrap();
        let total = engine.profile_count();
        let cands = select_native_candidates(&opts, "example.com");
        assert_eq!(cands.len(), total);
        // Each entry: (idx, total)
        for (i, (idx, t)) in cands.iter().enumerate() {
            assert_eq!(*idx as usize, i);
            assert_eq!(*t as usize, total);
        }
    }

    #[test]
    fn cloudflare_host_excludes_unsafe_native_profiles() {
        let opts = make_relay_opts_with_engine();
        let engine = opts.native_bypass.as_ref().unwrap();

        let all = select_native_candidates(&opts, "example.com");
        let cf = select_native_candidates(&opts, "gateway.discord.com");

        // Cloudflare-filtered list should be smaller (some profiles have cloudflare_safe=false)
        assert!(
            cf.len() < all.len(),
            "cloudflare host should have fewer candidates: cf={} all={}",
            cf.len(),
            all.len()
        );

        // All profiles in the cf list must be cloudflare-safe
        for (idx, _total) in &cf {
            assert!(
                engine.is_profile_cloudflare_safe(*idx as usize),
                "profile {} should be cloudflare-safe but was included for discord",
                engine.profile_name(*idx as usize)
            );
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

        // For normal domains: Direct + up to 4 Native (no bypass pool)
        let native_count = cands.iter().filter(|c| c.kind == RouteKind::Native).count();
        assert!(
            native_count > 0 && native_count <= 4,
            "normal domain: up to 4 native candidates, got {}",
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
        let map = &routing_state().global_bypass_profile_health;
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
        let map = &routing_state().global_bypass_profile_health;
        map.remove(&key);

        record_global_bypass_profile_success_sync(&candidate, &EngineConfig::default());

        let successes = map.get(&key).expect("health entry created").successes;
        assert_eq!(successes, 1);
        map.remove(&key);
    }

    #[test]
    fn record_native_failure_increments_global_health() {
        let candidate = RouteCandidate::native_with_family("engine", 4, 12, RouteIpFamily::Any);
        let key = bypass_profile_health_key(&candidate.route_id(), candidate.family);
        let map = &routing_state().global_bypass_profile_health;
        map.remove(&key);

        record_global_bypass_profile_failure_sync(
            &candidate,
            "handshake-io",
            now_unix_secs(),
            &EngineConfig::default(),
        );

        let failures = map.get(&key).expect("health entry created").failures;
        assert_eq!(failures, 1);
        map.remove(&key);
    }

    // ── ML-sort: bandit score influences first-race candidate selection ───────

    /// Seed profile 15 (0-based index 14) with a high global health score, then verify
    /// that `select_route_candidates` for a blocked domain places it in the first 8
    /// candidates rather than excluding it as it would under plain index order.
    #[test]
    fn ml_sorted_candidates_promote_high_score_profile() {
        routing_state().reset();

        let opts = RelayOptions {
            bypass_domain_check: Some(|h| h.contains("censored.example")),
            ..make_relay_opts_with_engine()
        };
        let engine = opts.native_bypass.as_ref().unwrap();
        let total = engine.profile_count();
        // Test only makes sense when there are enough profiles.
        if total < 16 {
            return;
        }

        // Give profile index 14 (native:15) a high global health score.
        let high_idx: u8 = 14;
        let key = format!("native:{}", high_idx + 1);
        routing_state().global_bypass_profile_health.insert(
            key.clone(),
            BypassProfileHealth {
                successes: 50,
                failures: 0,
                last_success_unix: now_unix_secs(),
                ..Default::default()
            },
        );

        let target = crate::pt::TargetAddr::Domain("censored.example.com".to_owned());
        let cands = select_route_candidates(
            &opts,
            &target,
            443,
            "censored.example.com",
            &EngineConfig::default(),
        );

        let native_indices: Vec<u8> = cands
            .iter()
            .filter(|c| c.kind == RouteKind::Native)
            .map(|c| c.bypass_profile_idx)
            .collect();

        assert!(
            native_indices.contains(&high_idx),
            "profile {} should be in the first-race candidates after ML promotion; got {:?}",
            high_idx,
            native_indices
        );

        // Cleanup
        routing_state().global_bypass_profile_health.remove(&key);
        routing_state().reset();
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
