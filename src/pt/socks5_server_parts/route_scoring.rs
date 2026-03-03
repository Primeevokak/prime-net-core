use crate::config::EngineConfig;
use crate::pt::socks5_server::*;

pub fn route_health_score(route_key: &str, candidate: &RouteCandidate, now: u64, cfg: &EngineConfig) -> i64 {
    let route_id = candidate.route_id();
    let mut bonus = 0i64;
    if candidate.kind == RouteKind::Bypass {
        let bucket = host_service_bucket(route_key, cfg);
        bonus += bypass_bucket_bonus(&bucket, candidate, cfg);
    }
    let local_score = {
        let map = DEST_ROUTE_HEALTH.get_or_init(dashmap::DashMap::new);
        if let Some(per_route) = map.get(route_key) {
            if let Some(health) = per_route.get(&route_id) {
                let mut score = (health.successes as i64 * 3) - (health.failures as i64 * 4);
                if health.weak_until_unix > now { score -= 10_000; }
                score
            } else { 0 }
        } else { 0 }
    };
    local_score + global_bypass_profile_score(candidate, now, cfg) + bonus
}

pub fn global_bypass_profile_score(candidate: &RouteCandidate, now: u64, cfg: &EngineConfig) -> i64 {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") { return 0; }
    let primary_key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(dashmap::DashMap::new);
    if let Some(health) = map.get(&primary_key) {
        if should_reset_bypass_profile_health(&health, now, cfg) {
            drop(health); map.remove(&primary_key); return 0;
        }
        return bypass_profile_score_from_health(&health, now, cfg);
    }
    0
}

pub fn bypass_profile_score_from_health(health: &BypassProfileHealth, now: u64, _cfg: &EngineConfig) -> i64 {
    let mut score = (health.successes as i64 * 5) - (health.failures as i64 * 6);
    if health.last_success_unix > 0 && now.saturating_sub(health.last_success_unix) <= 300 { score += 3; }
    score
}

pub fn should_reset_bypass_profile_health(health: &BypassProfileHealth, now: u64, _cfg: &EngineConfig) -> bool {
    health.successes == 0 && health.failures > 20 && now.saturating_sub(health.last_failure_unix) > 600
}

fn bypass_bucket_bonus(bucket: &str, candidate: &RouteCandidate, _cfg: &EngineConfig) -> i64 {
    if candidate.kind != RouteKind::Bypass { return 0; }
    match bucket {
        "meta-group:youtube" | "meta-group:discord" => {
            if candidate.bypass_profile_idx == 1 { 8_000 } else { 4_000 }
        }
        _ => 0,
    }
}

pub fn ordered_route_candidates(route_key: &str, candidates: Vec<RouteCandidate>, cfg: &EngineConfig) -> Vec<RouteCandidate> {
    let now = now_unix_secs();
    let mut filtered = candidates;
    filtered.sort_by(|a, b| {
        let a_score = route_health_score(route_key, a, now, cfg);
        let b_score = route_health_score(route_key, b, now, cfg);
        b_score.cmp(&a_score).then_with(|| a.kind_rank().cmp(&b.kind_rank()))
    });
    filtered
}

pub fn is_censored_domain(route_key: &str, cfg: &EngineConfig) -> bool {
    let raw_bucket = host_service_bucket(route_destination_key(route_key), cfg);
    cfg.routing.censored_groups.keys().any(|g| raw_bucket == *g || raw_bucket == format!("meta-group:{}", g))
}

pub fn route_race_decision(_port: u16, _rk: &str, candidates: &[RouteCandidate], _cfg: &EngineConfig) -> (bool, RouteRaceReason) {
    if candidates.len() < 2 { return (false, RouteRaceReason::SingleCandidate); }
    (true, RouteRaceReason::NoWinner)
}

pub fn record_route_success_sync(route_key: &str, candidate: &RouteCandidate, cfg: &EngineConfig) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    {
        let map = DEST_ROUTE_HEALTH.get_or_init(dashmap::DashMap::new);
        let per_route = map.entry(route_key.to_owned()).or_default();
        let mut health = per_route.entry(route_id.clone()).or_default();
        health.successes += 1; health.consecutive_failures = 0; health.last_success_unix = now;
    }
    record_global_bypass_profile_success_sync(candidate, cfg);
}

pub fn record_route_failure_sync(route_key: &str, candidate: &RouteCandidate, reason: &'static str, cfg: &EngineConfig) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    {
        let map = DEST_ROUTE_HEALTH.get_or_init(dashmap::DashMap::new);
        let per_route = map.entry(route_key.to_owned()).or_default();
        let mut health = per_route.entry(route_id.clone()).or_default();
        health.failures += 1; health.consecutive_failures += 1; health.last_failure_unix = now;
        if health.consecutive_failures >= ROUTE_FAILS_BEFORE_WEAK { health.weak_until_unix = now + 60; }
    }
    record_global_bypass_profile_failure_sync(candidate, reason, now, cfg);
}

pub fn record_global_bypass_profile_success_sync(candidate: &RouteCandidate, _cfg: &EngineConfig) {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") { return; }
    let key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(dashmap::DashMap::new);
    let mut entry = map.entry(key).or_default();
    entry.successes += 1; entry.last_success_unix = now_unix_secs();
}

pub fn record_global_bypass_profile_failure_sync(candidate: &RouteCandidate, reason: &'static str, now: u64, _cfg: &EngineConfig) {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") { return; }
    let key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(dashmap::DashMap::new);
    let mut entry = map.entry(key).or_default();
    entry.failures += 1; entry.last_failure_unix = now;
    if reason == "connect-failed" { entry.connect_failures += 1; }
}

pub fn select_route_candidates(relay_opts: &RelayOptions, target: &crate::pt::TargetAddr, port: u16, destination: &str, cfg: &EngineConfig) -> Vec<RouteCandidate> {
    let mut out = vec![RouteCandidate::direct_with_family("adaptive", route_family_for_target(target))];
    if port == 443 {
        for (addr, idx, total) in select_bypass_candidates(relay_opts, destination, cfg) {
            out.push(RouteCandidate::bypass_with_family("pool", addr, idx, total, route_family_for_target(target)));
        }
    }
    out
}

pub fn host_service_bucket(host: &str, cfg: &EngineConfig) -> String {
    let host = host.to_ascii_lowercase();
    for (group, patterns) in &cfg.routing.censored_groups {
        for p in patterns { if host.contains(p) { return format!("meta-group:{}", group); } }
    }
    host
}

pub fn bypass_profile_health_key(route_id: &str, family: RouteIpFamily) -> String {
    if family == RouteIpFamily::Any { route_id.to_owned() } else { format!("{}|{}", route_id, family.label()) }
}

pub fn select_bypass_candidates(relay_opts: &RelayOptions, _dest: &str, _cfg: &EngineConfig) -> Vec<(std::net::SocketAddr, u8, u8)> {
    let mut out = Vec::new();
    for (i, addr) in relay_opts.bypass_socks5_pool.iter().enumerate() {
        out.push((*addr, i as u8, relay_opts.bypass_socks5_pool.len() as u8));
    }
    out
}

pub fn route_family_for_target(target: &crate::pt::TargetAddr) -> RouteIpFamily {
    match target {
        crate::pt::TargetAddr::Ip(std::net::IpAddr::V4(_)) => RouteIpFamily::V4,
        crate::pt::TargetAddr::Ip(std::net::IpAddr::V6(_)) => RouteIpFamily::V6,
        _ => RouteIpFamily::Any,
    }
}

pub fn mark_route_capability_healthy(kind: RouteKind, family: RouteIpFamily) {
    if family == RouteIpFamily::Any { return; }
    let map = ROUTE_CAPABILITIES.get_or_init(|| std::sync::RwLock::new(RouteCapabilities::default()));
    if let Ok(mut g) = map.write() {
        match (kind, family) {
            (RouteKind::Direct, RouteIpFamily::V4) => g.direct_v4_weak_until = 0,
            (RouteKind::Direct, RouteIpFamily::V6) => g.direct_v6_weak_until = 0,
            (RouteKind::Bypass, RouteIpFamily::V4) => g.bypass_v4_weak_until = 0,
            (RouteKind::Bypass, RouteIpFamily::V6) => g.bypass_v6_weak_until = 0,
            _ => {}
        }
    }
}

pub fn route_capability_is_available(kind: RouteKind, family: RouteIpFamily, now: u64) -> bool {
    if family == RouteIpFamily::Any { return true; }
    let map = ROUTE_CAPABILITIES.get_or_init(|| std::sync::RwLock::new(RouteCapabilities::default()));
    if let Ok(g) = map.read() {
        let until = match (kind, family) {
            (RouteKind::Direct, RouteIpFamily::V4) => g.direct_v4_weak_until,
            (RouteKind::Direct, RouteIpFamily::V6) => g.direct_v6_weak_until,
            (RouteKind::Bypass, RouteIpFamily::V4) => g.bypass_v4_weak_until,
            (RouteKind::Bypass, RouteIpFamily::V6) => g.bypass_v6_weak_until,
            _ => 0,
        };
        now >= until
    } else { true }
}

pub fn route_destination_key(rk: &str) -> &str { rk.split('|').next().unwrap_or(rk) }
pub fn record_bypass_profile_failure(destination: &str, current_idx: u8, total: u8, _reason: &'static str, _cfg: &EngineConfig) {
    if total == 0 { return; }
    let next_idx = (current_idx + 1) % total;
    let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(dashmap::DashMap::new);
    idx_map.insert(destination.to_owned(), next_idx);
}
pub fn record_route_success(_rk: &str, _c: &RouteCandidate, _cfg: &EngineConfig) {}
pub fn record_route_failure(_rk: &str, _c: &RouteCandidate, _r: &'static str, _cfg: &EngineConfig) {}
