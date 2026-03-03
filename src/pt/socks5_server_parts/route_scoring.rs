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

pub fn is_censored_domain(domain: &str, relay_opts: &RelayOptions, cfg: &EngineConfig) -> bool {
    let dest_lower = domain.to_lowercase();

    // 1. Check global engine blocklist
    if let Some(lock) = BLOCKLIST_DOMAINS.get() {
        if let Ok(set) = lock.read() {
            if set.contains(&dest_lower) {
                return true;
            }
            // Subdomain check (e.g., test.discord.com -> discord.com)
            for (idx, byte) in dest_lower.as_bytes().iter().enumerate() {
                if *byte == b'.' {
                    let suffix = &dest_lower[idx + 1..];
                    if set.contains(suffix) {
                        return true;
                    }
                }
            }
        }
    }

    // 2. Check if the runtime provided a custom check function (antifilter list fallback)
    if let Some(check_fn) = relay_opts.bypass_domain_check {
        if check_fn(domain) {
            return true;
        }
    }

    // 3. Check config groups
    let raw_bucket = host_service_bucket(route_destination_key(domain), cfg);
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
    
    // NUCLEAR PENALTY: If we get a Connection Reset (10054), it's a strong DPI signal.
    // We immediately mark this profile as weak for this domain group.
    let is_reset = reason.contains("reset") || reason.contains("10054") || reason.contains("BrokenPipe");
    
    {
        let map = DEST_ROUTE_HEALTH.get_or_init(dashmap::DashMap::new);
        let per_route = map.entry(route_key.to_owned()).or_default();
        let mut health = per_route.entry(route_id.clone()).or_default();
        health.failures += 1;
        health.consecutive_failures += 1;
        health.last_failure_unix = now;
        
        if is_reset || health.consecutive_failures >= ROUTE_FAILS_BEFORE_WEAK {
            // Mark as weak for 5 minutes (300s) on reset, or 60s on normal failure
            let penalty_secs = if is_reset { 300 } else { 60 };
            health.weak_until_unix = now + penalty_secs;
            
            // If it's a reset on a bypass profile, force a rotation for the whole domain group
            if is_reset && candidate.kind == RouteKind::Bypass {
                record_bypass_profile_failure(route_key, candidate.bypass_profile_idx, candidate.bypass_profile_total, reason, cfg);
            }
        }
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
    let mut out = Vec::new();
    let is_blocked = is_censored_domain(destination, relay_opts, cfg);
    let family = route_family_for_target(target);

    if port == 443 || port == 80 || port == 6443 || (port >= 5000 && port <= 9000) { // Add Discord/Game ports
        let bypass_cands = select_bypass_candidates(relay_opts, destination, cfg);
        
        if is_blocked {
            // For known blocked domains, use ONLY Bypass routes OR give Bypass a huge head start.
            let mut count = 0;
            for (addr, idx, total) in bypass_cands {
                out.push(RouteCandidate {
                    score: 100, // High priority
                    ..RouteCandidate::bypass_with_family("pool", addr, idx, total, family)
                });
                count += 1;
                if count >= 4 { break; } // Limit to 4 parallel bypass attempts for efficiency
            }
            // Direct is a very late fallback
            out.push(RouteCandidate {
                score: -1000, // Massive handicap
                ..RouteCandidate::direct_with_family("adaptive", family)
            });
        } else {
            // Normal domains: Direct first, then Bypass as backup
            out.push(RouteCandidate {
                score: 100,
                ..RouteCandidate::direct_with_family("adaptive", family)
            });
            for (addr, idx, total) in bypass_cands {
                out.push(RouteCandidate::bypass_with_family("pool", addr, idx, total, family));
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

pub fn route_destination_key(rk: &str) -> &str {
    let host = rk.split('|').next().unwrap_or(rk);
    let host = host.split(':').next().unwrap_or(host);
    
    // Group subdomains for high-traffic services to share route winners
    if host.ends_with(".googlevideo.com") { return "googlevideo.com"; }
    if host.ends_with(".ytimg.com") { return "ytimg.com"; }
    if host.ends_with(".ggpht.com") { return "ggpht.com"; }
    if host.ends_with(".googleusercontent.com") { return "googleusercontent.com"; }
    if host.ends_with(".discord.gg") { return "discord.gg"; }
    if host.ends_with(".discordapp.com") { return "discordapp.com"; }
    if host.ends_with(".discord.com") { return "discord.com"; }
    if host.ends_with(".sndcdn.com") { return "sndcdn.com"; } // SoundCloud
    if host.ends_with(".soundcloud.com") { return "soundcloud.com"; }
    if host.ends_with(".instagram.com") { return "instagram.com"; }
    if host.ends_with(".cdninstagram.com") { return "cdninstagram.com"; }
    if host.ends_with(".facebook.com") { return "facebook.com"; }
    if host.ends_with(".fbcdn.net") { return "fbcdn.net"; }
    
    host
}
pub fn record_bypass_profile_failure(destination: &str, current_idx: u8, total: u8, _reason: &'static str, _cfg: &EngineConfig) {
    if total == 0 { return; }
    let next_idx = (current_idx + 1) % total;
    let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(dashmap::DashMap::new);
    idx_map.insert(destination.to_owned(), next_idx);
}
pub fn record_route_success(_rk: &str, _c: &RouteCandidate, _cfg: &EngineConfig) {}
pub fn record_route_failure(_rk: &str, _c: &RouteCandidate, _r: &'static str, _cfg: &EngineConfig) {}
