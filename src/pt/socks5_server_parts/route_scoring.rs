use super::*;

pub(super) fn route_health_score(route_key: &str, candidate: &RouteCandidate, now: u64) -> i64 {
    let route_id = candidate.route_id();
    let mut bonus = 0i64;

    if candidate.kind == RouteKind::Bypass {
        match candidate.source {
            "builtin" | "learned-domain" | "learned-ip" => {
                bonus += 5000;
            }
            _ => {}
        }

        let bucket = host_service_bucket(route_key);
        if bucket == "meta-group:discord" || bucket == "meta-group:youtube" {
            let is_failing = {
                let map = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
                map.get(route_key)
                    .and_then(|m| {
                        m.get(&candidate.route_id())
                            .map(|h| h.consecutive_failures >= 3)
                    })
                    .unwrap_or(false)
            };
            if !is_failing {
                bonus += bypass_bucket_bonus(&bucket, candidate);
            }
        }
    }

    let local_score = {
        let map = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
        if let Some(per_route) = map.get(route_key) {
            if let Some(health) = per_route.get(&route_id) {
                let mut score = (health.successes as i64 * 3) - (health.failures as i64 * 4);
                score -= i64::from(health.consecutive_failures) * 8;
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

    local_score + global_bypass_profile_score(candidate, now) + bonus
}

pub(super) fn global_bypass_profile_score(candidate: &RouteCandidate, now: u64) -> i64 {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") {
        return 0;
    }
    let primary_key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);

    if let Some(health) = map.get(&primary_key) {
        if should_reset_bypass_profile_health(&health, now) {
            drop(health);
            map.remove(&primary_key);
            return 0;
        }
        return bypass_profile_score_from_health(&health, now);
    }

    if candidate.family != RouteIpFamily::Any {
        if let Some(legacy) = map.get(&route_id) {
            if should_reset_bypass_profile_health(&legacy, now) {
                drop(legacy);
                map.remove(&route_id);
                return 0;
            }
            return bypass_profile_score_from_health(&legacy, now);
        }
    }
    0
}

pub(super) fn bypass_profile_score_from_health(health: &BypassProfileHealth, now: u64) -> i64 {
    let mut score = (health.successes as i64 * 5) - (health.failures as i64 * 6);
    score -= health.connect_failures as i64 * 8;
    score -= health.soft_zero_replies as i64 * 30;
    score -= health.io_errors as i64 * 25;
    if health.last_success_unix > 0 && now.saturating_sub(health.last_success_unix) <= 5 * 60 {
        score += 3;
    }
    if health.last_failure_unix > 0 && now.saturating_sub(health.last_failure_unix) <= 90 {
        score -= 4;
    }
    score
}

pub(super) fn should_reset_bypass_profile_health(health: &BypassProfileHealth, now: u64) -> bool {
    if health.successes == 0
        && (health.failures > 20 || health.connect_failures > 10)
        && now.saturating_sub(health.last_failure_unix) > 600
    {
        return true;
    }
    if bypass_profile_score_from_health(health, now) < GLOBAL_BYPASS_HARD_WEAK_SCORE
        && now.saturating_sub(health.last_failure_unix) > 1800
    {
        return true;
    }
    false
}

fn bypass_profile_matches_bucket_preference(bucket: &str, candidate: &RouteCandidate) -> bool {
    if candidate.kind != RouteKind::Bypass {
        return false;
    }
    match bucket {
        // Discord profiles are ordered by conservativeness. Keep preferring the first
        // two profiles, prioritizing profile #2 on Windows (disorder+fake style).
        "meta-group:discord" => {
            if candidate.bypass_profile_total <= 1 {
                return candidate.bypass_profile_idx == 0;
            }
            candidate.bypass_profile_idx <= 1
        }
        // YouTube is usually most stable with the split+disorder profile first,
        // but keep one fallback profile to avoid getting stuck.
        "meta-group:youtube" => {
            candidate.bypass_profile_total > 0 && candidate.bypass_profile_idx <= 1
        }
        _ => false,
    }
}

fn bypass_bucket_bonus(bucket: &str, candidate: &RouteCandidate) -> i64 {
    if candidate.kind != RouteKind::Bypass {
        return 0;
    }
    match bucket {
        // Prefer profile #2 for Discord if available, keep profile #1 as fallback.
        "meta-group:discord" => {
            if candidate.bypass_profile_total <= 1 {
                return if candidate.bypass_profile_idx == 0 {
                    8_000
                } else {
                    0
                };
            }
            if candidate.bypass_profile_idx == 1 {
                8_000
            } else if candidate.bypass_profile_idx == 0 {
                4_000
            } else {
                0
            }
        }
        // Prefer profile #1 for YouTube (split+disorder), keep #2 as fallback.
        "meta-group:youtube" => {
            if candidate.bypass_profile_idx == 0 {
                8_000
            } else if candidate.bypass_profile_idx == 1 {
                3_000
            } else {
                0
            }
        }
        _ => 0,
    }
}

pub(super) fn route_is_temporarily_weak(route_key: &str, route_id: &str, now: u64) -> bool {
    let map = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
    map.get(route_key)
        .and_then(|m| m.get(route_id).map(|h| h.weak_until_unix > now))
        .unwrap_or(false)
}

pub(super) fn route_winner_for_key(route_key: &str) -> Option<RouteWinner> {
    let map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
    if let Some(winner) = map.get(route_key) {
        return Some(winner.clone());
    }
    if let Some(service_key) = route_service_key(route_key) {
        if let Some(winner) = map.get(&service_key) {
            return Some(winner.clone());
        }
    }
    if let Some(meta_key) = route_meta_service_key(route_key) {
        if let Some(winner) = map.get(&meta_key) {
            return Some(winner.clone());
        }
    }
    None
}

pub(super) fn ordered_route_candidates(
    route_key: &str,
    candidates: Vec<RouteCandidate>,
) -> Vec<RouteCandidate> {
    let now = now_unix_secs();
    let winner = route_winner_for_key(route_key);

    let mut filtered: Vec<RouteCandidate> = candidates
        .iter()
        .filter(|c| route_capability_is_available(c.kind, c.family, now))
        .filter(|c| !route_is_temporarily_weak(route_key, &c.route_id(), now))
        .filter(|c| {
            if c.kind == RouteKind::Bypass {
                let score = global_bypass_profile_score(c, now);
                if score > GLOBAL_BYPASS_HARD_WEAK_SCORE {
                    return true;
                }

                // Keep the currently cached winner in the candidate set even when its
                // global profile score temporarily dips. Otherwise a transient global
                // downgrade can force a direct-only decision for this destination.
                if winner
                    .as_ref()
                    .map(|w| w.route_id == c.route_id())
                    .unwrap_or(false)
                {
                    return true;
                }

                let bucket = host_service_bucket(route_key);
                if bypass_profile_matches_bucket_preference(&bucket, c) {
                    return true;
                }
                return false;
            }
            true
        })
        .cloned()
        .collect();

    if filtered.is_empty() {
        filtered = candidates;
    }

    let has_healthy_bypass = filtered.iter().any(|candidate| {
        candidate.kind == RouteKind::Bypass
            && global_bypass_profile_score(candidate, now) > GLOBAL_BYPASS_HARD_WEAK_SCORE
    });

    if has_healthy_bypass {
        filtered.retain(|candidate| {
            if candidate.kind != RouteKind::Bypass {
                return true;
            }
            global_bypass_profile_score(candidate, now) > GLOBAL_BYPASS_HARD_WEAK_SCORE
        });
    }

    filtered.sort_by(|a, b| {
        let a_id = a.route_id();
        let b_id = b.route_id();
        let a_winner = winner.as_ref().map(|w| w.route_id == a_id).unwrap_or(false);
        let b_winner = winner.as_ref().map(|w| w.route_id == b_id).unwrap_or(false);
        if a_winner != b_winner {
            return if a_winner {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }
        let a_score = route_health_score(route_key, a, now);
        let b_score = route_health_score(route_key, b, now);

        b_score
            .cmp(&a_score)
            .then_with(|| a.kind_rank().cmp(&b.kind_rank()))
            .then_with(|| a.route_label().cmp(&b.route_label()))
    });
    filtered
}

pub(super) fn route_race_decision(
    port: u16,
    route_key: &str,
    candidates: &[RouteCandidate],
) -> (bool, RouteRaceReason) {
    const META_DIRECT_WINNER_TTL_SECS: u64 = 5;
    if port != 443 || candidates.len() < 2 {
        return if port != 443 {
            (false, RouteRaceReason::NonTlsPort)
        } else {
            (false, RouteRaceReason::SingleCandidate)
        };
    }
    let now = now_unix_secs();

    if let Some(winner_cand) = candidates.first() {
        if winner_cand.kind == RouteKind::Bypass
            && (winner_cand.source == "learned-domain" || winner_cand.source == "learned-ip")
            && route_key.contains("meta-group:")
        {
            let score = route_health_score(route_key, winner_cand, now);
            if score > 10000 {
                return (false, RouteRaceReason::WinnerHealthy);
            }
        }
    }

    let Some(winner) = route_winner_for_key(route_key) else {
        return (true, RouteRaceReason::NoWinner);
    };
    if winner.route_id.is_empty() {
        return (true, RouteRaceReason::EmptyWinner);
    }
    let winner_ttl_secs = if winner.route_id == "direct"
        && matches!(
            host_service_bucket(route_key).as_str(),
            "meta-group:youtube" | "meta-group:discord"
        ) {
        META_DIRECT_WINNER_TTL_SECS
    } else {
        ROUTE_WINNER_TTL_SECS
    };
    if now.saturating_sub(winner.updated_at_unix) > winner_ttl_secs {
        return (true, RouteRaceReason::WinnerStale);
    }
    if !candidates.iter().any(|c| c.route_id() == winner.route_id) {
        return (true, RouteRaceReason::WinnerMissingFromCandidates);
    }
    if route_is_temporarily_weak(route_key, &winner.route_id, now) {
        return (true, RouteRaceReason::WinnerWeak);
    }
    (false, RouteRaceReason::WinnerHealthy)
}

pub(super) fn record_route_success(route_key: &str, candidate: &RouteCandidate) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    let service_key = route_service_key(route_key);
    let meta_key = route_meta_service_key(route_key);

    let health_map = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
    let per_route = health_map.entry(route_key.to_owned()).or_default();
    let mut entry = per_route.entry(route_id.clone()).or_default();
    entry.successes = entry.successes.saturating_add(1);
    entry.consecutive_failures = 0;
    entry.weak_until_unix = 0;
    entry.last_success_unix = now;
    drop(entry);
    drop(per_route);

    let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
    let winner = RouteWinner {
        route_id: route_id.clone(),
        updated_at_unix: now,
    };
    winner_map.insert(route_key.to_owned(), winner.clone());
    if let Some(service_key) = service_key.as_ref() {
        if service_key != route_key {
            winner_map.insert(service_key.clone(), winner.clone());
        }
    }
    if let Some(meta_key) = meta_key.as_ref() {
        if meta_key != route_key && service_key.as_ref().map(|s| s != meta_key).unwrap_or(true) {
            winner_map.insert(meta_key.clone(), winner);
        }
    }

    if matches!(candidate.kind, RouteKind::Bypass) {
        record_global_bypass_profile_success(candidate, now);
    }
    if let Ok(mut m) = ROUTE_METRICS
        .get_or_init(|| RwLock::new(RouteMetrics::default()))
        .write()
    {
        match candidate.kind {
            RouteKind::Direct => {
                m.route_success_direct = m.route_success_direct.saturating_add(1);
            }
            RouteKind::Bypass => {
                m.route_success_bypass = m.route_success_bypass.saturating_add(1);
            }
        }
    }
    mark_route_capability_healthy(candidate.kind, candidate.family);
    debug!(
        target: "socks5.route",
        route_key = %route_key,
        route = %route_id,
        "adaptive route marked healthy"
    );
    maybe_flush_classifier_store(false);
}

pub(super) fn record_route_failure(
    route_key: &str,
    candidate: &RouteCandidate,
    reason: &'static str,
) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    let service_key = route_service_key(route_key);
    let meta_key = route_meta_service_key(route_key);

    let health_map = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
    let per_route = health_map.entry(route_key.to_owned()).or_default();
    let mut entry = per_route.entry(route_id.clone()).or_default();
    entry.failures = entry.failures.saturating_add(1);
    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1).min(32);
    if matches!(reason, "zero-reply-soft" | "suspicious-zero-reply")
        && entry.consecutive_failures < 2
    {
        entry.consecutive_failures = 2;
    }
    entry.last_failure_unix = now;
    let consecutive = entry.consecutive_failures;
    if entry.consecutive_failures >= ROUTE_FAILS_BEFORE_WEAK {
        let penalty = ROUTE_WEAK_BASE_SECS
            .saturating_mul(u64::from(entry.consecutive_failures))
            .min(ROUTE_WEAK_MAX_SECS);
        entry.weak_until_unix = now.saturating_add(penalty);
    }
    drop(entry);

    if let Some(service_key) = service_key.as_ref() {
        if service_key != route_key {
            let per_route_service = health_map.entry(service_key.clone()).or_default();
            let mut entry_service = per_route_service.entry(route_id.clone()).or_default();
            entry_service.failures = entry_service.failures.saturating_add(1);
            entry_service.consecutive_failures =
                entry_service.consecutive_failures.saturating_add(1).min(32);
            entry_service.last_failure_unix = now;
        }
    }
    if let Some(meta_key) = meta_key.as_ref() {
        if meta_key != route_key && service_key.as_ref().map(|s| s != meta_key).unwrap_or(true) {
            let per_route_meta = health_map.entry(meta_key.clone()).or_default();
            let mut entry_meta = per_route_meta.entry(route_id.clone()).or_default();
            entry_meta.failures = entry_meta.failures.saturating_add(1);
            entry_meta.consecutive_failures =
                entry_meta.consecutive_failures.saturating_add(1).min(32);
            entry_meta.last_failure_unix = now;
        }
    }
    drop(per_route);

    let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
    if winner_map
        .get(route_key)
        .map(|w| w.route_id == route_id)
        .unwrap_or(false)
    {
        winner_map.remove(route_key);
    }
    if let Some(service_key) = service_key.as_ref() {
        if winner_map
            .get(service_key)
            .map(|w| w.route_id == route_id)
            .unwrap_or(false)
        {
            winner_map.remove(service_key);
        }
    }
    if let Some(meta_key) = meta_key.as_ref() {
        if winner_map
            .get(meta_key)
            .map(|w| w.route_id == route_id)
            .unwrap_or(false)
        {
            winner_map.remove(meta_key);
        }
    }

    if matches!(candidate.kind, RouteKind::Bypass) {
        record_global_bypass_profile_failure(candidate, reason, now);
        if reason == "zero-reply-soft" && candidate.bypass_profile_total > 1 {
            record_bypass_profile_failure(
                route_destination_key(route_key),
                candidate.bypass_profile_idx,
                candidate.bypass_profile_total,
                "route-soft-zero-reply",
            );
        }
    }
    if let Ok(mut m) = ROUTE_METRICS
        .get_or_init(|| RwLock::new(RouteMetrics::default()))
        .write()
    {
        match candidate.kind {
            RouteKind::Direct => {
                m.route_failure_direct = m.route_failure_direct.saturating_add(1);
                if reason == "connect-failed" {
                    m.connect_failure_direct = m.connect_failure_direct.saturating_add(1);
                }
                if matches!(reason, "zero-reply-soft" | "suspicious-zero-reply") {
                    m.route_soft_zero_reply_direct =
                        m.route_soft_zero_reply_direct.saturating_add(1);
                }
            }
            RouteKind::Bypass => {
                m.route_failure_bypass = m.route_failure_bypass.saturating_add(1);
                if reason == "connect-failed" {
                    m.connect_failure_bypass = m.connect_failure_bypass.saturating_add(1);
                }
                if matches!(reason, "zero-reply-soft" | "suspicious-zero-reply") {
                    m.route_soft_zero_reply_bypass =
                        m.route_soft_zero_reply_bypass.saturating_add(1);
                }
            }
        }
    }
    warn!(
        target: "socks5.route",
        route_key = %route_key,
        route = %route_id,
        reason,
        consecutive_failures = consecutive,
        "adaptive route marked weak"
    );
    maybe_flush_classifier_store(false);
}

pub(super) fn record_global_bypass_profile_success(candidate: &RouteCandidate, now: u64) {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") {
        return;
    }
    let key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
    let mut entry = map.entry(key).or_default();
    entry.successes = entry.successes.saturating_add(1);
    entry.last_success_unix = now;
    entry.failures = entry.failures.saturating_sub(1);
    entry.connect_failures = entry.connect_failures.saturating_sub(1);
    entry.soft_zero_replies = entry.soft_zero_replies.saturating_sub(1);
    entry.io_errors = entry.io_errors.saturating_sub(1);
    maybe_prune_runtime_classifier_state(now);
}

pub(super) fn record_global_bypass_profile_failure(
    candidate: &RouteCandidate,
    reason: &'static str,
    now: u64,
) {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") {
        return;
    }
    let key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
    let mut entry = map.entry(key).or_default();
    entry.failures = entry.failures.saturating_add(1);
    entry.last_failure_unix = now;
    if reason == "connect-failed" {
        entry.connect_failures = entry.connect_failures.saturating_add(1);
    }
    if matches!(reason, "zero-reply-soft" | "suspicious-zero-reply") {
        entry.soft_zero_replies = entry.soft_zero_replies.saturating_add(1);
    }
    if reason == "io-error" {
        entry.io_errors = entry.io_errors.saturating_add(1);
    }
    maybe_prune_runtime_classifier_state(now);
}

pub(super) fn select_route_candidates(
    relay_opts: &RelayOptions,
    target: &TargetAddr,
    port: u16,
    destination: &str,
) -> Vec<RouteCandidate> {
    let destination_key = route_destination_key(destination);
    let host_lower = split_host_port_for_connect(destination_key)
        .map(|(host, _)| host.trim().trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_else(|| destination_key.to_ascii_lowercase());
    let is_noise = host_lower == "localhost"
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".lan")
        || host_lower.contains("msftconnecttest")
        || host_lower.contains("msftncsi")
        || host_lower.contains("kaspersky")
        || host_lower.contains("mullvad.net")
        || host_lower.contains("adguard.org");

    if is_noise {
        return vec![RouteCandidate::direct_with_family(
            "noise-bypass",
            RouteIpFamily::Any,
        )];
    }

    let family = route_family_for_target(target);
    let mut out = vec![RouteCandidate::direct_with_family("adaptive", family)];

    let source = select_bypass_source(relay_opts, target, port).unwrap_or("none");

    if source != "none" {
        for (addr, idx, total) in select_bypass_candidates(relay_opts, destination_key) {
            out.push(RouteCandidate::bypass_with_family(
                source, addr, idx, total, family,
            ));
        }
    }
    out
}

pub(super) fn host_service_bucket(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    if host.contains("discord")
        || host.contains("discordapp")
        || host.contains("discord.gg")
        || host.contains("discord.media")
        || host.contains("discord-attachments")
    {
        return "meta-group:discord".to_owned();
    }
    if host.contains("youtube")
        || host.contains("ytimg")
        || host.contains("googlevideo")
        || host.contains("ggpht")
        || host.contains("youtube-nocookie")
    {
        return "meta-group:youtube".to_owned();
    }
    if host.contains("google")
        || host.contains("gstatic")
        || host.contains("googleapis")
        || host.contains("googleusercontent")
        || host.contains("google-analytics")
    {
        return "meta-group:google".to_owned();
    }
    if host.contains("microsoft")
        || host.contains("windowsupdate")
        || host.contains("aka.ms")
        || host.contains("live.com")
        || host.contains("office")
        || host.contains("outlook")
        || host.contains("s-microsoft")
    {
        return "meta-group:microsoft".to_owned();
    }
    if host.contains("spotify") || host.contains("scdn.co") {
        return "meta-group:spotify".to_owned();
    }

    registrable_domain_bucket(&host).unwrap_or(host)
}

pub(super) fn destination_bypass_profile_idx_known(destination: &str, total: u8) -> Option<u8> {
    if total <= 1 {
        return Some(0);
    }
    let key = bypass_profile_key(destination);
    let map = DEST_BYPASS_PROFILE_IDX.get_or_init(DashMap::new);
    if let Some(v) = map.get(&key) {
        return Some((*v).min(total.saturating_sub(1)));
    }
    let legacy_key = bypass_profile_legacy_service_key(destination);
    if legacy_key != key {
        if let Some(v) = map.get(&legacy_key) {
            let normalized = (*v).min(total.saturating_sub(1));
            map.insert(key, normalized);
            return Some(normalized);
        }
    }
    if let Some(meta_key) = bypass_profile_meta_service_key(destination) {
        if meta_key != key && meta_key != legacy_key {
            if let Some(v) = map.get(&meta_key) {
                let normalized = (*v).min(total.saturating_sub(1));
                map.insert(key, normalized);
                return Some(normalized);
            }
        }
    }
    None
}

pub(super) fn record_route_connected(route_key: &str, candidate: &RouteCandidate) {
    // Do not pre-pin adaptive bypass winners: TCP connect can succeed while
    // TLS still gets blocked, which causes temporary route stickiness.
    if candidate.kind == RouteKind::Bypass && candidate.source == "adaptive-race" {
        return;
    }
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    let service_key = route_service_key(route_key);
    let meta_key = route_meta_service_key(route_key);
    let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
    let winner = RouteWinner {
        route_id,
        updated_at_unix: now,
    };
    winner_map.insert(route_key.to_owned(), winner.clone());
    if let Some(service_key) = service_key.as_ref() {
        if service_key != route_key {
            winner_map.insert(service_key.clone(), winner.clone());
        }
    }
    if let Some(meta_key) = meta_key.as_ref() {
        if meta_key != route_key && service_key.as_ref().map(|s| s != meta_key).unwrap_or(true) {
            winner_map.insert(meta_key.clone(), winner);
        }
    }
}

#[cfg(test)]
pub(super) fn destination_bypass_profile_idx(destination: &str, total: u8) -> u8 {
    destination_bypass_profile_idx_known(destination, total).unwrap_or(0)
}

pub(super) fn record_bypass_profile_failure(
    destination: &str,
    current_idx: u8,
    total: u8,
    reason: &'static str,
) {
    if total == 0 {
        return;
    }
    let key = bypass_profile_key(destination);
    let service_key = bypass_profile_legacy_service_key(destination);
    let meta_key = bypass_profile_meta_service_key(destination);
    let next_idx = if total > 1 {
        (current_idx + 1) % total
    } else {
        0
    };
    let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(DashMap::new);
    idx_map.insert(key.clone(), next_idx);
    if service_key != key {
        idx_map.insert(service_key.clone(), next_idx);
    }
    if let Some(meta_key) = meta_key.as_ref() {
        if meta_key != &key && meta_key != &service_key {
            idx_map.insert(meta_key.clone(), next_idx);
        }
    }
    let fail_map = DEST_BYPASS_PROFILE_FAILURES.get_or_init(DashMap::new);
    let mut entry = fail_map.entry(key.clone()).or_insert(0);
    *entry = entry.saturating_add(1);
    let failures = *entry;
    drop(entry);
    if service_key != key {
        let mut s_entry = fail_map.entry(service_key).or_insert(0);
        *s_entry = s_entry.saturating_add(1);
    }
    if let Some(meta_key) = meta_key {
        if meta_key != key && meta_key != bypass_profile_legacy_service_key(destination) {
            let mut m_entry = fail_map.entry(meta_key).or_insert(0);
            *m_entry = m_entry.saturating_add(1);
        }
    }
    note_phase2_profile_rotation(destination);
    info!(target: "socks5.bypass", destination, profile_key = %key, reason, next_profile = next_idx + 1, failures, "bypass profile rotated");
    maybe_flush_classifier_store(false);
}

pub(super) fn should_bypass_by_classifier_host(host: &str, port: u16) -> bool {
    if port != 443 {
        return false;
    }
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".local") || host.contains("adguard.org") {
        return false;
    }
    let key = bypass_profile_key(&format!("{host}:{port}"));
    let map = DEST_FAILURES.get_or_init(DashMap::new);
    map.get(&key).map(|r| *r).unwrap_or(0) >= LEARNED_BYPASS_MIN_FAILURES_DOMAIN
}

pub(super) fn should_bypass_by_classifier_ip(ip: std::net::IpAddr, port: u16) -> bool {
    if port != 443 || !is_bypassable_public_ip(ip) {
        return false;
    }
    let key = format!("{ip}:{port}");
    let map = DEST_FAILURES.get_or_init(DashMap::new);
    map.get(&key).map(|r| *r).unwrap_or(0) >= LEARNED_BYPASS_MIN_FAILURES_IP
}

pub(super) fn is_bypassable_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unicast_link_local()
                && !v6.is_unique_local()
                && !v6.is_multicast()
                && !v6.is_unspecified()
        }
    }
}

pub(super) fn bypass_profile_health_key(route_id: &str, family: RouteIpFamily) -> String {
    if family == RouteIpFamily::Any {
        route_id.to_owned()
    } else {
        format!("{route_id}|{}", family.label())
    }
}

pub(super) fn bypass_profile_key(destination: &str) -> String {
    route_state_key(route_destination_key(destination))
}

pub(super) fn bypass_profile_legacy_service_key(destination: &str) -> String {
    let destination = route_destination_key(destination);
    if let Some((host, port)) = split_host_port_for_connect(destination) {
        let normalized_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if !normalized_host.is_empty() {
            if let Some(ip) = parse_ip_literal(&normalized_host) {
                return format!("{ip}:{port}");
            }
            let service_bucket =
                registrable_domain_bucket(&normalized_host).unwrap_or(normalized_host);
            return format!("{service_bucket}:{port}");
        }
    }
    destination.trim().to_ascii_lowercase()
}

pub(super) fn bypass_profile_meta_service_key(destination: &str) -> Option<String> {
    let destination = route_destination_key(destination);
    let (host, port) = split_host_port_for_connect(destination)?;
    let normalized_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized_host.is_empty() || parse_ip_literal(&normalized_host).is_some() {
        return None;
    }
    let bucket = host_service_bucket(&normalized_host);
    if !bucket.starts_with("meta-group:") {
        return None;
    }
    Some(format!("{bucket}:{port}"))
}

pub(super) fn bypass_profile_health_is_empty(health: &BypassProfileHealth) -> bool {
    health.successes == 0
        && health.failures == 0
        && health.connect_failures == 0
        && health.soft_zero_replies == 0
        && health.io_errors == 0
        && health.last_success_unix == 0
        && health.last_failure_unix == 0
}

pub(super) fn bypass_profile_health_last_seen_unix(health: &BypassProfileHealth) -> u64 {
    health.last_success_unix.max(health.last_failure_unix)
}

pub(super) fn learned_bypass_threshold(destination: &str) -> Option<u8> {
    let (host, port) = split_host_port_for_connect(destination)?;
    if port != 443 {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_bypassable_public_ip(ip) {
            return Some(LEARNED_BYPASS_MIN_FAILURES_IP);
        }
        return None;
    }
    Some(LEARNED_BYPASS_MIN_FAILURES_DOMAIN)
}

pub(super) fn select_bypass_source(
    relay_opts: &RelayOptions,
    target: &TargetAddr,
    port: u16,
) -> Option<&'static str> {
    if port != 443 {
        return None;
    }
    match target {
        TargetAddr::Domain(host) => {
            if let Some(ip) = parse_ip_literal(host) {
                if should_bypass_by_classifier_ip(ip, port) {
                    return Some("learned-ip");
                }
                if is_bypassable_public_ip(ip) {
                    return Some("adaptive-race");
                }
                return None;
            }
            if let Some(check_fn) = relay_opts.bypass_domain_check {
                if check_fn(host) {
                    return Some("builtin");
                }
            }
            if should_bypass_by_classifier_host(host, port) {
                return Some("learned-domain");
            }
            if should_enable_universal_bypass_domain(host) {
                return Some("adaptive-race");
            }
            if should_prefer_adaptive_bypass_for_host(host) {
                return Some("adaptive-race");
            }
            None
        }
        TargetAddr::Ip(ip) => {
            if let Some(check_fn) = relay_opts.bypass_domain_check {
                if check_fn(&ip.to_string()) {
                    return Some("builtin");
                }
            }
            if should_bypass_by_classifier_ip(*ip, port) {
                return Some("learned-ip");
            }
            if is_bypassable_public_ip(*ip) && should_prefer_adaptive_bypass_for_ip(*ip) {
                return Some("adaptive-race");
            }
            None
        }
    }
}

fn should_prefer_adaptive_bypass_for_host(host: &str) -> bool {
    let bucket = host_service_bucket(host);
    matches!(
        bucket.as_str(),
        "meta-group:youtube" | "meta-group:discord" | "meta-group:google"
    )
}

fn should_prefer_adaptive_bypass_for_ip(_ip: std::net::IpAddr) -> bool {
    false
}

pub(super) fn select_bypass_candidates(
    relay_opts: &RelayOptions,
    destination: &str,
) -> Vec<(SocketAddr, u8, u8)> {
    if !relay_opts.bypass_socks5_pool.is_empty() {
        let total = relay_opts.bypass_socks5_pool.len().min(255) as u8;
        let preferred =
            destination_bypass_profile_idx_known(destination, total).unwrap_or_else(|| {
                (NEXT_BYPASS_POOL_IDX.fetch_add(1, Ordering::Relaxed) % u64::from(total)) as u8
            });
        let mut out = Vec::with_capacity(total as usize);
        for offset in 0..total {
            let idx = (preferred + offset) % total;
            out.push((relay_opts.bypass_socks5_pool[idx as usize], idx, total));
        }
        return out;
    }
    relay_opts
        .bypass_socks5
        .map(|addr| vec![(addr, 0, 1)])
        .unwrap_or_default()
}

pub(super) fn mark_route_capability_weak(
    kind: RouteKind,
    family: RouteIpFamily,
    reason: &'static str,
    penalty_secs: u64,
) {
    if family == RouteIpFamily::Any {
        return;
    }
    let now = now_unix_secs();
    let until = now.saturating_add(penalty_secs);
    let map = ROUTE_CAPABILITIES.get_or_init(|| RwLock::new(RouteCapabilities::default()));
    if let Ok(mut guard) = map.write() {
        if let Some(slot) = route_capability_slot_mut(&mut guard, kind, family) {
            *slot = (*slot).max(until);
        }
    }
    warn!(
        target: "socks5.route",
        route = match kind {
            RouteKind::Direct => "direct",
            RouteKind::Bypass => "bypass",
        },
        family = family.label(),
        reason,
        weak_for_secs = penalty_secs,
        "route capability temporarily downgraded"
    );
}

pub(super) fn mark_route_capability_healthy(kind: RouteKind, family: RouteIpFamily) {
    if family == RouteIpFamily::Any {
        return;
    }
    let map = ROUTE_CAPABILITIES.get_or_init(|| RwLock::new(RouteCapabilities::default()));
    if let Ok(mut guard) = map.write() {
        if let Some(slot) = route_capability_slot_mut(&mut guard, kind, family) {
            *slot = 0;
        }
    }
}

pub(super) fn record_route_race_decision(race: bool, reason: RouteRaceReason) {
    if let Ok(mut m) = ROUTE_METRICS
        .get_or_init(|| RwLock::new(RouteMetrics::default()))
        .write()
    {
        if race {
            m.race_started = m.race_started.saturating_add(1);
        } else {
            m.race_skipped = m.race_skipped.saturating_add(1);
        }
        match reason {
            RouteRaceReason::NonTlsPort => {
                m.race_reason_non_tls = m.race_reason_non_tls.saturating_add(1)
            }
            RouteRaceReason::SingleCandidate => {
                m.race_reason_single_candidate = m.race_reason_single_candidate.saturating_add(1)
            }
            RouteRaceReason::NoWinner => {
                m.race_reason_no_winner = m.race_reason_no_winner.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::EmptyWinner => {
                m.race_reason_empty_winner = m.race_reason_empty_winner.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::WinnerStale => {
                m.race_reason_winner_stale = m.race_reason_winner_stale.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::WinnerMissingFromCandidates => {
                m.race_reason_winner_missing = m.race_reason_winner_missing.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::WinnerWeak => {
                m.race_reason_winner_weak = m.race_reason_winner_weak.saturating_add(1);
                m.winner_cache_misses = m.winner_cache_misses.saturating_add(1);
            }
            RouteRaceReason::WinnerHealthy => {
                m.race_reason_winner_healthy = m.race_reason_winner_healthy.saturating_add(1);
                m.winner_cache_hits = m.winner_cache_hits.saturating_add(1);
            }
        }
    }
}

pub(super) fn record_route_selected(candidate: &RouteCandidate, raced: bool) {
    if let Ok(mut m) = ROUTE_METRICS
        .get_or_init(|| RwLock::new(RouteMetrics::default()))
        .write()
    {
        match candidate.kind {
            RouteKind::Direct => {
                m.route_selected_direct = m.route_selected_direct.saturating_add(1);
                if raced {
                    m.race_winner_direct = m.race_winner_direct.saturating_add(1);
                }
            }
            RouteKind::Bypass => {
                m.route_selected_bypass = m.route_selected_bypass.saturating_add(1);
                if raced {
                    m.race_winner_bypass = m.race_winner_bypass.saturating_add(1);
                }
            }
        }
    }
}

pub(super) fn should_enable_universal_bypass_domain(host: &str) -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let enabled = *ENABLED.get_or_init(|| {
        std::env::var("PRIME_PACKET_BYPASS_UNIVERSAL_DOMAINS")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    });
    if !enabled {
        return false;
    }
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host == "localhost" || host.ends_with(".local") {
        return false;
    }
    if parse_ip_literal(&host).is_some() {
        return false;
    }
    host.contains('.')
}
