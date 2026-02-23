fn mark_route_capability_weak(
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
    let map = ROUTE_CAPABILITIES.get_or_init(|| Mutex::new(RouteCapabilities::default()));
    if let Ok(mut guard) = map.lock() {
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

fn mark_route_capability_healthy(kind: RouteKind, family: RouteIpFamily) {
    if family == RouteIpFamily::Any {
        return;
    }
    let map = ROUTE_CAPABILITIES.get_or_init(|| Mutex::new(RouteCapabilities::default()));
    if let Ok(mut guard) = map.lock() {
        if let Some(slot) = route_capability_slot_mut(&mut guard, kind, family) {
            *slot = 0;
        }
    }
}

fn should_enable_universal_bypass_domain(host: &str) -> bool {
    if !universal_bypass_domains_enabled() {
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

fn universal_bypass_domains_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("PRIME_PACKET_BYPASS_UNIVERSAL_DOMAINS")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

fn select_bypass_source(
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
            // CRITICAL: Always check if the classifier has learned that this host needs bypass
            if should_bypass_by_classifier_host(host, port) {
                return Some("learned-domain");
            }
            if should_enable_universal_bypass_domain(host) {
                return Some("adaptive-race");
            }
            None
        }
        TargetAddr::Ip(ip) => {
            if should_bypass_by_classifier_ip(*ip, port) {
                return Some("learned-ip");
            }
            if is_bypassable_public_ip(*ip) {
                return Some("adaptive-race");
            }
            None
        }
    }
}

fn select_bypass_candidates(
    relay_opts: &RelayOptions,
    destination: &str,
) -> Vec<(SocketAddr, u8, u8)> {
    if !relay_opts.bypass_socks5_pool.is_empty() {
        let total = relay_opts.bypass_socks5_pool.len().min(255) as u8;
        let preferred = destination_bypass_profile_idx(destination, total);
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

fn select_route_candidates(
    relay_opts: &RelayOptions,
    target: &TargetAddr,
    port: u16,
    destination: &str,
) -> Vec<RouteCandidate> {
    let family = route_family_for_target(target);
    let mut out = vec![RouteCandidate::direct_with_family("adaptive", family)];
    
    // Attempt to determine the bypass source (builtin, learned, or adaptive-race)
    let source = select_bypass_source(relay_opts, target, port).unwrap_or_else(|| {
        // Fallback: If it's port 443 and a public IP, allow adaptive race with bypass
        if port == 443 {
            let is_public = match target {
                TargetAddr::Ip(ip) => is_bypassable_public_ip(*ip),
                TargetAddr::Domain(host) => {
                    if let Some(ip) = parse_ip_literal(host) {
                        is_bypassable_public_ip(ip)
                    } else {
                        true // Assume public domain
                    }
                }
            };
            if is_public {
                return "adaptive-race";
            }
        }
        "none"
    });

    if source != "none" {
        for (addr, idx, total) in select_bypass_candidates(relay_opts, destination) {
            out.push(RouteCandidate::bypass_with_family(
                source, addr, idx, total, family,
            ));
        }
    }
    out
}

fn bypass_profile_health_key(route_id: &str, family: RouteIpFamily) -> String {
    if family == RouteIpFamily::Any {
        route_id.to_owned()
    } else {
        format!("{route_id}|{}", family.label())
    }
}

fn route_health_score(route_key: &str, candidate: &RouteCandidate, now: u64) -> i64 {
    let route_id = candidate.route_id();
    let mut bonus = 0i64;
    
    // Give a significant bonus to bypass routes when they are explicitly requested by blocklist or classifier.
    // This ensures they win the race against direct connections that might succeed at TCP level but fail later.
    if candidate.kind == RouteKind::Bypass {
        match candidate.source {
            "builtin" | "learned-domain" | "learned-ip" => {
                bonus += 1000;
            }
            "adaptive-race" => {
                bonus += 10;
            }
            _ => {}
        }
    }

    let local_score = {
        let map = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
        let Ok(guard) = map.lock() else {
            return global_bypass_profile_score(candidate, now) + bonus;
        };
        let Some(per_route) = guard.get(route_key) else {
            return global_bypass_profile_score(candidate, now) + bonus;
        };
        let Some(health) = per_route.get(&route_id) else {
            return global_bypass_profile_score(candidate, now) + bonus;
        };
        let mut score = (health.successes as i64 * 3) - (health.failures as i64 * 4);
        score -= i64::from(health.consecutive_failures) * 8;
        if health.weak_until_unix > now {
            score -= 10_000;
        }
        score
    };
    local_score + global_bypass_profile_score(candidate, now) + bonus
}

fn bypass_profile_health_last_seen_unix(health: &BypassProfileHealth) -> u64 {
    health.last_success_unix.max(health.last_failure_unix)
}

fn bypass_profile_health_is_empty(health: &BypassProfileHealth) -> bool {
    health.successes == 0
        && health.failures == 0
        && health.connect_failures == 0
        && health.soft_zero_replies == 0
        && health.io_errors == 0
        && health.last_success_unix == 0
        && health.last_failure_unix == 0
}

fn global_bypass_profile_score(candidate: &RouteCandidate, now: u64) -> i64 {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") {
        return 0;
    }
    let primary_key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        if let Some(health) = guard.get(&primary_key) {
            if should_reset_bypass_profile_health(health, now) {
                guard.remove(&primary_key);
                return 0;
            }
            return bypass_profile_score_from_health(health, now);
        }
        if candidate.family != RouteIpFamily::Any {
            if let Some(legacy) = guard.get(&route_id) {
                if should_reset_bypass_profile_health(legacy, now) {
                    guard.remove(&route_id);
                    return 0;
                }
                return bypass_profile_score_from_health(legacy, now);
            }
        }
    }
    0
}

fn bypass_profile_score_from_health(health: &BypassProfileHealth, now: u64) -> i64 {
    let mut score = (health.successes as i64 * 5) - (health.failures as i64 * 6);
    score -= health.connect_failures as i64 * 8;
    score -= health.soft_zero_replies as i64 * 30; // Increased penalty to ban broken profiles faster
    score -= health.io_errors as i64 * 7;
    if health.last_success_unix > 0 && now.saturating_sub(health.last_success_unix) <= 5 * 60 {
        score += 3;
    }
    if health.last_failure_unix > 0 && now.saturating_sub(health.last_failure_unix) <= 90 {
        score -= 4;
    }
    score
}

fn should_reset_bypass_profile_health(health: &BypassProfileHealth, now: u64) -> bool {
    // If it's a "total failure" profile (many errors, zero successes)
    if health.successes == 0 && (health.failures > 20 || health.connect_failures > 10) {
        // Reset if the last failure was more than 10 minutes ago
        if now.saturating_sub(health.last_failure_unix) > 600 {
            return true;
        }
    }
    // If it has extremely low score but hasn't been tried for 30 minutes
    if bypass_profile_score_from_health(health, now) < GLOBAL_BYPASS_HARD_WEAK_SCORE && now.saturating_sub(health.last_failure_unix) > 1800 {
        return true;
    }
    false
}

fn route_is_temporarily_weak(route_key: &str, route_id: &str, now: u64) -> bool {
    let map = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return false;
    };
    guard
        .get(route_key)
        .and_then(|m| m.get(route_id))
        .map(|h| h.weak_until_unix > now)
        .unwrap_or(false)
}

fn route_winner_for_key(route_key: &str) -> Option<RouteWinner> {
    let map = DEST_ROUTE_WINNER.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return None;
    };
    if let Some(winner) = guard.get(route_key).cloned() {
        return Some(winner);
    }
    let service_key = route_service_key(route_key)?;
    guard.get(&service_key).cloned()
}

fn ordered_route_candidates(
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
            // Strictly exclude bypass profiles that are globally failing
            if c.kind == RouteKind::Bypass {
                return global_bypass_profile_score(c, now) > GLOBAL_BYPASS_HARD_WEAK_SCORE;
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
            .then_with(|| a.route_label().cmp(b.route_label()))
    });
    filtered
}

fn route_race_reason_label(reason: RouteRaceReason) -> &'static str {
    match reason {
        RouteRaceReason::NonTlsPort => "non-tls-port",
        RouteRaceReason::SingleCandidate => "single-candidate",
        RouteRaceReason::NoWinner => "no-winner",
        RouteRaceReason::EmptyWinner => "empty-winner",
        RouteRaceReason::WinnerStale => "winner-stale",
        RouteRaceReason::WinnerMissingFromCandidates => "winner-missing-from-candidates",
        RouteRaceReason::WinnerWeak => "winner-weak",
        RouteRaceReason::WinnerHealthy => "winner-healthy",
    }
}

fn route_race_decision(
    port: u16,
    route_key: &str,
    candidates: &[RouteCandidate],
) -> (bool, RouteRaceReason) {
    if port != 443 || candidates.len() < 2 {
        return if port != 443 {
            (false, RouteRaceReason::NonTlsPort)
        } else {
            (false, RouteRaceReason::SingleCandidate)
        };
    }
    let now = now_unix_secs();
    let Some(winner) = route_winner_for_key(route_key) else {
        return (true, RouteRaceReason::NoWinner);
    };
    if winner.route_id.is_empty() {
        return (true, RouteRaceReason::EmptyWinner);
    }
    if now.saturating_sub(winner.updated_at_unix) > ROUTE_WINNER_TTL_SECS {
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

fn with_route_metrics<F>(f: F)
where
    F: FnOnce(&mut RouteMetrics),
{
    if let Ok(mut guard) = ROUTE_METRICS
        .get_or_init(|| Mutex::new(RouteMetrics::default()))
        .lock()
    {
        f(&mut guard);
    }
}

fn record_route_race_decision(race: bool, reason: RouteRaceReason) {
    with_route_metrics(|m| {
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
    });
}

fn record_route_selected(candidate: &RouteCandidate, raced: bool) {
    with_route_metrics(|m| match candidate.kind {
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
    });
}

fn record_route_success(route_key: &str, candidate: &RouteCandidate) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    with_route_metrics(|m| match candidate.kind {
        RouteKind::Direct => m.route_success_direct = m.route_success_direct.saturating_add(1),
        RouteKind::Bypass => m.route_success_bypass = m.route_success_bypass.saturating_add(1),
    });
    let health_map = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = health_map.lock() {
        let per_route = guard.entry(route_key.to_owned()).or_default();
        let entry = per_route.entry(route_id.clone()).or_default();
        entry.successes = entry.successes.saturating_add(1);
        entry.consecutive_failures = 0;
        entry.weak_until_unix = 0;
        entry.last_success_unix = now;
    }
    let winner_map = DEST_ROUTE_WINNER.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = winner_map.lock() {
        let winner = RouteWinner {
            route_id: route_id.clone(),
            updated_at_unix: now,
        };
        guard.insert(route_key.to_owned(), winner.clone());
        if let Some(service_key) = route_service_key(route_key) {
            if service_key != route_key {
                guard.insert(service_key, winner);
            }
        }
    }
    if matches!(candidate.kind, RouteKind::Bypass) {
        record_global_bypass_profile_success(candidate, now);
    }
    mark_route_capability_healthy(candidate.kind, candidate.family);
    info!(
        target: "socks5.route",
        route_key = %route_key,
        route = %route_id,
        "adaptive route marked healthy"
    );
    maybe_flush_classifier_store(false);
}

fn record_route_failure(route_key: &str, candidate: &RouteCandidate, reason: &'static str) {
    let now = now_unix_secs();
    let route_id = candidate.route_id();
    with_route_metrics(|m| match candidate.kind {
        RouteKind::Direct => {
            m.route_failure_direct = m.route_failure_direct.saturating_add(1);
            if reason == "connect-failed" {
                m.connect_failure_direct = m.connect_failure_direct.saturating_add(1);
            }
            if reason == "zero-reply-soft" {
                m.route_soft_zero_reply_direct = m.route_soft_zero_reply_direct.saturating_add(1);
            }
        }
        RouteKind::Bypass => {
            m.route_failure_bypass = m.route_failure_bypass.saturating_add(1);
            if reason == "connect-failed" {
                m.connect_failure_bypass = m.connect_failure_bypass.saturating_add(1);
            }
            if reason == "zero-reply-soft" {
                m.route_soft_zero_reply_bypass = m.route_soft_zero_reply_bypass.saturating_add(1);
            }
        }
    });
    let health_map = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let mut consecutive = 0u8;
    if let Ok(mut guard) = health_map.lock() {
        let per_route = guard.entry(route_key.to_owned()).or_default();
        let entry = per_route.entry(route_id.clone()).or_default();
        entry.failures = entry.failures.saturating_add(1);
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1).min(32);
        if matches!(reason, "zero-reply-soft" | "suspicious-zero-reply")
            && entry.consecutive_failures < ROUTE_FAILS_BEFORE_WEAK
        {
            entry.consecutive_failures = ROUTE_FAILS_BEFORE_WEAK;
        }
        entry.last_failure_unix = now;
        consecutive = entry.consecutive_failures;
        if entry.consecutive_failures >= ROUTE_FAILS_BEFORE_WEAK {
            let penalty = ROUTE_WEAK_BASE_SECS
                .saturating_mul(u64::from(entry.consecutive_failures))
                .min(ROUTE_WEAK_MAX_SECS);
            entry.weak_until_unix = now.saturating_add(penalty);
        }
    }
    if let Ok(mut guard) = DEST_ROUTE_WINNER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    {
        if guard
            .get(route_key)
            .map(|w| w.route_id == route_id)
            .unwrap_or(false)
        {
            guard.remove(route_key);
        }
        if let Some(service_key) = route_service_key(route_key) {
            if service_key != route_key
                && guard
                    .get(&service_key)
                    .map(|w| w.route_id == route_id)
                    .unwrap_or(false)
            {
                guard.remove(&service_key);
            }
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

fn record_global_bypass_profile_success(candidate: &RouteCandidate, now: u64) {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") {
        return;
    }
    let key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        let entry = guard.entry(key).or_default();
        entry.successes = entry.successes.saturating_add(1);
        entry.last_success_unix = now;
        if entry.failures > 0 {
            entry.failures = entry.failures.saturating_sub(1);
        }
        if entry.connect_failures > 0 {
            entry.connect_failures = entry.connect_failures.saturating_sub(1);
        }
        if entry.soft_zero_replies > 0 {
            entry.soft_zero_replies = entry.soft_zero_replies.saturating_sub(1);
        }
        if entry.io_errors > 0 {
            entry.io_errors = entry.io_errors.saturating_sub(1);
        }
    }
}

fn record_global_bypass_profile_failure(
    candidate: &RouteCandidate,
    reason: &'static str,
    now: u64,
) {
    let route_id = candidate.route_id();
    if !route_id.starts_with("bypass:") {
        return;
    }
    let key = bypass_profile_health_key(&route_id, candidate.family);
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        let entry = guard.entry(key).or_default();
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
    }
}

fn destination_bypass_profile_idx(destination: &str, total: u8) -> u8 {
    if total <= 1 {
        return 0;
    }
    let key = bypass_profile_key(destination);
    let legacy_key = bypass_profile_legacy_service_key(destination);
    let map = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        if let Some(v) = guard.get(&key).copied() {
            return v.min(total.saturating_sub(1));
        }
        if legacy_key != key {
            if let Some(v) = guard.get(&legacy_key).copied() {
                let normalized = v.min(total.saturating_sub(1));
                guard.insert(key, normalized);
                return normalized;
            }
        }
    }
    0
}

fn should_mark_bypass_profile_failure(
    port: u16,
    bytes_client_to_bypass: u64,
    bytes_bypass_to_client: u64,
    min_c2u: u64,
) -> bool {
    port == 443 && bytes_bypass_to_client == 0 && bytes_client_to_bypass >= min_c2u
}

fn should_skip_empty_session_scoring(
    bytes_client_to_upstream: u64,
    bytes_upstream_to_client: u64,
) -> bool {
    bytes_client_to_upstream == 0 && bytes_upstream_to_client == 0
}

fn should_mark_route_soft_zero_reply(
    port: u16,
    bytes_client_to_upstream: u64,
    bytes_upstream_to_client: u64,
) -> bool {
    port == 443
        && bytes_upstream_to_client == 0
        && bytes_client_to_upstream >= ROUTE_SOFT_ZERO_REPLY_MIN_C2U
}

fn should_mark_bypass_zero_reply_soft(
    port: u16,
    bytes_client_to_bypass: u64,
    bytes_bypass_to_client: u64,
    session_lifetime_ms: u64,
) -> bool {
    // Only mark as soft failure if the connection stayed open for a while but never got a reply.
    // Short zero-reply sessions are often just connection probes or pre-connects.
    port == 443
        && bytes_bypass_to_client == 0
        && bytes_client_to_bypass >= ROUTE_SOFT_ZERO_REPLY_MIN_C2U
        && session_lifetime_ms >= ROUTE_SOFT_ZERO_REPLY_MIN_LIFETIME_MS
}

fn should_mark_empty_bypass_session_as_soft_failure(candidate: &RouteCandidate, port: u16) -> bool {
    if port != 443 || candidate.kind != RouteKind::Bypass {
        return false;
    }
    
    matches!(
        candidate.source,
        "builtin" | "learned-domain" | "learned-ip"
    )
}

fn record_bypass_profile_failure(
    destination: &str,
    current_idx: u8,
    total: u8,
    reason: &'static str,
) {
    if total == 0 {
        return;
    }
    let key = bypass_profile_key(destination);
    let next_idx = if total > 1 {
        (current_idx + 1) % total
    } else {
        0
    };
    let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = idx_map.lock() {
        guard.insert(key.clone(), next_idx);
    }
    let fail_map = DEST_BYPASS_PROFILE_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let failures = if let Ok(mut guard) = fail_map.lock() {
        let entry = guard.entry(key.clone()).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    } else {
        0
    };
    info!(
        target: "socks5.bypass",
        destination = %destination,
        profile_key = %key,
        reason,
        current_profile = current_idx + 1,
        next_profile = next_idx + 1,
        profiles = total,
        failures,
        "bypass profile rotated for destination"
    );
    maybe_flush_classifier_store(false);
}

fn record_bypass_profile_success(destination: &str, idx: u8) {
    let key = bypass_profile_key(destination);
    let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = idx_map.lock() {
        guard.insert(key.clone(), idx);
    }
    let fail_map = DEST_BYPASS_PROFILE_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = fail_map.lock() {
        if let Some(entry) = guard.get_mut(&key) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                guard.remove(&key);
            }
        }
    }
    maybe_flush_classifier_store(false);
}

fn bypass_profile_key(destination: &str) -> String {
    route_state_key(destination)
}

fn bypass_profile_legacy_service_key(destination: &str) -> String {
    if let Some((host, port)) = split_host_port_for_connect(destination) {
        let normalized_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if !normalized_host.is_empty() {
            if let Some(ip) = parse_ip_literal(&normalized_host) {
                return format!("{ip}:{port}");
            }
            let service_bucket = host_service_bucket(&normalized_host);
            return format!("{service_bucket}:{port}");
        }
    }
    destination.trim().to_ascii_lowercase()
}

fn host_service_bucket(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    if labels.len() < 2 {
        return host.to_owned();
    }
    let tld = labels[labels.len() - 1];
    let sld = labels[labels.len() - 2];
    if labels.len() >= 3
        && tld.len() == 2
        && matches!(sld, "co" | "com" | "net" | "org" | "gov" | "edu" | "ac")
    {
        return labels[labels.len() - 3].to_owned();
    }
    sld.to_owned()
}

fn should_bypass_by_classifier_host(host: &str, port: u16) -> bool {
    if port != 443 {
        return false;
    }
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return false;
    }
    if let Some(ip) = parse_ip_literal(host) {
        return should_bypass_by_classifier_ip(ip, port);
    }

    let destination = format!("{host}:{port}");
    let key = bypass_profile_key(&destination);
    if destination_failures(&key) >= LEARNED_BYPASS_MIN_FAILURES_DOMAIN {
        return true;
    }

    false
}

fn should_bypass_by_classifier_ip(ip: std::net::IpAddr, port: u16) -> bool {
    if port != 443 || !is_bypassable_public_ip(ip) {
        return false;
    }
    let key = format!("{ip}:{port}");
    destination_failures(&key) >= LEARNED_BYPASS_MIN_FAILURES_IP
}

fn is_bypassable_public_ip(ip: std::net::IpAddr) -> bool {
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

fn learned_bypass_threshold(destination: &str) -> Option<u8> {
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
