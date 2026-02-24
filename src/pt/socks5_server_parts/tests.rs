#[cfg(test)]
mod tests {
    use super::*;

    fn clear_route_state_for_test(route_key: &str) {
        let service_key = route_service_key(route_key);
        if let Ok(mut guard) = DEST_ROUTE_HEALTH
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.remove(route_key);
            if let Some(service_key) = service_key.as_ref() {
                guard.remove(service_key);
            }
        }
        if let Ok(mut guard) = DEST_ROUTE_WINNER
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.remove(route_key);
            if let Some(service_key) = service_key.as_ref() {
                guard.remove(service_key);
            }
        }
    }

    fn clear_global_bypass_health_for_test() {
        if let Ok(mut guard) = GLOBAL_BYPASS_PROFILE_HEALTH
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.clear();
        }
    }

    fn clear_bypass_profile_state_for_test() {
        if let Ok(mut guard) = DEST_BYPASS_PROFILE_IDX
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.clear();
        }
        if let Ok(mut guard) = DEST_BYPASS_PROFILE_FAILURES
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.clear();
        }
    }

    fn clear_route_capabilities_for_test() {
        if let Ok(mut guard) = ROUTE_CAPABILITIES
            .get_or_init(|| Mutex::new(RouteCapabilities::default()))
            .lock()
        {
            *guard = RouteCapabilities::default();
        }
    }

    #[test]
    fn connect_target_rejects_empty_host() {
        assert!(split_host_port_for_connect(":443").is_none());
        assert!(split_host_port_for_connect("[]:443").is_none());
    }

    #[test]
    fn connect_target_rejects_invalid_port() {
        assert!(split_host_port_for_connect("example.com:notaport").is_none());
    }

    #[test]
    fn host_header_rejects_invalid_port() {
        assert!(split_host_port_with_default("example.com:notaport", 80).is_none());
    }

    #[test]
    fn host_header_rejects_empty_bracketed_host() {
        assert!(split_host_port_with_default("[]:80", 80).is_none());
    }

    #[test]
    fn parse_http_forward_target_rejects_bad_host_header() {
        let req = "GET / HTTP/1.1\r\nHost: example.com:notaport\r\n\r\n";
        assert!(parse_http_forward_target("/", req).is_none());
    }

    #[test]
    fn parse_http_forward_target_normalizes_ipv6_host_header() {
        let req = "GET /api HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n";
        let parsed = parse_http_forward_target("/api", req).expect("parsed");
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.request_uri, "/api");
    }

    #[test]
    fn parse_http_forward_target_normalizes_ipv6_absolute_uri() {
        let req = "GET http://[2001:db8::2]:8000/v1?q=1 HTTP/1.1\r\n\r\n";
        let parsed =
            parse_http_forward_target("http://[2001:db8::2]:8000/v1?q=1", req).expect("parsed");
        assert_eq!(parsed.host, "2001:db8::2");
        assert_eq!(parsed.port, 8000);
        assert_eq!(parsed.request_uri, "/v1?q=1");
    }

    #[test]
    fn parse_ip_literal_accepts_bracketed_ipv6() {
        assert_eq!(
            parse_ip_literal("[2001:db8::3]").map(|ip| ip.to_string()),
            Some("2001:db8::3".to_owned())
        );
    }

    #[test]
    fn route_decision_key_is_family_aware_for_ip_targets() {
        let key_v4 = route_decision_key(
            "149.154.167.50:443",
            &TargetAddr::Ip("149.154.167.50".parse().expect("ip")),
        );
        let key_v6 = route_decision_key(
            "2001:67c:4e8:f002::a:443",
            &TargetAddr::Ip("2001:67c:4e8:f002::a".parse().expect("ip")),
        );
        assert_ne!(key_v4, key_v6);
        assert!(key_v4.ends_with("|v4"));
        assert!(key_v6.ends_with("|v6"));
    }

    #[test]
    fn route_decision_key_is_host_specific_for_domains() {
        let key_api = route_decision_key(
            "api.github.com:443",
            &TargetAddr::Domain("api.github.com".to_owned()),
        );
        let key_collector = route_decision_key(
            "collector.github.com:443",
            &TargetAddr::Domain("collector.github.com".to_owned()),
        );
        assert_ne!(key_api, key_collector);
        assert!(key_api.starts_with("api.github.com:443|"));
        assert!(key_collector.starts_with("collector.github.com:443|"));
    }

    #[test]
    fn route_service_key_groups_subdomains_by_registrable_domain() {
        let api_key = route_decision_key(
            "rr2---sn-gvnuxaxjvh-88vs.googlevideo.com:443",
            &TargetAddr::Domain("rr2---sn-gvnuxaxjvh-88vs.googlevideo.com".to_owned()),
        );
        let collector_key = route_decision_key(
            "rr3---sn-gvnuxaxjvh-88vz.googlevideo.com:443",
            &TargetAddr::Domain("rr3---sn-gvnuxaxjvh-88vz.googlevideo.com".to_owned()),
        );
        let api_service = route_service_key(&api_key).expect("service key");
        let collector_service = route_service_key(&collector_key).expect("service key");
        assert_eq!(api_service, collector_service);
        assert!(api_service.starts_with("googlevideo.com:443|"));
    }

    #[test]
    fn adaptive_route_skips_race_when_service_winner_is_healthy() {
        let winner_route_key = route_decision_key(
            "rr2---sn-gvnuxaxjvh-88vs.googlevideo.com:443",
            &TargetAddr::Domain("rr2---sn-gvnuxaxjvh-88vs.googlevideo.com".to_owned()),
        );
        let probe_route_key = route_decision_key(
            "rr3---sn-gvnuxaxjvh-88vz.googlevideo.com:443",
            &TargetAddr::Domain("rr3---sn-gvnuxaxjvh-88vz.googlevideo.com".to_owned()),
        );
        clear_route_state_for_test(&winner_route_key);
        clear_route_state_for_test(&probe_route_key);
        let service_key = route_service_key(&winner_route_key).expect("service key");
        if let Ok(mut guard) = DEST_ROUTE_WINNER
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.insert(
                service_key,
                RouteWinner {
                    route_id: "bypass:1".to_owned(),
                    updated_at_unix: now_unix_secs(),
                },
            );
        }
        let candidates = vec![
            RouteCandidate::direct("test"),
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1),
        ];
        let decision = route_race_decision(443, &probe_route_key, &candidates);
        assert_eq!(decision, (false, RouteRaceReason::WinnerHealthy));
        clear_route_state_for_test(&winner_route_key);
        clear_route_state_for_test(&probe_route_key);
    }

    #[test]
    fn bypass_zero_reply_soft_requires_meaningful_payload_and_lifetime() {
        assert!(!should_mark_bypass_zero_reply_soft(443, 1, 0, 5_000));
        assert!(!should_mark_bypass_zero_reply_soft(
            443,
            ROUTE_SOFT_ZERO_REPLY_MIN_C2U - 1,
            0,
            5_000
        ));
        assert!(!should_mark_bypass_zero_reply_soft(
            443,
            ROUTE_SOFT_ZERO_REPLY_MIN_C2U,
            0,
            ROUTE_SOFT_ZERO_REPLY_MIN_LIFETIME_MS - 1
        ));
        assert!(should_mark_bypass_zero_reply_soft(
            443,
            ROUTE_SOFT_ZERO_REPLY_MIN_C2U,
            0,
            ROUTE_SOFT_ZERO_REPLY_MIN_LIFETIME_MS
        ));
        assert!(!should_mark_bypass_zero_reply_soft(443, 500, 5, 5_000));
        assert!(!should_mark_bypass_zero_reply_soft(80, 500, 0, 5_000));
    }

    #[test]
    fn empty_bypass_soft_failure_is_limited_to_blocking_sensitive_sources() {
        let builtin =
            RouteCandidate::bypass("builtin", "127.0.0.1:19080".parse().expect("addr"), 0, 3);
        let learned = RouteCandidate::bypass(
            "learned-domain",
            "127.0.0.1:19081".parse().expect("addr"),
            1,
            3,
        );
        let adaptive = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19082".parse().expect("addr"),
            2,
            3,
        );
        let direct = RouteCandidate::direct("adaptive");
        assert!(should_mark_empty_bypass_session_as_soft_failure(
            &builtin, 443
        ));
        assert!(should_mark_empty_bypass_session_as_soft_failure(
            &learned, 443
        ));
        assert!(!should_mark_empty_bypass_session_as_soft_failure(
            &adaptive, 443
        ));
        assert!(!should_mark_empty_bypass_session_as_soft_failure(&direct, 443));
        assert!(!should_mark_empty_bypass_session_as_soft_failure(
            &builtin, 80
        ));
    }

    #[test]
    fn empty_session_scoring_is_skipped_only_for_zero_zero_traffic() {
        assert!(should_skip_empty_session_scoring(0, 0));
        assert!(!should_skip_empty_session_scoring(1, 0));
        assert!(!should_skip_empty_session_scoring(0, 1));
        assert!(!should_skip_empty_session_scoring(5, 7));
    }

    #[test]
    fn learned_bypass_activates_after_failures_for_tls_domain() {
        let key = "learned-bypass-test.invalid:443".to_owned();
        let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
        {
            let mut guard = map.lock().expect("lock failures map");
            guard.insert(key.clone(), LEARNED_BYPASS_MIN_FAILURES_DOMAIN);
        }

        assert!(should_bypass_by_classifier_host(
            "learned-bypass-test.invalid",
            443
        ));
        assert!(!should_bypass_by_classifier_host("127.0.0.1", 443));
        assert!(!should_bypass_by_classifier_host(
            "learned-bypass-test.invalid",
            80
        ));

        {
            let mut guard = map.lock().expect("lock failures map");
            guard.remove(&key);
        }
    }

    #[test]
    fn learned_bypass_activates_for_public_ip_but_not_loopback() {
        let pub_key = "79.133.169.98:443".to_owned();
        let loopback_key = "127.0.0.1:443".to_owned();
        let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
        {
            let mut guard = map.lock().expect("lock failures map");
            guard.insert(pub_key.clone(), LEARNED_BYPASS_MIN_FAILURES_IP);
            guard.insert(loopback_key.clone(), LEARNED_BYPASS_MIN_FAILURES_IP);
        }

        assert!(should_bypass_by_classifier_ip(
            "79.133.169.98".parse().expect("ip"),
            443
        ));
        assert!(!should_bypass_by_classifier_ip(
            "127.0.0.1".parse().expect("ip"),
            443
        ));

        {
            let mut guard = map.lock().expect("lock failures map");
            guard.remove(&pub_key);
            guard.remove(&loopback_key);
        }
    }

    #[test]
    fn bypass_profile_rotation_is_host_specific() {
        clear_bypass_profile_state_for_test();
        record_bypass_profile_failure("api.github.com:443", 0, 3, "unit-test");
        assert_eq!(destination_bypass_profile_idx("api.github.com:443", 3), 1);
        assert_eq!(
            destination_bypass_profile_idx("collector.github.com:443", 3),
            0
        );
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn bypass_profile_index_uses_legacy_service_key_fallback() {
        clear_bypass_profile_state_for_test();
        let service_key = bypass_profile_legacy_service_key("api.github.com:443");
        if let Ok(mut guard) = DEST_BYPASS_PROFILE_IDX
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.insert(service_key, 2);
        }
        assert_eq!(
            destination_bypass_profile_idx("collector.github.com:443", 3),
            2
        );
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn adaptive_route_candidates_include_bypass_for_public_tls_domain() {
        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec![
                "127.0.0.1:19080".parse().expect("addr"),
                "127.0.0.1:19081".parse().expect("addr"),
            ],
            bypass_domain_check: Some(|host| host == "service.example.com"),
            ..RelayOptions::default()
        };
        let candidates = select_route_candidates(
            &relay_opts,
            &TargetAddr::Domain("service.example.com".to_owned()),
            443,
            "service.example.com:443",
        );
        assert_eq!(candidates.len(), 3);
        assert!(candidates.iter().any(|c| c.kind == RouteKind::Direct));
        assert_eq!(
            candidates
                .iter()
                .filter(|c| c.kind == RouteKind::Bypass)
                .count(),
            2
        );
    }

    #[test]
    fn route_capability_filter_skips_temporarily_weak_ipv6_bypass() {
        clear_route_capabilities_for_test();
        mark_route_capability_weak(
            RouteKind::Bypass,
            RouteIpFamily::V6,
            "unit-test",
            ROUTE_CAPABILITY_BYPASS_REP03_SECS,
        );
        let route_key = "capability-filter-test:443|v6";
        let candidates = vec![
            RouteCandidate::direct_with_family("test", RouteIpFamily::V6),
            RouteCandidate::bypass_with_family(
                "test",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                1,
                RouteIpFamily::V6,
            ),
        ];
        let ordered = ordered_route_candidates(route_key, candidates);
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].route_id(), "direct");
        clear_route_capabilities_for_test();
    }

    #[test]
    fn adaptive_route_weakens_and_recovers_after_cooldown() {
        let route_key = "adaptive-route-test:443";
        clear_route_state_for_test(route_key);
        let candidate =
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1);
        record_route_failure(route_key, &candidate, "unit-failure");
        record_route_failure(route_key, &candidate, "unit-failure");
        assert!(route_is_temporarily_weak(
            route_key,
            &candidate.route_id(),
            now_unix_secs()
        ));

        if let Ok(mut guard) = DEST_ROUTE_HEALTH
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            if let Some(per_route) = guard.get_mut(route_key) {
                if let Some(entry) = per_route.get_mut(&candidate.route_id()) {
                    entry.weak_until_unix = now_unix_secs().saturating_sub(1);
                }
            }
        }
        assert!(!route_is_temporarily_weak(
            route_key,
            &candidate.route_id(),
            now_unix_secs()
        ));

        record_route_success(route_key, &candidate);
        let winner = route_winner_for_key(route_key).expect("winner");
        assert_eq!(winner.route_id, candidate.route_id());
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn adaptive_route_reraces_when_cached_winner_is_unavailable() {
        let route_key = "adaptive-route-missing-winner:443";
        clear_route_state_for_test(route_key);
        if let Ok(mut guard) = DEST_ROUTE_WINNER
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.insert(
                route_key.to_owned(),
                RouteWinner {
                    route_id: "bypass:3".to_owned(),
                    updated_at_unix: now_unix_secs(),
                },
            );
        }

        let candidates = vec![
            RouteCandidate::direct("test"),
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1),
        ];
        assert_eq!(
            route_race_decision(443, route_key, &candidates),
            (true, RouteRaceReason::WinnerMissingFromCandidates)
        );
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn adaptive_route_skips_race_when_cached_winner_is_healthy() {
        let route_key = "adaptive-route-healthy-winner:443";
        clear_route_state_for_test(route_key);
        if let Ok(mut guard) = DEST_ROUTE_WINNER
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.insert(
                route_key.to_owned(),
                RouteWinner {
                    route_id: "direct".to_owned(),
                    updated_at_unix: now_unix_secs(),
                },
            );
        }
        let candidates = vec![
            RouteCandidate::direct("test"),
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1),
        ];
        let decision = route_race_decision(443, route_key, &candidates);
        assert_eq!(decision, (false, RouteRaceReason::WinnerHealthy));
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn snapshot_last_seen_uses_route_state_timestamps() {
        let mut entry = ClassifierSnapshotEntry {
            stats: DestinationClassifier {
                last_seen_unix: 9,
                ..DestinationClassifier::default()
            },
            ..ClassifierSnapshotEntry::default()
        };
        entry.route_winner = Some(RouteWinner {
            route_id: "direct".to_owned(),
            updated_at_unix: 13,
        });
        entry.route_health.insert(
            "direct".to_owned(),
            RouteHealth {
                last_failure_unix: 17,
                ..RouteHealth::default()
            },
        );

        assert_eq!(snapshot_entry_last_seen_unix(&entry), 17);
    }

    #[test]
    fn soft_zero_reply_marks_tls_no_reply_with_client_hello_sized_payload() {
        assert!(should_mark_route_soft_zero_reply(443, 517, 0));
        assert!(!should_mark_route_soft_zero_reply(443, 200, 0));
        assert!(!should_mark_route_soft_zero_reply(443, 517, 1));
        assert!(!should_mark_route_soft_zero_reply(80, 517, 0));
    }

    #[test]
    fn route_soft_zero_reply_immediately_sets_weak_cooldown() {
        let route_key = "adaptive-route-soft-zero:443";
        clear_route_state_for_test(route_key);
        let candidate =
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1);
        record_route_failure(route_key, &candidate, "zero-reply-soft");
        assert!(route_is_temporarily_weak(
            route_key,
            &candidate.route_id(),
            now_unix_secs()
        ));
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn global_bypass_health_reorders_profiles_without_service_rules() {
        clear_global_bypass_health_for_test();
        let now = now_unix_secs();
        if let Ok(mut guard) = GLOBAL_BYPASS_PROFILE_HEALTH
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.insert(
                "bypass:1".to_owned(),
                BypassProfileHealth {
                    failures: 5,
                    connect_failures: 2,
                    last_failure_unix: now,
                    ..BypassProfileHealth::default()
                },
            );
            guard.insert(
                "bypass:2".to_owned(),
                BypassProfileHealth {
                    successes: 6,
                    last_success_unix: now,
                    ..BypassProfileHealth::default()
                },
            );
        }
        let route_key = "global-bypass-health:443";
        clear_route_state_for_test(route_key);
        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                2,
            ),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19081".parse().expect("addr"),
                1,
                2,
            ),
        ];
        let ordered = ordered_route_candidates(route_key, candidates);
        let pos1 = ordered
            .iter()
            .position(|c| c.route_id() == "bypass:1")
            .expect("bypass:1 present");
        let pos2 = ordered
            .iter()
            .position(|c| c.route_id() == "bypass:2")
            .expect("bypass:2 present");
        assert!(pos2 < pos1);
        clear_global_bypass_health_for_test();
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn route_order_prefers_direct_when_scores_are_equal() {
        clear_global_bypass_health_for_test();
        let route_key = "route-order-direct-first:443";
        clear_route_state_for_test(route_key);
        let candidates = vec![
            RouteCandidate::direct("test"),
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1),
        ];
        let ordered = ordered_route_candidates(route_key, candidates);
        assert_eq!(
            ordered.first().map(|c| c.route_id()),
            Some("direct".to_owned())
        );
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn route_race_delays_bypass_when_direct_is_present() {
        let direct = RouteCandidate::direct("adaptive");
        let bypass =
            RouteCandidate::bypass("builtin", "127.0.0.1:19080".parse().expect("addr"), 0, 1);
        let bypass_adaptive = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19081".parse().expect("addr"),
            0,
            1,
        );
        assert_eq!(route_race_candidate_delay_ms(0, &direct, true), 0);
        assert_eq!(
            route_race_candidate_delay_ms(1, &bypass, true),
            ROUTE_RACE_BASE_DELAY_MS
                + ROUTE_RACE_DIRECT_HEADSTART_MS
                + ROUTE_RACE_BYPASS_EXTRA_DELAY_BUILTIN_MS
        );
        assert_eq!(
            route_race_candidate_delay_ms(1, &bypass_adaptive, true),
            ROUTE_RACE_BASE_DELAY_MS
                + ROUTE_RACE_DIRECT_HEADSTART_MS
                + ROUTE_RACE_BYPASS_EXTRA_DELAY_MS
        );
        assert_eq!(
            route_race_candidate_delay_ms(1, &bypass, false),
            ROUTE_RACE_BASE_DELAY_MS
        );
    }

    #[test]
    fn route_race_launch_order_prioritizes_direct_candidates() {
        let bypass_first =
            RouteCandidate::bypass("builtin", "127.0.0.1:19080".parse().expect("addr"), 0, 2);
        let direct = RouteCandidate::direct("adaptive");
        let bypass_second = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19081".parse().expect("addr"),
            1,
            2,
        );
        let ordered = vec![bypass_first.clone(), direct.clone(), bypass_second.clone()];

        let launch = route_race_launch_candidates(&ordered);
        // NEW: Now we respect the ordered list exactly.
        assert_eq!(launch[0].route_id(), bypass_first.route_id());
        assert_eq!(launch[1].route_id(), direct.route_id());
        assert_eq!(launch[2].route_id(), bypass_second.route_id());
    }

    #[test]
    fn route_race_launch_candidates_are_capped() {
        let direct = RouteCandidate::direct("adaptive");
        let bypass_1 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19080".parse().expect("addr"), 0, 4);
        let bypass_2 = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19081".parse().expect("addr"),
            1,
            4,
        );
        let bypass_3 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19082".parse().expect("addr"), 2, 4);
        let bypass_4 =
            RouteCandidate::bypass("learned-domain", "127.0.0.1:19083".parse().expect("addr"), 3, 4);
        let ordered = vec![
            direct.clone(),
            bypass_1.clone(),
            bypass_2.clone(),
            bypass_3,
            bypass_4,
        ];

        let launch = route_race_launch_candidates(&ordered);
        // NEW: Max capped at ROUTE_RACE_MAX_CANDIDATES (usually 3 or 4)
        assert_eq!(launch.len(), ROUTE_RACE_MAX_CANDIDATES);
        assert_eq!(launch[0].route_id(), direct.route_id());
        assert_eq!(launch[1].route_id(), bypass_1.route_id());
        assert_eq!(launch[2].route_id(), bypass_2.route_id());
    }

    #[test]
    fn hard_weak_global_bypass_profiles_are_pruned_when_healthier_exists() {
        clear_global_bypass_health_for_test();
        let now = now_unix_secs();
        if let Ok(mut guard) = GLOBAL_BYPASS_PROFILE_HEALTH
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
        {
            guard.insert(
                "bypass:1".to_owned(),
                BypassProfileHealth {
                    successes: 5,
                    last_success_unix: now,
                    ..BypassProfileHealth::default()
                },
            );
            guard.insert(
                "bypass:2".to_owned(),
                BypassProfileHealth {
                    failures: 40,
                    connect_failures: 20,
                    soft_zero_replies: 20,
                    last_failure_unix: now,
                    ..BypassProfileHealth::default()
                },
            );
        }
        let route_key = "hard-weak-prune:443";
        clear_route_state_for_test(route_key);
        let candidates = vec![
            RouteCandidate::direct("test"),
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 2),
            RouteCandidate::bypass("test", "127.0.0.1:19081".parse().expect("addr"), 1, 2),
        ];
        let ordered = ordered_route_candidates(route_key, candidates);
        assert!(ordered.iter().any(|c| c.route_id() == "bypass:1"));
        assert!(!ordered.iter().any(|c| c.route_id() == "bypass:2"));
        clear_route_state_for_test(route_key);
        clear_global_bypass_health_for_test();
    }

    #[test]
    fn direct_sinkhole_dns_errors_do_not_penalize_route_health() {
        let route_key = "direct-sinkhole-ignore:443";
        clear_route_state_for_test(route_key);
        let candidate = RouteCandidate::direct("test");
        let err = EngineError::InvalidInput(
            "dns resolver returned only unspecified/sinkhole IPs for 'blocked.example'".to_owned(),
        );
        assert!(should_ignore_route_failure(&candidate, &err));
        assert!(!route_is_temporarily_weak(
            route_key,
            &candidate.route_id(),
            now_unix_secs()
        ));
        clear_route_state_for_test(route_key);
    }
}
