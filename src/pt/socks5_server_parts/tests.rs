use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_route_state_for_test(route_key: &str) {
        let service_key = route_service_key(route_key);
        let meta_key = route_meta_service_key(route_key);
        let health_map = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
        health_map.remove(route_key);
        if let Some(service_key) = service_key.as_ref() {
            health_map.remove(service_key);
        }
        if let Some(meta_key) = meta_key.as_ref() {
            health_map.remove(meta_key);
        }

        let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        winner_map.remove(route_key);
        if let Some(service_key) = service_key.as_ref() {
            winner_map.remove(service_key);
        }
        if let Some(meta_key) = meta_key.as_ref() {
            winner_map.remove(meta_key);
        }
    }

    fn clear_global_bypass_health_for_test() {
        let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
        map.clear();
    }

    fn clear_bypass_profile_state_for_test() {
        let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(DashMap::new);
        idx_map.clear();
        let fail_map = DEST_BYPASS_PROFILE_FAILURES.get_or_init(DashMap::new);
        fail_map.clear();
    }

    fn clear_route_capabilities_for_test() {
        let map = ROUTE_CAPABILITIES.get_or_init(|| RwLock::new(RouteCapabilities::default()));
        if let Ok(mut guard) = map.write() {
            *guard = RouteCapabilities::default();
        }
    }

    fn ml_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn clear_destination_classifier_state_for_test() {
        DEST_FAILURES.get_or_init(DashMap::new).clear();
        DEST_PREFERRED_STAGE.get_or_init(DashMap::new).clear();
        DEST_CLASSIFIER.get_or_init(DashMap::new).clear();
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
    fn parse_http_request_line_is_strict() {
        let line = parse_http_request_line("GET /path?q=1 HTTP/1.1").expect("parsed");
        assert_eq!(line.method, "GET");
        assert_eq!(line.target, "/path?q=1");
        assert_eq!(line.version, "HTTP/1.1");
        assert!(parse_http_request_line("GET /path HTTP/1.1 EXTRA").is_none());
        assert!(parse_http_request_line("G E T / HTTP/1.1").is_none());
        assert!(parse_http_request_line("GET /path NOTHTTP").is_none());
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
    fn connect_target_parses_ipv6_with_port() {
        let bracketed = split_host_port_for_connect("[2001:db8::10]:8443").expect("parsed");
        assert_eq!(bracketed.0, "2001:db8::10");
        assert_eq!(bracketed.1, 8443);

        let unbracketed = split_host_port_for_connect("2001:db8::10:8443").expect("parsed");
        assert_eq!(unbracketed.0, "2001:db8::10");
        assert_eq!(unbracketed.1, 8443);
    }

    #[test]
    fn target_endpoint_display_brackets_ipv6_literal() {
        let endpoint = TargetEndpoint {
            addr: TargetAddr::Ip("2001:db8::42".parse().expect("ip")),
            port: 443,
        };
        assert_eq!(endpoint.to_string(), "[2001:db8::42]:443");
    }

    #[test]
    fn registrable_domain_bucket_handles_private_suffixes() {
        assert_eq!(
            registrable_domain_bucket("api.user.github.io").as_deref(),
            Some("user.github.io")
        );
        assert_eq!(
            registrable_domain_bucket("x.myapp.vercel.app").as_deref(),
            Some("myapp.vercel.app")
        );
    }

    #[test]
    fn host_service_bucket_uses_registrable_bucket_for_multitenant_suffixes() {
        assert_eq!(host_service_bucket("api.user.github.io"), "user.github.io");
        assert_eq!(
            host_service_bucket("x.myapp.vercel.app"),
            "myapp.vercel.app"
        );
    }

    #[test]
    fn validate_relay_topology_rejects_self_referential_proxy_loop() {
        let listen: SocketAddr = "127.0.0.1:1080".parse().expect("addr");
        let opts = RelayOptions {
            upstream_socks5: Some(listen),
            ..RelayOptions::default()
        };
        let err = validate_relay_topology(listen, &opts).expect_err("must reject loop");
        assert!(format!("{err}").contains("forwarding loop"));
    }

    #[test]
    fn stage4_fragmentation_is_not_one_byte_on_non_windows() {
        let destination = "example.com:443";
        let key = destination.to_owned();
        DEST_FAILURES
            .get_or_init(DashMap::new)
            .insert(key.clone(), 8);
        let _tuned = tune_relay_for_target(RelayOptions::default(), 443, destination, false, false);
        #[cfg(not(windows))]
        {
            assert!(_tuned.options.fragment_size_min >= 32);
            assert!(_tuned.options.fragment_size_max >= _tuned.options.fragment_size_min);
        }
        DEST_FAILURES.get_or_init(DashMap::new).remove(&key);
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
        let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        winner_map.insert(
            service_key,
            RouteWinner {
                route_id: "bypass:1".to_owned(),
                updated_at_unix: now_unix_secs(),
            },
        );

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
    fn adaptive_route_skips_race_when_meta_service_winner_is_healthy() {
        let winner_route_key = route_decision_key(
            "www.youtube.com:443",
            &TargetAddr::Domain("www.youtube.com".to_owned()),
        );
        let probe_route_key = route_decision_key(
            "i.ytimg.com:443",
            &TargetAddr::Domain("i.ytimg.com".to_owned()),
        );
        clear_route_state_for_test(&winner_route_key);
        clear_route_state_for_test(&probe_route_key);
        let meta_key = route_meta_service_key(&winner_route_key).expect("meta key");
        let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        winner_map.insert(
            meta_key,
            RouteWinner {
                route_id: "bypass:2".to_owned(),
                updated_at_unix: now_unix_secs(),
            },
        );

        let candidates = vec![
            RouteCandidate::direct("test"),
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 2),
            RouteCandidate::bypass("test", "127.0.0.1:19081".parse().expect("addr"), 1, 2),
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
        assert!(!should_mark_empty_bypass_session_as_soft_failure(
            &direct, 443
        ));
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
        let map = DEST_FAILURES.get_or_init(DashMap::new);
        map.insert(key.clone(), LEARNED_BYPASS_MIN_FAILURES_DOMAIN);

        assert!(should_bypass_by_classifier_host(
            "learned-bypass-test.invalid",
            443
        ));
        assert!(!should_bypass_by_classifier_host("127.0.0.1", 443));
        assert!(!should_bypass_by_classifier_host(
            "learned-bypass-test.invalid",
            80
        ));

        map.remove(&key);
    }

    #[test]
    fn learned_bypass_activates_for_public_ip_but_not_loopback() {
        let pub_key = "79.133.169.98:443".to_owned();
        let loopback_key = "127.0.0.1:443".to_owned();
        let map = DEST_FAILURES.get_or_init(DashMap::new);
        map.insert(pub_key.clone(), LEARNED_BYPASS_MIN_FAILURES_IP);
        map.insert(loopback_key.clone(), LEARNED_BYPASS_MIN_FAILURES_IP);

        assert!(should_bypass_by_classifier_ip(
            "79.133.169.98".parse().expect("ip"),
            443
        ));
        assert!(!should_bypass_by_classifier_ip(
            "127.0.0.1".parse().expect("ip"),
            443
        ));

        map.remove(&pub_key);
        map.remove(&loopback_key);
    }

    #[test]
    fn bypass_profile_rotation_propagates_to_service() {
        clear_bypass_profile_state_for_test();
        record_bypass_profile_failure("api.github.com:443", 0, 3, "unit-test");
        assert_eq!(destination_bypass_profile_idx("api.github.com:443", 3), 1);
        // NEW: Other subdomains of github.com should now also use index 1
        assert_eq!(
            destination_bypass_profile_idx("collector.github.com:443", 3),
            1
        );
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn bypass_profile_index_uses_legacy_service_key_fallback() {
        clear_bypass_profile_state_for_test();
        let service_key = bypass_profile_legacy_service_key("api.github.com:443");
        let idx_map = DEST_BYPASS_PROFILE_IDX.get_or_init(DashMap::new);
        idx_map.insert(service_key, 2);

        assert_eq!(
            destination_bypass_profile_idx("collector.github.com:443", 3),
            2
        );
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn bypass_profile_rotation_normalizes_family_aware_route_keys() {
        clear_bypass_profile_state_for_test();
        record_bypass_profile_failure("www.youtube.com:443|any", 0, 3, "handshake-io");
        assert_eq!(destination_bypass_profile_idx("www.youtube.com:443", 3), 1);
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn bypass_profile_rotation_propagates_to_meta_service_group() {
        clear_bypass_profile_state_for_test();
        record_bypass_profile_failure("www.youtube.com:443", 0, 3, "unit-test");
        assert_eq!(destination_bypass_profile_idx("i.ytimg.com:443", 3), 1);
        assert_eq!(destination_bypass_profile_idx("yt3.ggpht.com:443", 3), 1);
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn bypass_candidates_round_robin_when_profile_not_pinned() {
        clear_bypass_profile_state_for_test();
        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec![
                "127.0.0.1:19080".parse().expect("addr"),
                "127.0.0.1:19081".parse().expect("addr"),
                "127.0.0.1:19082".parse().expect("addr"),
            ],
            ..RelayOptions::default()
        };
        let first = select_bypass_candidates(&relay_opts, "round-robin.example:443");
        let second = select_bypass_candidates(&relay_opts, "round-robin.example:443");
        assert_ne!(first[0].1, second[0].1);
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn adaptive_bypass_multi_profile_success_pins_winner() {
        let route_key = "adaptive-pin.example:443|any";
        clear_route_state_for_test(route_key);
        let candidate = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            3,
        );
        record_route_success(route_key, &candidate);
        let winner = route_winner_for_key(route_key).expect("winner");
        assert_eq!(winner.route_id, "bypass:1");
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn route_connected_primes_winner_before_session_scoring() {
        let route_key = "route-connected-prime.example:443|any";
        clear_route_state_for_test(route_key);
        let candidate =
            RouteCandidate::bypass("builtin", "127.0.0.1:19080".parse().expect("addr"), 0, 2);
        record_route_connected(route_key, &candidate);
        let winner = route_winner_for_key(route_key).expect("winner");
        assert_eq!(winner.route_id, "bypass:1");
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn route_connected_does_not_pin_adaptive_bypass_winner() {
        let route_key = "route-connected-no-pin.example:443|any";
        clear_route_state_for_test(route_key);
        let candidate = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            2,
        );
        record_route_connected(route_key, &candidate);
        assert!(route_winner_for_key(route_key).is_none());
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn route_connected_does_not_pin_adaptive_direct_winner() {
        let route_key = "route-connected-no-pin-direct.example:443|any";
        clear_route_state_for_test(route_key);
        let candidate = RouteCandidate::direct("adaptive");
        record_route_connected(route_key, &candidate);
        assert!(route_winner_for_key(route_key).is_none());
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn youtube_race_not_suppressed_by_adaptive_direct_connect_only() {
        let route_key = "www.youtube.com:443|any";
        clear_route_state_for_test(route_key);
        let direct = RouteCandidate::direct("adaptive");
        let bypass = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            1,
        );
        let candidates = vec![direct.clone(), bypass];

        record_route_connected(route_key, &direct);
        let (race, reason) = route_race_decision(443, route_key, &candidates);
        assert!(race);
        assert_eq!(reason, RouteRaceReason::NoWinner);
        clear_route_state_for_test(route_key);
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
    fn adaptive_route_candidates_include_bypass_for_youtube_domain() {
        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec![
                "127.0.0.1:19080".parse().expect("addr"),
                "127.0.0.1:19081".parse().expect("addr"),
            ],
            ..RelayOptions::default()
        };
        let target = TargetAddr::Domain("i.ytimg.com".to_owned());
        let route_key = route_decision_key("i.ytimg.com:443", &target);
        let candidates = select_route_candidates(&relay_opts, &target, 443, &route_key);
        assert!(candidates.iter().any(|c| c.kind == RouteKind::Bypass));
    }

    #[test]
    fn adaptive_route_candidates_include_bypass_for_google_bucket_domain() {
        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec![
                "127.0.0.1:19080".parse().expect("addr"),
                "127.0.0.1:19081".parse().expect("addr"),
            ],
            ..RelayOptions::default()
        };
        let target = TargetAddr::Domain("www.gstatic.com".to_owned());
        let route_key = route_decision_key("www.gstatic.com:443", &target);
        let candidates = select_route_candidates(&relay_opts, &target, 443, &route_key);
        assert!(candidates.iter().any(|c| c.kind == RouteKind::Bypass));
    }

    #[test]
    fn non_blocked_public_domains_do_not_force_adaptive_bypass() {
        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec!["127.0.0.1:19080".parse().expect("addr")],
            ..RelayOptions::default()
        };
        let target = TargetAddr::Domain("cdn.localizeapi.com".to_owned());
        let route_key = route_decision_key("cdn.localizeapi.com:443", &target);
        let candidates = select_route_candidates(&relay_opts, &target, 443, &route_key);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, RouteKind::Direct);
        assert_ne!(candidates[0].source, "noise-bypass");
    }

    #[test]
    fn noise_bypass_matches_local_hosts_only() {
        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec!["127.0.0.1:19080".parse().expect("addr")],
            ..RelayOptions::default()
        };

        let localhost = TargetAddr::Domain("localhost".to_owned());
        let localhost_key = route_decision_key("localhost:443", &localhost);
        let localhost_candidates =
            select_route_candidates(&relay_opts, &localhost, 443, &localhost_key);
        assert_eq!(localhost_candidates.len(), 1);
        assert_eq!(localhost_candidates[0].kind, RouteKind::Direct);
        assert_eq!(localhost_candidates[0].source, "noise-bypass");

        let local = TargetAddr::Domain("printer.local".to_owned());
        let local_key = route_decision_key("printer.local:443", &local);
        let local_candidates = select_route_candidates(&relay_opts, &local, 443, &local_key);
        assert_eq!(local_candidates.len(), 1);
        assert_eq!(local_candidates[0].kind, RouteKind::Direct);
        assert_eq!(local_candidates[0].source, "noise-bypass");
    }

    #[test]
    fn https_noise_probe_detection_covers_ad_domains() {
        assert!(is_noise_probe_https_destination(
            "static.doubleclick.net:443"
        ));
        assert!(is_noise_probe_https_destination(
            "ogads-pa.clients6.google.com:443"
        ));
        assert!(!is_noise_probe_https_destination("www.youtube.com:443"));
    }

    #[test]
    fn bypass_resolve_picker_skips_ip_pinning_for_youtube_bucket() {
        let ips = vec![
            "142.250.74.206".parse().expect("ip"),
            "142.250.74.238".parse().expect("ip"),
        ];
        assert_eq!(pick_bypass_resolved_ip("www.youtube.com", &ips), None);
    }

    #[test]
    fn bypass_resolve_picker_prefers_ipv4_for_discord() {
        let ips = vec![
            "2a00:1450:4009:822::200e".parse().expect("ip"),
            "162.159.129.233".parse().expect("ip"),
        ];
        assert_eq!(
            pick_bypass_resolved_ip("discord.com", &ips),
            Some("162.159.129.233".parse().expect("ip"))
        );
    }

    #[test]
    fn bypass_resolve_picker_filters_non_public_ips() {
        let ips = vec![
            "127.0.0.1".parse().expect("ip"),
            "10.0.0.1".parse().expect("ip"),
        ];
        assert_eq!(pick_bypass_resolved_ip("example.com", &ips), None);
    }

    #[test]
    fn https_noise_probe_detection_handles_route_keys_with_family_suffix() {
        assert!(is_noise_probe_https_destination(route_destination_key(
            "ogads-pa.clients6.google.com:443|any"
        )));
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

        let health_map = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
        if let Some(per_route) = health_map.get_mut(route_key) {
            if let Some(mut entry) = per_route.get_mut(&candidate.route_id()) {
                entry.weak_until_unix = now_unix_secs().saturating_sub(1);
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
        let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        winner_map.insert(
            route_key.to_owned(),
            RouteWinner {
                route_id: "bypass:3".to_owned(),
                updated_at_unix: now_unix_secs(),
            },
        );

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
        let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        winner_map.insert(
            route_key.to_owned(),
            RouteWinner {
                route_id: "direct".to_owned(),
                updated_at_unix: now_unix_secs(),
            },
        );

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
    fn long_disconnect_penalty_applies_only_for_bypass_youtube_or_discord() {
        let bypass_youtube = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            2,
        );
        assert!(should_penalize_disconnect_as_soft_zero_reply(
            "www.youtube.com:443|any",
            &bypass_youtube,
            3_000
        ));
        assert!(!should_penalize_disconnect_as_soft_zero_reply(
            "www.youtube.com:443|any",
            &bypass_youtube,
            2_999
        ));

        let bypass_default = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            2,
        );
        assert!(!should_penalize_disconnect_as_soft_zero_reply(
            "api.github.com:443|any",
            &bypass_default,
            20_000
        ));

        let direct_youtube = RouteCandidate::direct("adaptive");
        assert!(!should_penalize_disconnect_as_soft_zero_reply(
            "www.youtube.com:443|any",
            &direct_youtube,
            20_000
        ));
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
        let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
        map.insert(
            "bypass:1".to_owned(),
            BypassProfileHealth {
                failures: 5,
                connect_failures: 2,
                last_failure_unix: now,
                ..BypassProfileHealth::default()
            },
        );
        map.insert(
            "bypass:2".to_owned(),
            BypassProfileHealth {
                successes: 6,
                last_success_unix: now,
                ..BypassProfileHealth::default()
            },
        );

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
        assert_eq!(
            route_race_candidate_delay_ms(0, &direct, true, "example.com"),
            0
        );
        assert_eq!(
            route_race_candidate_delay_ms(1, &bypass, true, "example.com"),
            ROUTE_RACE_BASE_DELAY_MS
                + ROUTE_RACE_DIRECT_HEADSTART_MS
                + ROUTE_RACE_BYPASS_EXTRA_DELAY_BUILTIN_MS
        );
        assert_eq!(
            route_race_candidate_delay_ms(1, &bypass_adaptive, true, "example.com"),
            ROUTE_RACE_BASE_DELAY_MS
                + ROUTE_RACE_DIRECT_HEADSTART_MS
                + ROUTE_RACE_BYPASS_EXTRA_DELAY_MS
        );
        assert_eq!(
            route_race_candidate_delay_ms(1, &bypass, false, "example.com"),
            ROUTE_RACE_BASE_DELAY_MS
        );
    }

    #[test]
    fn route_race_delays_are_staggered_by_candidate_index() {
        let bypass_1 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19080".parse().expect("addr"), 0, 3);
        let bypass_2 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19081".parse().expect("addr"), 1, 3);
        let bypass_3 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19082".parse().expect("addr"), 2, 3);

        let d1 = route_race_candidate_delay_ms(1, &bypass_1, false, "example.com");
        let d2 = route_race_candidate_delay_ms(2, &bypass_2, false, "example.com");
        let d3 = route_race_candidate_delay_ms(3, &bypass_3, false, "example.com");

        assert!(d2 > d1);
        assert!(d3 > d2);
    }

    #[test]
    fn route_race_youtube_bypass_candidates_launch_without_stagger() {
        let bypass_1 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19080".parse().expect("addr"), 0, 3);
        let bypass_2 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19081".parse().expect("addr"), 1, 3);
        let bypass_3 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19082".parse().expect("addr"), 2, 3);

        let d1 = route_race_candidate_delay_ms(1, &bypass_1, false, "www.youtube.com:443|any");
        let d2 = route_race_candidate_delay_ms(2, &bypass_2, false, "www.youtube.com:443|any");
        let d3 = route_race_candidate_delay_ms(3, &bypass_3, false, "www.youtube.com:443|any");

        assert_eq!(d1, 0);
        assert_eq!(d2, 0);
        assert_eq!(d3, 0);
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

        let launch = route_race_launch_candidates(&ordered, "example.com:443|any");
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
        let bypass_4 = RouteCandidate::bypass(
            "learned-domain",
            "127.0.0.1:19083".parse().expect("addr"),
            3,
            4,
        );
        let ordered = vec![
            direct.clone(),
            bypass_1.clone(),
            bypass_2.clone(),
            bypass_3,
            bypass_4,
        ];

        let launch = route_race_launch_candidates(&ordered, "example.com:443|any");
        // NEW: Max capped at ROUTE_RACE_MAX_CANDIDATES (usually 3 or 4)
        assert_eq!(launch.len(), ROUTE_RACE_MAX_CANDIDATES);
        assert_eq!(launch[0].route_id(), direct.route_id());
        assert_eq!(launch[1].route_id(), bypass_1.route_id());
        assert_eq!(launch[2].route_id(), bypass_2.route_id());
    }

    #[test]
    fn route_race_launch_for_youtube_uses_direct_and_two_best_bypass_profiles() {
        let direct = RouteCandidate::direct("adaptive");
        let bypass_1 = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            3,
        );
        let bypass_2 = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19081".parse().expect("addr"),
            1,
            3,
        );
        let bypass_3 = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19082".parse().expect("addr"),
            2,
            3,
        );
        let ordered = vec![direct.clone(), bypass_1.clone(), bypass_2, bypass_3];

        let launch = route_race_launch_candidates(&ordered, "www.youtube.com:443|any");
        assert_eq!(launch.len(), 3);
        assert_eq!(launch[0].route_id(), bypass_1.route_id());
        assert_eq!(launch[1].route_id(), "bypass:2");
        assert_eq!(launch[2].route_id(), direct.route_id());
    }

    #[test]
    fn adaptive_route_reraces_for_stale_direct_winner_on_youtube() {
        let route_key = "www.youtube.com:443|any";
        clear_route_state_for_test(route_key);
        let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        winner_map.insert(
            route_key.to_owned(),
            RouteWinner {
                route_id: "direct".to_owned(),
                updated_at_unix: now_unix_secs().saturating_sub(6),
            },
        );
        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                3,
            ),
        ];
        assert_eq!(
            route_race_decision(443, route_key, &candidates),
            (true, RouteRaceReason::WinnerStale)
        );
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn adaptive_route_keeps_fresh_direct_winner_on_youtube() {
        let route_key = "www.youtube.com:443|any";
        clear_route_state_for_test(route_key);
        let winner_map = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        winner_map.insert(
            route_key.to_owned(),
            RouteWinner {
                route_id: "direct".to_owned(),
                updated_at_unix: now_unix_secs().saturating_sub(2),
            },
        );
        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                3,
            ),
        ];
        assert_eq!(
            route_race_decision(443, route_key, &candidates),
            (false, RouteRaceReason::WinnerHealthy)
        );
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn hard_weak_global_bypass_profiles_are_pruned_when_healthier_exists() {
        clear_global_bypass_health_for_test();
        let now = now_unix_secs();
        let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
        map.insert(
            "bypass:1".to_owned(),
            BypassProfileHealth {
                successes: 5,
                last_success_unix: now,
                ..BypassProfileHealth::default()
            },
        );
        map.insert(
            "bypass:2".to_owned(),
            BypassProfileHealth {
                failures: 40,
                connect_failures: 20,
                soft_zero_replies: 20,
                last_failure_unix: now,
                ..BypassProfileHealth::default()
            },
        );

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
    fn youtube_bucket_prefers_primary_and_keeps_fallback_profiles() {
        clear_global_bypass_health_for_test();
        let route_key = "www.youtube.com:443|any";
        clear_route_state_for_test(route_key);

        let direct = RouteCandidate::direct("adaptive");
        let bypass_1 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19080".parse().expect("addr"), 0, 3);
        let bypass_2 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19081".parse().expect("addr"), 1, 3);
        let bypass_3 =
            RouteCandidate::bypass("builtin", "127.0.0.1:19082".parse().expect("addr"), 2, 3);

        let ordered = ordered_route_candidates(
            route_key,
            vec![direct, bypass_1, bypass_2, bypass_3.clone()],
        );
        assert_eq!(
            ordered.first().map(|candidate| candidate.route_id()),
            Some("bypass:1".to_owned())
        );
        assert!(ordered.iter().any(|c| c.route_id() == "bypass:2"));
        assert!(ordered.iter().any(|c| c.route_id() == bypass_3.route_id()));

        clear_route_state_for_test(route_key);
        clear_global_bypass_health_for_test();
    }

    #[test]
    fn cached_bypass_winner_is_kept_even_when_global_profile_is_weak() {
        clear_global_bypass_health_for_test();
        let route_key = "winner-kept-when-global-weak:443|any";
        clear_route_state_for_test(route_key);

        let bypass = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            1,
        );
        record_route_success(route_key, &bypass);

        let now = now_unix_secs();
        let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
        map.insert(
            "bypass:1".to_owned(),
            BypassProfileHealth {
                failures: 50,
                connect_failures: 30,
                soft_zero_replies: 20,
                last_failure_unix: now,
                ..BypassProfileHealth::default()
            },
        );

        let ordered = ordered_route_candidates(
            route_key,
            vec![RouteCandidate::direct("adaptive"), bypass.clone()],
        );
        assert!(ordered.iter().any(|c| c.route_id() == "bypass:1"));
        assert_eq!(
            ordered.first().map(|c| c.route_id()),
            Some("bypass:1".to_owned())
        );

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

    #[test]
    fn bypass_pool_warmup_is_throttled_per_backend() {
        let addr: SocketAddr = "127.0.0.1:19080".parse().expect("addr");
        let warmup_map = BYPASS_POOL_WARMUP_NEXT_AT_MS.get_or_init(DashMap::new);
        warmup_map.remove(&addr);

        assert!(should_schedule_bypass_pool_warmup_at(addr, 1_000));
        assert!(!should_schedule_bypass_pool_warmup_at(addr, 1_500));
        assert!(should_schedule_bypass_pool_warmup_at(addr, 2_001));

        warmup_map.remove(&addr);
    }

    #[test]
    fn runtime_prune_evicts_stale_destination_entries_across_all_maps() {
        let prefix = format!("runtime-prune-destination-{}", now_unix_secs());
        let failures = DEST_FAILURES.get_or_init(DashMap::new);
        let preferred = DEST_PREFERRED_STAGE.get_or_init(DashMap::new);
        let classifier = DEST_CLASSIFIER.get_or_init(DashMap::new);
        let bypass_idx = DEST_BYPASS_PROFILE_IDX.get_or_init(DashMap::new);
        let bypass_failures = DEST_BYPASS_PROFILE_FAILURES.get_or_init(DashMap::new);
        let winner = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
        let route_health = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);

        let old_keys: Vec<String> = (0..3).map(|i| format!("{prefix}-old-{i}:443")).collect();
        let fresh_keys: Vec<String> = (0..3).map(|i| format!("{prefix}-fresh-{i}:443")).collect();

        for (idx, key) in old_keys.iter().enumerate() {
            let ts = 10 + idx as u64;
            failures.insert(key.clone(), 2);
            preferred.insert(key.clone(), 2);
            classifier.insert(
                key.clone(),
                DestinationClassifier {
                    failures: 2,
                    last_seen_unix: ts,
                    ..DestinationClassifier::default()
                },
            );
            bypass_idx.insert(key.clone(), 1);
            bypass_failures.insert(key.clone(), 1);
            winner.insert(
                key.clone(),
                RouteWinner {
                    route_id: "bypass:1".to_owned(),
                    updated_at_unix: ts,
                },
            );
            {
                let per_route = route_health.entry(key.clone()).or_default();
                per_route.insert(
                    "bypass:1".to_owned(),
                    RouteHealth {
                        failures: 1,
                        last_failure_unix: ts,
                        ..RouteHealth::default()
                    },
                );
            }
        }
        for (idx, key) in fresh_keys.iter().enumerate() {
            let ts = 9_000_000_000 + idx as u64;
            failures.insert(key.clone(), 2);
            preferred.insert(key.clone(), 2);
            classifier.insert(
                key.clone(),
                DestinationClassifier {
                    successes: 1,
                    last_seen_unix: ts,
                    ..DestinationClassifier::default()
                },
            );
            bypass_idx.insert(key.clone(), 1);
            bypass_failures.insert(key.clone(), 1);
            winner.insert(
                key.clone(),
                RouteWinner {
                    route_id: "bypass:1".to_owned(),
                    updated_at_unix: ts,
                },
            );
            {
                let per_route = route_health.entry(key.clone()).or_default();
                per_route.insert(
                    "bypass:1".to_owned(),
                    RouteHealth {
                        successes: 1,
                        last_success_unix: ts,
                        ..RouteHealth::default()
                    },
                );
            }
        }

        let (removed_destinations, _) =
            prune_runtime_classifier_state_for_test(3, 3, usize::MAX, usize::MAX);
        assert!(removed_destinations >= old_keys.len());

        for key in &fresh_keys {
            assert!(failures.contains_key(key));
            assert!(preferred.contains_key(key));
            assert!(classifier.contains_key(key));
            assert!(bypass_idx.contains_key(key));
            assert!(bypass_failures.contains_key(key));
            assert!(winner.contains_key(key));
            assert!(route_health.contains_key(key));
        }
        for key in &old_keys {
            assert!(!failures.contains_key(key));
            assert!(!preferred.contains_key(key));
            assert!(!classifier.contains_key(key));
            assert!(!bypass_idx.contains_key(key));
            assert!(!bypass_failures.contains_key(key));
            assert!(!winner.contains_key(key));
            assert!(!route_health.contains_key(key));
        }
    }

    #[test]
    fn runtime_prune_evicts_stale_global_bypass_profile_health_entries() {
        let prefix = format!("runtime-prune-bypass-{}", now_unix_secs());
        let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
        let old_keys: Vec<String> = (0..3).map(|i| format!("bypass:{prefix}-old-{i}")).collect();
        let fresh_keys: Vec<String> = (0..3)
            .map(|i| format!("bypass:{prefix}-fresh-{i}"))
            .collect();

        for (idx, key) in old_keys.iter().enumerate() {
            map.insert(
                key.clone(),
                BypassProfileHealth {
                    failures: 1,
                    last_failure_unix: 10 + idx as u64,
                    ..BypassProfileHealth::default()
                },
            );
        }
        for (idx, key) in fresh_keys.iter().enumerate() {
            map.insert(
                key.clone(),
                BypassProfileHealth {
                    successes: 1,
                    last_success_unix: 9_000_000_000 + idx as u64,
                    ..BypassProfileHealth::default()
                },
            );
        }

        let (_, removed_profiles) =
            prune_runtime_classifier_state_for_test(usize::MAX, usize::MAX, 3, 3);
        assert!(removed_profiles > 0);

        for key in &fresh_keys {
            assert!(map.contains_key(key));
        }
        for key in &old_keys {
            assert!(!map.contains_key(key));
        }
    }

    #[test]
    fn route_ml_event_serialization_and_validation() {
        let _guard = ml_test_lock();
        let decision = RouteDecisionEvent {
            decision_id: 1,
            timestamp_unix: 1_700_000_000,
            bucket: "meta-group:youtube".to_owned(),
            host: "www.youtube.com".to_owned(),
            route_arm: "bypass:1".to_owned(),
            profile: Some(1),
            raced: true,
            winner: false,
            shadow_route_arm: "direct".to_owned(),
        };
        assert!(decision.validate().is_ok());
        let encoded = serde_json::to_string(&decision).expect("decision json");
        let decoded: RouteDecisionEvent = serde_json::from_str(&encoded).expect("decision decode");
        assert_eq!(decoded, decision);

        let mut invalid_decision = decision.clone();
        invalid_decision.host.clear();
        assert!(invalid_decision.validate().is_err());

        let outcome = RouteOutcomeEvent {
            decision_id: 1,
            timestamp_unix: 1_700_000_123,
            bucket: "meta-group:youtube".to_owned(),
            host: "www.youtube.com".to_owned(),
            route_arm: "bypass:1".to_owned(),
            profile: Some(1),
            raced: true,
            winner: true,
            connect_ok: true,
            tls_ok_proxy: true,
            bytes_u2c: 171_744,
            lifetime_ms: 10_112,
            error_class: "ok".to_owned(),
            shadow_route_arm: "direct".to_owned(),
            shadow_reward: 37,
        };
        assert!(outcome.validate().is_ok());
        let encoded = serde_json::to_string(&outcome).expect("outcome json");
        let decoded: RouteOutcomeEvent = serde_json::from_str(&encoded).expect("outcome decode");
        assert_eq!(decoded, outcome);

        let mut invalid_outcome = outcome.clone();
        invalid_outcome.error_class.clear();
        assert!(invalid_outcome.validate().is_err());
    }

    #[test]
    fn route_ml_decision_to_outcome_consistency_property() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();
        clear_destination_classifier_state_for_test();

        let samples = 96u64;
        for i in 0..samples {
            let route_key = format!("svc-{i}.example.com:443|any");
            let mut candidates = vec![RouteCandidate::direct("adaptive")];
            if i % 2 == 0 {
                candidates.push(RouteCandidate::bypass(
                    "adaptive-race",
                    "127.0.0.1:19080".parse().expect("addr"),
                    0,
                    2,
                ));
            }
            if i % 3 == 0 {
                candidates.push(RouteCandidate::bypass(
                    "adaptive-race",
                    "127.0.0.1:19081".parse().expect("addr"),
                    1,
                    2,
                ));
            }

            let decision_id = begin_route_decision_event(&route_key, &candidates, i % 2 == 0);
            let choice_idx = (stable_hash(&route_key) as usize) % candidates.len();
            let chosen = &candidates[choice_idx];
            let connect_ok = i % 5 != 0;
            let tls_ok = connect_ok && i % 3 != 0;
            let bytes_u2c = if tls_ok { 171_744 } else { 0 };
            let lifetime_ms = if connect_ok { 10_000 } else { 0 };
            let error_class = if connect_ok {
                if tls_ok {
                    "ok"
                } else {
                    "zero-reply-soft"
                }
            } else {
                "connect-failed"
            };

            complete_route_outcome_event(
                decision_id,
                &route_key,
                Some(chosen),
                connect_ok,
                tls_ok,
                bytes_u2c,
                lifetime_ms,
                error_class,
            );
        }

        assert_eq!(route_ml_pending_len_for_test(), 0);
        let outcomes = route_ml_outcomes_for_test();
        assert_eq!(outcomes.len(), samples as usize);

        for (idx, outcome) in outcomes.iter().enumerate() {
            assert_eq!(outcome.decision_id, (idx as u64) + 1);
            assert!(!outcome.bucket.is_empty());
            assert!(!outcome.host.is_empty());
            assert!(!outcome.error_class.is_empty());
        }

        let stats = shadow_bandit_stats_for_test("default", "direct");
        assert!(stats.is_some());
    }

    #[test]
    fn route_ml_shadow_does_not_change_route_selection_golden_trace() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();
        clear_destination_classifier_state_for_test();
        clear_bypass_profile_state_for_test();
        clear_global_bypass_health_for_test();

        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec!["127.0.0.1:19080".parse().expect("addr")],
            ..RelayOptions::default()
        };

        let traces = vec![
            (
                "www.youtube.com:443",
                TargetAddr::Domain("www.youtube.com".to_owned()),
                "bypass:1",
                true,
            ),
            (
                "discord.com:443",
                TargetAddr::Domain("discord.com".to_owned()),
                "bypass:1",
                true,
            ),
            (
                "cdn.localizeapi.com:443",
                TargetAddr::Domain("cdn.localizeapi.com".to_owned()),
                "direct",
                false,
            ),
        ];

        for (destination, target, expected_arm, expected_race) in traces {
            let route_key = route_decision_key(destination, &target);
            clear_route_state_for_test(&route_key);

            let baseline_candidates =
                select_route_candidates(&relay_opts, &target, 443, &route_key);
            let baseline_ordered = ordered_route_candidates(&route_key, baseline_candidates);
            assert_eq!(
                baseline_ordered
                    .first()
                    .map(|candidate| candidate.route_id()),
                Some(expected_arm.to_owned())
            );
            assert_eq!(
                route_race_decision(443, &route_key, &baseline_ordered).0,
                expected_race
            );

            let decision_id =
                begin_route_decision_event(&route_key, &baseline_ordered, expected_race);
            let winner = baseline_ordered.first().expect("winner candidate");
            complete_route_outcome_event(
                decision_id,
                &route_key,
                Some(winner),
                true,
                true,
                4_096,
                250,
                "ok",
            );

            let after_candidates = select_route_candidates(&relay_opts, &target, 443, &route_key);
            let after_ordered = ordered_route_candidates(&route_key, after_candidates);
            assert_eq!(
                after_ordered.first().map(|candidate| candidate.route_id()),
                Some(expected_arm.to_owned())
            );
            assert_eq!(
                route_race_decision(443, &route_key, &after_ordered).0,
                expected_race
            );

            clear_route_state_for_test(&route_key);
        }
    }

    #[test]
    fn shadow_phase1_bucket_priors_are_applied() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        assert_eq!(
            shadow_bucket_name_for_test("www.youtube.com:443|any", "www.youtube.com"),
            "youtube"
        );
        assert_eq!(
            shadow_bucket_name_for_test("discord.com:443|any", "discord.com"),
            "discord"
        );
        assert_eq!(
            shadow_bucket_name_for_test("ajax.googleapis.com:443|any", "ajax.googleapis.com"),
            "google-common"
        );
        assert_eq!(
            shadow_bucket_name_for_test("static.doubleclick.net:443|any", "static.doubleclick.net"),
            "ads-noise"
        );
        assert_eq!(
            shadow_bucket_name_for_test("api.github.com:443|any", "api.github.com"),
            "default"
        );
        let (prior_pulls, youtube_direct_reward_sum) =
            shadow_arm_prior_for_test("youtube", "direct");
        let (_, youtube_bypass_reward_sum) = shadow_arm_prior_for_test("youtube", "bypass:1");
        assert!(prior_pulls > 0);
        assert!(youtube_bypass_reward_sum > youtube_direct_reward_sum);

        let youtube_candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                3,
            ),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19081".parse().expect("addr"),
                1,
                3,
            ),
        ];
        assert_eq!(
            shadow_choose_route_arm("youtube", "www.youtube.com:443|any", &youtube_candidates),
            "bypass:1"
        );

        let discord_candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                3,
            ),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19081".parse().expect("addr"),
                1,
                3,
            ),
        ];
        assert_eq!(
            shadow_choose_route_arm("discord", "discord.com:443|any", &discord_candidates),
            "bypass:2"
        );

        let ads_candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                1,
            ),
        ];
        assert_eq!(
            shadow_choose_route_arm(
                "ads-noise",
                "static.doubleclick.net:443|any",
                &ads_candidates
            ),
            "direct"
        );
    }

    #[test]
    fn shadow_phase1_posterior_update_prefers_learned_arm() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let route_key = "video.example.com:443|any";
        let mut bypass_candidate = RouteCandidate::bypass(
            "adaptive-race",
            "127.0.0.1:19080".parse().expect("addr"),
            0,
            1,
        );
        bypass_candidate.family = RouteIpFamily::V6;
        let candidates = vec![RouteCandidate::direct("adaptive"), bypass_candidate];

        assert_eq!(
            shadow_choose_route_arm("default", route_key, &candidates),
            "direct"
        );

        for _ in 0..8 {
            let decision_id = begin_route_decision_event(route_key, &candidates, true);
            complete_route_outcome_event(
                decision_id,
                route_key,
                Some(&candidates[1]),
                true,
                true,
                171_744,
                10_000,
                "ok",
            );
        }
        for _ in 0..6 {
            let decision_id = begin_route_decision_event(route_key, &candidates, true);
            complete_route_outcome_event(
                decision_id,
                route_key,
                Some(&candidates[0]),
                true,
                false,
                0,
                220,
                "zero-reply-soft",
            );
        }

        assert_eq!(
            shadow_choose_route_arm("default", route_key, &candidates),
            "bypass:1"
        );

        let stats = shadow_bandit_stats_for_test("default", "bypass:1").expect("bypass stats");
        assert!(stats.pulls >= 8);
    }

    #[test]
    fn shadow_phase1_deterministic_fallback_is_stable() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let route_key = "cold-start.example.com:443|any";
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

        let first = shadow_choose_route_arm("default", route_key, &candidates);
        for _ in 0..24 {
            let current = shadow_choose_route_arm("default", route_key, &candidates);
            assert_eq!(current, first);
        }

        assert_eq!(
            shadow_exploration_enabled("ads-noise", 1, "static.doubleclick.net:443|any"),
            false
        );
        assert_eq!(
            shadow_exploration_enabled("default", 42, route_key),
            shadow_exploration_enabled("default", 42, route_key)
        );
    }

    #[test]
    fn shadow_phase1_cold_start_simulation_keeps_baseline_route_behavior() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();
        clear_destination_classifier_state_for_test();
        clear_bypass_profile_state_for_test();
        clear_global_bypass_health_for_test();

        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec![
                "127.0.0.1:19080".parse().expect("addr"),
                "127.0.0.1:19081".parse().expect("addr"),
            ],
            ..RelayOptions::default()
        };

        let scenarios = vec![
            (
                "www.youtube.com:443",
                TargetAddr::Domain("www.youtube.com".to_owned()),
            ),
            (
                "discord.com:443",
                TargetAddr::Domain("discord.com".to_owned()),
            ),
            (
                "cdn.localizeapi.com:443",
                TargetAddr::Domain("cdn.localizeapi.com".to_owned()),
            ),
            (
                "ajax.googleapis.com:443",
                TargetAddr::Domain("ajax.googleapis.com".to_owned()),
            ),
        ];

        for (destination, target) in scenarios {
            let route_key = route_decision_key(destination, &target);
            clear_route_state_for_test(&route_key);
            let baseline = ordered_route_candidates(
                &route_key,
                select_route_candidates(&relay_opts, &target, 443, &route_key),
            );
            let baseline_winner = baseline.first().map(|candidate| candidate.route_id());
            let baseline_race = route_race_decision(443, &route_key, &baseline).0;

            for _ in 0..12 {
                let decision_id = begin_route_decision_event(&route_key, &baseline, baseline_race);
                if let Some(winner) = baseline.first() {
                    complete_route_outcome_event(
                        decision_id,
                        &route_key,
                        Some(winner),
                        true,
                        true,
                        8_192,
                        500,
                        "ok",
                    );
                }
            }

            let after = ordered_route_candidates(
                &route_key,
                select_route_candidates(&relay_opts, &target, 443, &route_key),
            );
            assert_eq!(
                after.first().map(|candidate| candidate.route_id()),
                baseline_winner
            );
            assert_eq!(
                route_race_decision(443, &route_key, &after).0,
                baseline_race
            );
            clear_route_state_for_test(&route_key);
        }
    }

    fn train_shadow_outcomes(
        route_key: &str,
        candidates: &[RouteCandidate],
        candidate_idx: usize,
        samples: usize,
        success: bool,
    ) {
        let chosen = &candidates[candidate_idx];
        for _ in 0..samples {
            let decision_id = begin_route_decision_event(route_key, candidates, true);
            if success {
                complete_route_outcome_event(
                    decision_id,
                    route_key,
                    Some(chosen),
                    true,
                    true,
                    171_744,
                    10_000,
                    "ok",
                );
            } else {
                complete_route_outcome_event(
                    decision_id,
                    route_key,
                    Some(chosen),
                    false,
                    false,
                    0,
                    0,
                    "connect-failed",
                );
            }
        }
    }

    #[test]
    fn shadow_phase2_canary_applies_only_to_allowed_buckets() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let route_key = "www.youtube.com:443|any";
        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                1,
            ),
        ];
        train_shadow_outcomes(route_key, &candidates, 1, 32, true);
        train_shadow_outcomes(route_key, &candidates, 0, 28, false);

        let (reordered, decision) = apply_phase2_canary_override(route_key, candidates.clone());
        assert!(decision.applied);
        assert_eq!(decision.route_arm, "bypass:1");
        assert_eq!(reordered[0].route_id(), "bypass:1");

        let default_key = "api.github.com:443|any";
        let (default_reordered, default_decision) =
            apply_phase2_canary_override(default_key, candidates);
        assert!(!default_decision.applied);
        assert_eq!(default_decision.reason, "bucket-not-allowed");
        assert_eq!(default_reordered[0].route_id(), "direct");
    }

    #[test]
    fn shadow_phase2_guardrails_switch_window_and_cooldown_work() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let route_key = "www.youtube.com:443|any";
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

        train_shadow_outcomes(route_key, &candidates, 1, 32, true);
        train_shadow_outcomes(route_key, &candidates, 0, 32, false);
        let (_, first) = apply_phase2_canary_override(route_key, candidates.clone());
        assert!(first.applied);
        assert_eq!(first.route_arm, "bypass:1");

        train_shadow_outcomes(route_key, &candidates, 2, 48, true);
        train_shadow_outcomes(route_key, &candidates, 1, 64, false);
        let (_, second) = apply_phase2_canary_override(route_key, candidates.clone());
        assert!(second.applied);
        assert_eq!(second.route_arm, "bypass:2");

        let bandit = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
        bandit.insert(
            "youtube|bypass:1".to_owned(),
            ShadowBanditArmStats {
                pulls: 200,
                reward_sum: 18_000,
                last_reward: 120,
                last_seen_unix: now_unix_secs(),
                ..ShadowBanditArmStats::default()
            },
        );
        bandit.insert(
            "youtube|bypass:2".to_owned(),
            ShadowBanditArmStats {
                pulls: 200,
                reward_sum: 4_000,
                last_reward: 10,
                last_seen_unix: now_unix_secs(),
                ..ShadowBanditArmStats::default()
            },
        );
        let (_, third) = apply_phase2_canary_override(route_key, candidates.clone());
        assert!(!third.applied);
        assert_eq!(third.reason, "switch-guard");

        note_phase2_profile_rotation("www.youtube.com:443|any");
        let (_, cooled) = apply_phase2_canary_override(route_key, candidates);
        assert!(!cooled.applied);
        assert_eq!(cooled.reason, "bucket-cooldown");
        assert!(canary_bucket_cooldown_until_for_test("youtube").is_some());
    }

    #[test]
    fn shadow_phase2_chaos_burst_triggers_rollback() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let route_key = "www.youtube.com:443|any";
        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                1,
            ),
        ];
        let canary = ShadowCanaryDecision {
            applied: true,
            route_arm: "bypass:1".to_owned(),
            confidence_milli: 20_000,
            reason: "unit-test",
        };
        for _ in 0..16 {
            let decision_id = begin_route_decision_event_with_canary(
                route_key,
                &candidates,
                true,
                Some(canary.clone()),
            );
            complete_route_outcome_event(
                decision_id,
                route_key,
                Some(&candidates[1]),
                false,
                false,
                0,
                0,
                "timeout",
            );
        }
        let rollback_until = canary_rollback_until_for_test();
        assert!(rollback_until > now_unix_secs());

        train_shadow_outcomes(route_key, &candidates, 1, 40, true);
        let (_, decision) = apply_phase2_canary_override(route_key, candidates);
        assert!(!decision.applied);
        assert_eq!(decision.reason, "rollback-active");
    }

    #[test]
    fn shadow_phase2_canary_acceptance_slo_keeps_canary_when_healthy() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let route_key = "discord.com:443|any";
        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                1,
            ),
        ];
        train_shadow_outcomes(route_key, &candidates, 1, 40, true);
        train_shadow_outcomes(route_key, &candidates, 0, 30, false);

        let canary = ShadowCanaryDecision {
            applied: true,
            route_arm: "bypass:1".to_owned(),
            confidence_milli: 25_000,
            reason: "unit-test",
        };
        for _ in 0..14 {
            let decision_id = begin_route_decision_event_with_canary(
                route_key,
                &candidates,
                true,
                Some(canary.clone()),
            );
            complete_route_outcome_event(
                decision_id,
                route_key,
                Some(&candidates[1]),
                true,
                true,
                171_744,
                10_000,
                "ok",
            );
        }
        assert_eq!(canary_rollback_until_for_test(), 0);
        let (_, decision) = apply_phase2_canary_override(route_key, candidates.clone());
        assert!(decision.applied);
    }

    #[test]
    fn shadow_phase2_replay_scenario_respects_bucket_policy() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let youtube_candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                1,
            ),
        ];
        let discord_candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19081".parse().expect("addr"),
                1,
                2,
            ),
        ];
        train_shadow_outcomes("www.youtube.com:443|any", &youtube_candidates, 1, 36, true);
        train_shadow_outcomes("www.youtube.com:443|any", &youtube_candidates, 0, 30, false);
        train_shadow_outcomes("discord.com:443|any", &discord_candidates, 1, 36, true);
        train_shadow_outcomes("discord.com:443|any", &discord_candidates, 0, 30, false);

        let replay = vec![
            ("www.youtube.com:443|any", youtube_candidates.clone(), true),
            ("discord.com:443|any", discord_candidates.clone(), true),
            ("ajax.googleapis.com:443|any", youtube_candidates, false),
            ("cdn.localizeapi.com:443|any", discord_candidates, false),
        ];
        for (route_key, candidates, expect_applied) in replay {
            let (_, decision) = apply_phase2_canary_override(route_key, candidates);
            assert_eq!(decision.applied, expect_applied);
        }
    }

    #[test]
    fn shadow_phase3_decay_prefers_recent_data_over_stale_history() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let route_key = "www.youtube.com:443|any";
        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                1,
            ),
        ];
        let now = now_unix_secs();
        let bandit = SHADOW_BANDIT_ARMS.get_or_init(DashMap::new);
        bandit.insert(
            "default|bypass:1".to_owned(),
            ShadowBanditArmStats {
                pulls: 400,
                reward_sum: 28_000,
                last_reward: 120,
                last_seen_unix: now.saturating_sub(12 * 3600),
                ..ShadowBanditArmStats::default()
            },
        );
        bandit.insert(
            "default|direct".to_owned(),
            ShadowBanditArmStats {
                pulls: 48,
                reward_sum: 2_600,
                last_reward: 55,
                last_seen_unix: now,
                ..ShadowBanditArmStats::default()
            },
        );

        let selected = shadow_choose_route_arm("default", route_key, &candidates);
        assert_eq!(selected, "direct");
    }

    #[test]
    fn shadow_phase3_drift_detection_blocks_unstable_arm() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let route_key = "www.youtube.com:443|any";
        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                1,
            ),
        ];

        train_shadow_outcomes(route_key, &candidates, 1, 96, true);
        train_shadow_outcomes(route_key, &candidates, 0, 64, false);
        assert!(!shadow_arm_drift_detected_for_test("youtube", "bypass:1"));

        for _ in 0..8 {
            let decision_id = begin_route_decision_event(route_key, &candidates, true);
            complete_route_outcome_event(
                decision_id,
                route_key,
                Some(&candidates[1]),
                false,
                false,
                0,
                0,
                "timeout",
            );
        }

        assert!(shadow_arm_drift_detected_for_test("youtube", "bypass:1"));
        let (_, decision) = apply_phase3_ml_override(route_key, candidates);
        assert!(!decision.applied);
        assert_eq!(decision.route_arm, "bypass:1");
        assert_eq!(decision.reason, "a-drift-override");
    }

    #[test]
    fn shadow_phase3_offline_replay_rebuilds_policy() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();

        let route_key = "discord.com:443|any";
        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19081".parse().expect("addr"),
                1,
                2,
            ),
        ];
        train_shadow_outcomes(route_key, &candidates, 1, 48, true);
        train_shadow_outcomes(route_key, &candidates, 0, 30, false);
        let replay_data = route_ml_outcomes_for_test();
        assert!(!replay_data.is_empty());

        clear_route_ml_state_for_test();
        let replayed = replay_route_outcomes_for_test(&replay_data);
        assert_eq!(replayed, replay_data.len());

        let (_, decision) = apply_phase3_ml_override(route_key, candidates);
        assert!(decision.applied);
        assert_eq!(decision.route_arm, "bypass:2");
    }

    #[test]
    fn shadow_phase3_invariants_keep_a_as_safety_net() {
        let _guard = ml_test_lock();
        clear_route_ml_state_for_test();
        clear_global_bypass_health_for_test();

        let candidates = vec![
            RouteCandidate::direct("adaptive"),
            RouteCandidate::bypass(
                "adaptive-race",
                "127.0.0.1:19080".parse().expect("addr"),
                0,
                1,
            ),
        ];

        train_shadow_outcomes("static.doubleclick.net:443|any", &candidates, 1, 72, true);
        train_shadow_outcomes("static.doubleclick.net:443|any", &candidates, 0, 48, false);
        let (_, ads_decision) =
            apply_phase3_ml_override("static.doubleclick.net:443|any", candidates.clone());
        assert!(!ads_decision.applied);
        assert_eq!(ads_decision.reason, "bucket-not-allowed");

        let route_key = "phase3.youtube.com:443|any";
        clear_route_state_for_test(route_key);
        train_shadow_outcomes(route_key, &candidates, 1, 72, true);
        train_shadow_outcomes(route_key, &candidates, 0, 48, false);
        let bad_health = BypassProfileHealth {
            failures: 80,
            connect_failures: 40,
            soft_zero_replies: 16,
            io_errors: 8,
            last_failure_unix: now_unix_secs(),
            ..BypassProfileHealth::default()
        };
        let global_health = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
        global_health.insert(
            bypass_profile_health_key("bypass:1", RouteIpFamily::V6),
            bad_health.clone(),
        );
        global_health.insert(
            bypass_profile_health_key("bypass:1", RouteIpFamily::Any),
            bad_health,
        );
        let (ordered_global, weak_global) = apply_phase3_ml_override(route_key, candidates.clone());
        assert_eq!(ordered_global[0].route_id(), "direct");
        if weak_global.route_arm == "bypass:1" {
            assert!(!weak_global.applied);
            assert_eq!(weak_global.reason, "a-global-weak-override");
        }

        clear_global_bypass_health_for_test();
        let weak_until = now_unix_secs().saturating_add(120);
        let route_health = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
        let per_route = route_health.entry(route_key.to_owned()).or_default();
        per_route.insert(
            "bypass:1".to_owned(),
            RouteHealth {
                weak_until_unix: weak_until,
                ..RouteHealth::default()
            },
        );
        drop(per_route);
        let (ordered_route, weak_route) = apply_phase3_ml_override(route_key, candidates);
        assert_eq!(ordered_route[0].route_id(), "direct");
        if weak_route.route_arm == "bypass:1" {
            assert!(!weak_route.applied);
            assert_eq!(weak_route.reason, "a-weak-route-override");
        }
        clear_route_state_for_test(route_key);
        clear_global_bypass_health_for_test();
    }
}
