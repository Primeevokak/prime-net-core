use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_route_state_for_test(route_key: &str) {
        let service_key = route_service_key(route_key, &EngineConfig::default());
        let meta_key = route_meta_service_key(route_key, &EngineConfig::default());
        let rs = routing_state();
        rs.dest_route_health.remove(route_key);
        if let Some(k) = service_key.as_ref() {
            rs.dest_route_health.remove(k);
        }
        if let Some(k) = meta_key.as_ref() {
            rs.dest_route_health.remove(k);
        }
        rs.dest_route_winner.remove(route_key);
        if let Some(k) = service_key.as_ref() {
            rs.dest_route_winner.remove(k);
        }
        if let Some(k) = meta_key.as_ref() {
            rs.dest_route_winner.remove(k);
        }
    }

    fn clear_global_bypass_health_for_test() {
        routing_state().global_bypass_profile_health.clear();
    }

    fn clear_bypass_profile_state_for_test() {
        let rs = routing_state();
        rs.dest_bypass_profile_idx.clear();
        rs.dest_bypass_profile_failures.clear();
    }

    fn clear_route_capabilities_for_test() {
        if let Ok(mut guard) = routing_state().route_capabilities.write() {
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
        let rs = routing_state();
        rs.dest_failures.clear();
        rs.dest_preferred_stage.clear();
        rs.dest_classifier.clear();
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
    fn rewrite_http_forward_head_keeps_non_default_port_in_host_header() {
        let req = "GET http://example.com:8080/api HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\n\r\n";
        let target = HttpForwardTarget {
            host: "example.com".to_owned(),
            port: 8080,
            request_uri: "/api".to_owned(),
        };
        let rewritten = rewrite_http_forward_head(req, &target);
        assert!(rewritten.contains("\r\nHost: example.com:8080\r\n"));
        assert!(!rewritten.contains("\r\nProxy-Connection:"));
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
        assert_eq!(
            host_service_bucket("api.user.github.io", &EngineConfig::default()),
            "user.github.io"
        );
        assert_eq!(
            host_service_bucket("x.myapp.vercel.app", &EngineConfig::default()),
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
        routing_state().dest_failures.insert(key.clone(), 8);
        let _tuned = tune_relay_for_target(RelayOptions::default(), 443, destination, false, false);
        #[cfg(not(windows))]
        {
            assert!(_tuned.options.fragment_size_min >= 32);
            assert!(_tuned.options.fragment_size_max >= _tuned.options.fragment_size_min);
        }
        routing_state().dest_failures.remove(&key);
    }

    #[test]
    fn bypass_mode_disables_internal_evasion_toggles() {
        let base = RelayOptions {
            fragment_client_hello: true,
            split_at_sni: true,
            client_hello_split_offsets: vec![1, 5, 16],
            tcp_window_trick: true,
            sni_spoofing: true,
            sni_case_toggle: true,
            ..RelayOptions::default()
        };
        let tuned = tune_relay_for_target(base, 443, "www.youtube.com:443", false, true);
        assert!(!tuned.options.fragment_client_hello);
        assert!(!tuned.options.split_at_sni);
        assert!(tuned.options.client_hello_split_offsets.is_empty());
        assert!(!tuned.options.tcp_window_trick);
        assert!(!tuned.options.sni_spoofing);
        assert!(!tuned.options.sni_case_toggle);
    }

    #[test]
    fn route_decision_key_is_family_aware_for_ip_targets() {
        let key_v4 = route_decision_key(
            "149.154.167.50:443",
            &TargetAddr::Ip("149.154.167.50".parse().expect("ip")),
            &EngineConfig::default(),
        );
        let key_v6 = route_decision_key(
            "2001:67c:4e8:f002::a:443",
            &TargetAddr::Ip("2001:67c:4e8:f002::a".parse().expect("ip")),
            &EngineConfig::default(),
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
            &EngineConfig::default(),
        );
        let key_collector = route_decision_key(
            "collector.github.com:443",
            &TargetAddr::Domain("collector.github.com".to_owned()),
            &EngineConfig::default(),
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
            &EngineConfig::default(),
        );
        let collector_key = route_decision_key(
            "rr3---sn-gvnuxaxjvh-88vz.googlevideo.com:443",
            &TargetAddr::Domain("rr3---sn-gvnuxaxjvh-88vz.googlevideo.com".to_owned()),
            &EngineConfig::default(),
        );
        let api_service =
            route_service_key(&api_key, &EngineConfig::default()).expect("service key");
        let collector_service =
            route_service_key(&collector_key, &EngineConfig::default()).expect("service key");
        assert_eq!(api_service, collector_service);
        assert!(api_service.starts_with("googlevideo.com:443|"));
    }

    #[test]
    fn adaptive_route_skips_race_when_service_winner_is_healthy() {
        let winner_route_key = route_decision_key(
            "rr2---sn-gvnuxaxjvh-88vs.googlevideo.com:443",
            &TargetAddr::Domain("rr2---sn-gvnuxaxjvh-88vs.googlevideo.com".to_owned()),
            &EngineConfig::default(),
        );
        let probe_route_key = route_decision_key(
            "rr3---sn-gvnuxaxjvh-88vz.googlevideo.com:443",
            &TargetAddr::Domain("rr3---sn-gvnuxaxjvh-88vz.googlevideo.com".to_owned()),
            &EngineConfig::default(),
        );
        clear_route_state_for_test(&winner_route_key);
        clear_route_state_for_test(&probe_route_key);
        let service_key =
            route_service_key(&winner_route_key, &EngineConfig::default()).expect("service key");
        routing_state().dest_route_winner.insert(
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
        let decision =
            route_race_decision(443, &probe_route_key, &candidates, &EngineConfig::default());
        assert_eq!(decision, (false, RouteRaceReason::WinnerHealthy));
        clear_route_state_for_test(&winner_route_key);
        clear_route_state_for_test(&probe_route_key);
    }

    #[test]
    fn adaptive_route_skips_race_when_meta_service_winner_is_healthy() {
        let winner_route_key = route_decision_key(
            "www.youtube.com:443",
            &TargetAddr::Domain("www.youtube.com".to_owned()),
            &EngineConfig::default(),
        );
        let probe_route_key = route_decision_key(
            "i.ytimg.com:443",
            &TargetAddr::Domain("i.ytimg.com".to_owned()),
            &EngineConfig::default(),
        );
        clear_route_state_for_test(&winner_route_key);
        clear_route_state_for_test(&probe_route_key);
        let meta_key =
            route_meta_service_key(&winner_route_key, &EngineConfig::default()).expect("meta key");
        routing_state().dest_route_winner.insert(
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
        let decision =
            route_race_decision(443, &probe_route_key, &candidates, &EngineConfig::default());
        assert_eq!(decision, (false, RouteRaceReason::WinnerHealthy));
        clear_route_state_for_test(&winner_route_key);
        clear_route_state_for_test(&probe_route_key);
    }

    #[test]
    fn learned_bypass_activates_after_failures_for_tls_domain() {
        let key = "learned-bypass-test.invalid:443|any".to_owned();
        let map = &routing_state().dest_failures;
        map.insert(key.clone(), LEARNED_BYPASS_MIN_FAILURES_DOMAIN);

        assert!(should_bypass_by_classifier_host(
            "learned-bypass-test.invalid",
            443,
            &EngineConfig::default()
        ));
        assert!(!should_bypass_by_classifier_host(
            "127.0.0.1",
            443,
            &EngineConfig::default()
        ));
        assert!(!should_bypass_by_classifier_host(
            "learned-bypass-test.invalid",
            80,
            &EngineConfig::default()
        ));

        map.remove(&key);
    }

    #[test]
    fn bypass_profile_rotation_propagates_to_service() {
        clear_bypass_profile_state_for_test();
        record_bypass_profile_failure(
            "api.github.com:443",
            0,
            3,
            "unit-test",
            &EngineConfig::default(),
        );
        assert_eq!(destination_bypass_profile_idx("api.github.com:443", 3), 1);
        assert_eq!(
            destination_bypass_profile_idx("collector.github.com:443", 3),
            1
        );
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn bypass_profile_index_uses_legacy_service_key_fallback() {
        clear_bypass_profile_state_for_test();
        let service_key =
            bypass_profile_legacy_service_key("api.github.com:443", &EngineConfig::default());
        routing_state().dest_bypass_profile_idx.insert(service_key, 2);

        assert_eq!(
            destination_bypass_profile_idx("collector.github.com:443", 3),
            2
        );
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn bypass_profile_rotation_normalizes_family_aware_route_keys() {
        clear_bypass_profile_state_for_test();
        record_bypass_profile_failure(
            "www.youtube.com:443|any",
            0,
            3,
            "handshake-io",
            &EngineConfig::default(),
        );
        assert_eq!(destination_bypass_profile_idx("www.youtube.com:443", 3), 1);
        clear_bypass_profile_state_for_test();
    }

    #[test]
    fn bypass_profile_rotation_propagates_to_meta_service_group() {
        clear_bypass_profile_state_for_test();
        record_bypass_profile_failure(
            "www.youtube.com:443",
            0,
            3,
            "unit-test",
            &EngineConfig::default(),
        );
        assert_eq!(destination_bypass_profile_idx("i.ytimg.com:443", 3), 1);
        assert_eq!(destination_bypass_profile_idx("yt3.ggpht.com:443", 3), 1);
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
        record_route_success(route_key, &candidate, &EngineConfig::default());
        let winner = route_winner_for_key(route_key, &EngineConfig::default()).expect("winner");
        assert_eq!(winner.route_id, "bypass:1");
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn route_connected_primes_winner_before_session_scoring() {
        let route_key = "route-connected-prime.example:443|any";
        clear_route_state_for_test(route_key);
        let candidate =
            RouteCandidate::bypass("manual", "127.0.0.1:19080".parse().expect("addr"), 0, 2);
        record_route_connected(route_key, &candidate, &EngineConfig::default());
        let winner = route_winner_for_key(route_key, &EngineConfig::default()).expect("winner");
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
        record_route_connected(route_key, &candidate, &EngineConfig::default());
        assert!(route_winner_for_key(route_key, &EngineConfig::default()).is_none());
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn route_connected_does_not_pin_adaptive_direct_winner() {
        let route_key = "route-connected-no-pin-direct.example:443|any";
        clear_route_state_for_test(route_key);
        let candidate = RouteCandidate::direct("adaptive");
        record_route_connected(route_key, &candidate, &EngineConfig::default());
        assert!(route_winner_for_key(route_key, &EngineConfig::default()).is_none());
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

        record_route_connected(route_key, &direct, &EngineConfig::default());
        let (race, reason) =
            route_race_decision(443, route_key, &candidates, &EngineConfig::default());
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
        let target = TargetAddr::Domain("service.example.com".to_owned());
        let candidates = select_route_candidates(
            &relay_opts,
            &target,
            443,
            "service.example.com:443",
            &EngineConfig::default(),
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
        let route_key = route_decision_key("i.ytimg.com:443", &target, &EngineConfig::default());
        let candidates = select_route_candidates(
            &relay_opts,
            &target,
            443,
            &route_key,
            &EngineConfig::default(),
        );
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
        let route_key =
            route_decision_key("www.gstatic.com:443", &target, &EngineConfig::default());
        let candidates = select_route_candidates(
            &relay_opts,
            &target,
            443,
            &route_key,
            &EngineConfig::default(),
        );
        assert!(candidates.iter().any(|c| c.kind == RouteKind::Bypass));
    }

    #[test]
    fn non_blocked_public_domains_do_not_force_adaptive_bypass() {
        let relay_opts = RelayOptions {
            bypass_socks5_pool: vec!["127.0.0.1:19080".parse().expect("addr")],
            ..RelayOptions::default()
        };
        let target = TargetAddr::Domain("cdn.localizeapi.com".to_owned());
        let route_key =
            route_decision_key("cdn.localizeapi.com:443", &target, &EngineConfig::default());
        let candidates = select_route_candidates(
            &relay_opts,
            &target,
            443,
            &route_key,
            &EngineConfig::default(),
        );
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
        let localhost_key =
            route_decision_key("localhost:443", &localhost, &EngineConfig::default());
        let localhost_candidates = select_route_candidates(
            &relay_opts,
            &localhost,
            443,
            &localhost_key,
            &EngineConfig::default(),
        );
        assert_eq!(localhost_candidates.len(), 1);
        assert_eq!(localhost_candidates[0].kind, RouteKind::Direct);
        assert_eq!(localhost_candidates[0].source, "noise-bypass");

        let local = TargetAddr::Domain("printer.local".to_owned());
        let local_key = route_decision_key("printer.local:443", &local, &EngineConfig::default());
        let local_candidates = select_route_candidates(
            &relay_opts,
            &local,
            443,
            &local_key,
            &EngineConfig::default(),
        );
        assert_eq!(local_candidates.len(), 1);
        assert_eq!(local_candidates[0].kind, RouteKind::Direct);
        assert_eq!(local_candidates[0].source, "noise-bypass");
    }

    #[test]
    fn bypass_resolve_picker_prefers_ipv4_for_discord() {
        let ips = vec![
            "2a00:1450:4009:822::200e".parse().expect("ip"),
            "162.159.129.233".parse().expect("ip"),
        ];
        assert_eq!(
            pick_bypass_resolved_ip("discord.com", &ips, &EngineConfig::default()),
            Some("162.159.129.233".parse().expect("ip"))
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
        let ordered = ordered_route_candidates(route_key, candidates, &EngineConfig::default());
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].route_id(), "direct");
        clear_route_capabilities_for_test();
    }

    #[test]
    fn adaptive_route_weakens_and_recovers_after_cooldown() {
        let route_key = "adaptive-route-test:443|any";
        clear_route_state_for_test(route_key);
        let candidate =
            RouteCandidate::bypass("test", "127.0.0.1:19080".parse().expect("addr"), 0, 1);
        record_route_failure(
            route_key,
            &candidate,
            "unit-failure",
            &EngineConfig::default(),
        );
        record_route_failure(
            route_key,
            &candidate,
            "unit-failure",
            &EngineConfig::default(),
        );
        assert!(route_is_temporarily_weak(
            route_key,
            &candidate.route_id(),
            now_unix_secs()
        ));

        let health_map = &routing_state().dest_route_health;
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

        record_route_success(route_key, &candidate, &EngineConfig::default());
        let winner = route_winner_for_key(route_key, &EngineConfig::default()).expect("winner");
        assert_eq!(winner.route_id, candidate.route_id());
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn adaptive_route_reraces_when_cached_winner_is_unavailable() {
        let route_key = "adaptive-route-missing-winner:443|any";
        clear_route_state_for_test(route_key);
        routing_state().dest_route_winner.insert(
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
            route_race_decision(443, route_key, &candidates, &EngineConfig::default()),
            (true, RouteRaceReason::WinnerMissingFromCandidates)
        );
        clear_route_state_for_test(route_key);
    }

    #[test]
    fn adaptive_route_skips_race_when_cached_winner_is_healthy() {
        let route_key = "adaptive-route-healthy-winner:443|any";
        clear_route_state_for_test(route_key);
        routing_state().dest_route_winner.insert(
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
        let decision = route_race_decision(443, route_key, &candidates, &EngineConfig::default());
        assert_eq!(decision, (false, RouteRaceReason::WinnerHealthy));
        clear_route_state_for_test(route_key);
    }
}
