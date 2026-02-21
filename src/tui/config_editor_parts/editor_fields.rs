impl ConfigEditor {
    fn set_field(&mut self, field: &str, value: &str) -> Result<()> {
        match field {
            "template" => self.apply_template(value)?,
            "doh_enabled" => self.config.anticensorship.doh_enabled = parse_bool(value)?,
            "doh_providers" => self.config.anticensorship.doh_providers = parse_array(value),
            "dot_servers" => self.config.anticensorship.dot_servers = parse_array(value),
            "doq_servers" => self.config.anticensorship.doq_servers = parse_array(value),
            "dns_query_timeout_secs" => {
                self.config.anticensorship.dns_query_timeout_secs = parse_u64(value, 1, 300)?
            }
            "system_dns_enabled" => {
                self.config.anticensorship.system_dns_enabled = parse_bool(value)?
            }
            "http3_insecure_skip_verify" => {
                self.config.transport.http3_insecure_skip_verify = parse_bool(value)?
            }
            "http3_only" => self.config.transport.http3_only = parse_bool(value)?,
            "alpn_protocols" => self.config.tls.alpn_protocols = parse_array(value),
            "domain_fronting_enabled" => {
                self.config.anticensorship.domain_fronting_enabled = parse_bool(value)?
            }
            "tls_randomization_enabled" => {
                self.config.anticensorship.tls_randomization_enabled = parse_bool(value)?
            }
            "privacy_tracker_enabled" => {
                self.config.privacy.tracker_blocker.enabled = parse_bool(value)?
            }
            "privacy_tracker_mode" => {
                self.config.privacy.tracker_blocker.mode =
                    match value.trim().to_ascii_lowercase().as_str() {
                        "block" => crate::config::TrackerBlockerMode::Block,
                        "logonly" | "log_only" => crate::config::TrackerBlockerMode::LogOnly,
                        _ => {
                            return Err(EngineError::InvalidInput(
                                "privacy_tracker_mode должен быть block|log_only".to_owned(),
                            ))
                        }
                    }
            }
            "privacy_on_block" => {
                self.config.privacy.tracker_blocker.on_block =
                    match value.trim().to_ascii_lowercase().as_str() {
                        "error" => crate::config::TrackerBlockAction::Error,
                        "empty200" | "empty_200" => crate::config::TrackerBlockAction::Empty200,
                        _ => {
                            return Err(EngineError::InvalidInput(
                                "privacy_on_block должен быть error|empty_200".to_owned(),
                            ))
                        }
                    }
            }
            "privacy_allowlist" => {
                self.config.privacy.tracker_blocker.allowlist = parse_array(value)
            }
            "privacy_referer_enabled" => self.config.privacy.referer.enabled = parse_bool(value)?,
            "privacy_referer_mode" => {
                self.config.privacy.referer.mode = match value.trim().to_ascii_lowercase().as_str()
                {
                    "strip" => crate::config::RefererMode::Strip,
                    "originonly" | "origin_only" => crate::config::RefererMode::OriginOnly,
                    "passthrough" | "pass_through" | "pass-through" => {
                        crate::config::RefererMode::PassThrough
                    }
                    _ => {
                        return Err(EngineError::InvalidInput(
                            "privacy_referer_mode должен быть strip|origin_only|pass_through"
                                .to_owned(),
                        ))
                    }
                }
            }
            "privacy_search_strip" => {
                self.config.privacy.referer.strip_from_search_engines = parse_bool(value)?
            }
            "privacy_search_domains" => {
                self.config.privacy.referer.search_engine_domains = parse_array(value)
            }
            "privacy_send_dnt" => self.config.privacy.signals.send_dnt = parse_bool(value)?,
            "privacy_send_gpc" => self.config.privacy.signals.send_gpc = parse_bool(value)?,
            "privacy_headers_ua_enabled" => {
                self.config.privacy.user_agent.enabled = parse_bool(value)?
            }
            "privacy_headers_ua_preset" => {
                self.config.privacy.user_agent.preset =
                    match value.trim().to_ascii_lowercase().as_str() {
                        "chromewindows" | "chrome_windows" => UserAgentPreset::ChromeWindows,
                        "firefoxlinux" | "firefox_linux" => UserAgentPreset::FirefoxLinux,
                        "safarimacos" | "safari_macos" | "safari_mac_os" => {
                            UserAgentPreset::SafariMacOs
                        }
                        "custom" => UserAgentPreset::Custom,
                        _ => {
                            return Err(EngineError::InvalidInput(
                                "privacy_headers_ua_preset должен быть chrome_windows|firefox_linux|safari_macos|custom".to_owned(),
                            ))
                        }
                    }
            }
            "privacy_headers_ua_custom_value" => {
                self.config.privacy.user_agent.custom_value = value.to_owned()
            }
            "privacy_headers_referer_override_enabled" => {
                self.config.privacy.referer_override.enabled = parse_bool(value)?
            }
            "privacy_headers_referer_override_value" => {
                self.config.privacy.referer_override.value = value.to_owned()
            }
            "privacy_headers_ip_spoof_enabled" => {
                self.config.privacy.ip_spoof.enabled = parse_bool(value)?
            }
            "privacy_headers_ip_spoofed_ip" => {
                self.config.privacy.ip_spoof.spoofed_ip = value.to_owned()
            }
            "privacy_headers_webrtc_block_enabled" => {
                self.config.privacy.webrtc.block_enabled = parse_bool(value)?
            }
            "privacy_headers_location_api_block_enabled" => {
                self.config.privacy.location_api.block_enabled = parse_bool(value)?
            }
            "kind" => match value.trim().to_ascii_lowercase().as_str() {
                "direct" | "none" => self.config.pt = None,
                other => self.ensure_pt_for_kind(parse_pt_kind(other)?),
            },
            "local_socks5_bind" => {
                if let Some(pt) = self.config.pt.as_mut() {
                    pt.local_socks5_bind = value.to_owned();
                }
            }
            "trojan_server" => {
                self.ensure_pt_for_kind(PluggableTransportKind::Trojan);
                if let Some(pt) = self.config.pt.as_mut() {
                    if let Some(t) = pt.trojan.as_mut() {
                        t.server = value.to_owned();
                    }
                }
            }
            "trojan_password" => {
                self.ensure_pt_for_kind(PluggableTransportKind::Trojan);
                if let Some(pt) = self.config.pt.as_mut() {
                    if let Some(t) = pt.trojan.as_mut() {
                        t.password = value.to_owned();
                    }
                }
            }
            "trojan_sni" => {
                self.ensure_pt_for_kind(PluggableTransportKind::Trojan);
                if let Some(pt) = self.config.pt.as_mut() {
                    if let Some(t) = pt.trojan.as_mut() {
                        t.sni = if value.trim().is_empty() {
                            None
                        } else {
                            Some(value.trim().to_owned())
                        };
                    }
                }
            }
            "ss_server" => {
                self.ensure_pt_for_kind(PluggableTransportKind::Shadowsocks);
                if let Some(pt) = self.config.pt.as_mut() {
                    if let Some(s) = pt.shadowsocks.as_mut() {
                        s.server = value.to_owned();
                    }
                }
            }
            "ss_password" => {
                self.ensure_pt_for_kind(PluggableTransportKind::Shadowsocks);
                if let Some(pt) = self.config.pt.as_mut() {
                    if let Some(s) = pt.shadowsocks.as_mut() {
                        s.password = value.to_owned();
                    }
                }
            }
            "ss_method" => {
                self.ensure_pt_for_kind(PluggableTransportKind::Shadowsocks);
                if let Some(pt) = self.config.pt.as_mut() {
                    if let Some(s) = pt.shadowsocks.as_mut() {
                        s.method = value.to_owned();
                    }
                }
            }
            "initial_concurrency" => {
                self.config.download.initial_concurrency = parse_usize(value, 1, 64)?
            }
            "max_concurrency" => self.config.download.max_concurrency = parse_usize(value, 1, 128)?,
            "request_timeout_secs" => {
                self.config.download.request_timeout_secs = parse_u64(value, 1, 300)?
            }
            "mode" => {
                self.config.system_proxy.mode = match value.trim().to_ascii_lowercase().as_str() {
                    "off" => SystemProxyMode::Off,
                    "all" => SystemProxyMode::All,
                    "pac" => SystemProxyMode::Pac,
                    "custom" => SystemProxyMode::Custom,
                    _ => {
                        return Err(EngineError::InvalidInput(
                            "mode должен быть off|all|pac|custom".to_owned(),
                        ))
                    }
                };
            }
            "socks_endpoint" => {
                self.config.system_proxy.socks_endpoint = value.to_owned();
                if let Some(pt) = self.config.pt.as_mut() {
                    pt.local_socks5_bind = value.to_owned();
                }
            }
            "pac_port" => self.config.system_proxy.pac_port = parse_u16(value, 1, 65535)?,
            "enabled" => self.config.blocklist.enabled = parse_bool(value)?,
            "source" => self.config.blocklist.source = value.to_owned(),
            "auto_update" => self.config.blocklist.auto_update = parse_bool(value)?,
            "repo" => self.config.updater.repo = value.to_owned(),
            "check_interval_hours" => {
                self.config.updater.check_interval_hours = parse_u64(value, 1, 720)?
            }
            _ => {
                return Err(EngineError::InvalidInput(format!(
                    "неизвестное поле: {field}"
                )))
            }
        }
        Ok(())
    }

    fn fields_for_section(&self) -> Vec<(String, String, FieldKind, String)> {
        let all = match self.current_section {
            Section::Dns => vec![
                item(
                    "doh_enabled",
                    self.get_field("doh_enabled"),
                    FieldKind::Bool,
                    "Включить DNS-over-HTTPS",
                ),
                item(
                    "doh_providers",
                    self.get_field("doh_providers"),
                    FieldKind::Array,
                    "Список DoH-провайдеров",
                ),
                item(
                    "dot_servers",
                    self.get_field("dot_servers"),
                    FieldKind::Array,
                    "DoT upstream-серверы",
                ),
                item(
                    "doq_servers",
                    self.get_field("doq_servers"),
                    FieldKind::Array,
                    "DoQ upstream-серверы",
                ),
                item(
                    "dns_query_timeout_secs",
                    self.get_field("dns_query_timeout_secs"),
                    FieldKind::Number,
                    "Таймаут DNS-запроса в секундах",
                ),
                item(
                    "system_dns_enabled",
                    self.get_field("system_dns_enabled"),
                    FieldKind::Bool,
                    "Разрешить fallback на системный DNS",
                ),
            ],
            Section::Tls => vec![
                item(
                    "http3_insecure_skip_verify",
                    self.get_field("http3_insecure_skip_verify"),
                    FieldKind::Bool,
                    "Опасно: пропускать проверку сертификата для HTTP/3",
                ),
                item(
                    "alpn_protocols",
                    self.get_field("alpn_protocols"),
                    FieldKind::Array,
                    "Порядок ALPN",
                ),
                item(
                    "http3_only",
                    self.get_field("http3_only"),
                    FieldKind::Bool,
                    "Требовать только HTTP/3",
                ),
            ],
            Section::Anticensorship => vec![
                item(
                    "domain_fronting_enabled",
                    self.get_field("domain_fronting_enabled"),
                    FieldKind::Bool,
                    "Включить domain fronting",
                ),
                item(
                    "tls_randomization_enabled",
                    self.get_field("tls_randomization_enabled"),
                    FieldKind::Bool,
                    "Включить рандомизацию TLS",
                ),
            ],
            Section::Privacy => vec![
                item(
                    "privacy_tracker_enabled",
                    self.get_field("privacy_tracker_enabled"),
                    FieldKind::Bool,
                    "Блокировать известные трекеры до отправки запроса",
                ),
                item(
                    "privacy_tracker_mode",
                    self.get_field("privacy_tracker_mode"),
                    FieldKind::Text,
                    "Режим: block|log_only",
                ),
                item(
                    "privacy_on_block",
                    self.get_field("privacy_on_block"),
                    FieldKind::Text,
                    "Ответ при блоке: error|empty_200",
                ),
                item(
                    "privacy_allowlist",
                    self.get_field("privacy_allowlist"),
                    FieldKind::Array,
                    "Домены-исключения (allowlist)",
                ),
                item(
                    "privacy_referer_enabled",
                    self.get_field("privacy_referer_enabled"),
                    FieldKind::Bool,
                    "Управление утечками Referer между доменами",
                ),
                item(
                    "privacy_referer_mode",
                    self.get_field("privacy_referer_mode"),
                    FieldKind::Text,
                    "strip | origin_only | pass_through",
                ),
                item(
                    "privacy_search_strip",
                    self.get_field("privacy_search_strip"),
                    FieldKind::Bool,
                    "Всегда убирать Referer с поисковиков",
                ),
                item(
                    "privacy_search_domains",
                    self.get_field("privacy_search_domains"),
                    FieldKind::Array,
                    "Дополнительные домены поисковиков",
                ),
                item(
                    "privacy_send_dnt",
                    self.get_field("privacy_send_dnt"),
                    FieldKind::Bool,
                    "DNT: 1 (устаревший сигнал приватности)",
                ),
                item(
                    "privacy_send_gpc",
                    self.get_field("privacy_send_gpc"),
                    FieldKind::Bool,
                    "Sec-GPC: 1 (юридически значимый сигнал приватности)",
                ),
            ],
            Section::PrivacyHeaders => vec![
                item(
                    "privacy_headers_ua_enabled",
                    self.get_field("privacy_headers_ua_enabled"),
                    FieldKind::Bool,
                    "Включить подмену User-Agent",
                ),
                item(
                    "privacy_headers_ua_preset",
                    self.get_field("privacy_headers_ua_preset"),
                    FieldKind::Text,
                    "chrome_windows | firefox_linux | safari_macos | custom",
                ),
                item(
                    "privacy_headers_ua_custom_value",
                    self.get_field("privacy_headers_ua_custom_value"),
                    FieldKind::Text,
                    "Пользовательская строка User-Agent при preset=custom",
                ),
                item(
                    "privacy_headers_referer_override_enabled",
                    self.get_field("privacy_headers_referer_override_enabled"),
                    FieldKind::Bool,
                    "Принудительно подставлять статический Referer в каждый запрос",
                ),
                item(
                    "privacy_headers_referer_override_value",
                    self.get_field("privacy_headers_referer_override_value"),
                    FieldKind::Text,
                    "Значение подмены Referer",
                ),
                item(
                    "privacy_headers_ip_spoof_enabled",
                    self.get_field("privacy_headers_ip_spoof_enabled"),
                    FieldKind::Bool,
                    "Добавлять X-Forwarded-For / X-Real-IP",
                ),
                item(
                    "privacy_headers_ip_spoofed_ip",
                    self.get_field("privacy_headers_ip_spoofed_ip"),
                    FieldKind::Text,
                    "Подменный IP-адрес",
                ),
                item(
                    "privacy_headers_webrtc_block_enabled",
                    self.get_field("privacy_headers_webrtc_block_enabled"),
                    FieldKind::Bool,
                    "Добавлять сигнал Permissions-Policy для WebRTC",
                ),
                item(
                    "privacy_headers_location_api_block_enabled",
                    self.get_field("privacy_headers_location_api_block_enabled"),
                    FieldKind::Bool,
                    "Добавлять сигнал Permissions-Policy для geolocation",
                ),
            ],
            Section::Pt => {
                let mut v = vec![
                    item("kind", self.get_field("kind"), FieldKind::Text, "Тип PT"),
                    item(
                        "local_socks5_bind",
                        self.get_field("local_socks5_bind"),
                        FieldKind::Text,
                        "Локальный endpoint привязки SOCKS5",
                    ),
                ];
                match self.config.pt.as_ref().map(|v| &v.kind) {
                    Some(PluggableTransportKind::Trojan) => {
                        v.push(item(
                            "trojan_server",
                            self.get_field("trojan_server"),
                            FieldKind::Text,
                            "Адрес trojan-сервера host:port",
                        ));
                        v.push(item(
                            "trojan_password",
                            self.get_field("trojan_password"),
                            FieldKind::Text,
                            "Пароль trojan",
                        ));
                        v.push(item(
                            "trojan_sni",
                            self.get_field("trojan_sni"),
                            FieldKind::Text,
                            "Необязательный TLS SNI (пусто = авто)",
                        ));
                    }
                    Some(PluggableTransportKind::Shadowsocks) => {
                        v.push(item(
                            "ss_server",
                            self.get_field("ss_server"),
                            FieldKind::Text,
                            "Адрес shadowsocks-сервера host:port",
                        ));
                        v.push(item(
                            "ss_password",
                            self.get_field("ss_password"),
                            FieldKind::Text,
                            "Пароль shadowsocks",
                        ));
                        v.push(item(
                            "ss_method",
                            self.get_field("ss_method"),
                            FieldKind::Text,
                            "Метод шифрования (например, chacha20-ietf-poly1305)",
                        ));
                    }
                    _ => {}
                }
                v
            }
            Section::Download => vec![
                item(
                    "initial_concurrency",
                    self.get_field("initial_concurrency"),
                    FieldKind::Number,
                    "Начальное число параллельных чанков",
                ),
                item(
                    "max_concurrency",
                    self.get_field("max_concurrency"),
                    FieldKind::Number,
                    "Максимальное число параллельных чанков",
                ),
                item(
                    "request_timeout_secs",
                    self.get_field("request_timeout_secs"),
                    FieldKind::Number,
                    "Таймаут запроса (сек)",
                ),
            ],
            Section::SystemProxy => vec![
                item(
                    "template",
                    self.get_field("template"),
                    FieldKind::Text,
                    "Быстрый профиль: direct|trojan|shadowsocks",
                ),
                item(
                    "mode",
                    self.get_field("mode"),
                    FieldKind::Text,
                    "Режим системного прокси",
                ),
                item(
                    "socks_endpoint",
                    self.get_field("socks_endpoint"),
                    FieldKind::Text,
                    "Адрес SOCKS5 endpoint в формате host:port",
                ),
                item(
                    "pac_port",
                    self.get_field("pac_port"),
                    FieldKind::Number,
                    "Порт PAC-сервера",
                ),
            ],
            Section::Blocklist => vec![
                item(
                    "enabled",
                    self.get_field("enabled"),
                    FieldKind::Bool,
                    "Включить блоклист",
                ),
                item(
                    "source",
                    self.get_field("source"),
                    FieldKind::Text,
                    "URL источника РКН",
                ),
                item(
                    "auto_update",
                    self.get_field("auto_update"),
                    FieldKind::Bool,
                    "Автообновление блоклиста",
                ),
            ],
            Section::Updater => vec![
                item(
                    "repo",
                    self.get_field("repo"),
                    FieldKind::Text,
                    "GitHub репозиторий owner/name",
                ),
                item(
                    "check_interval_hours",
                    self.get_field("check_interval_hours"),
                    FieldKind::Number,
                    "Интервал автопроверки",
                ),
            ],
        };
        match self.ux_mode {
            UxMode::Advanced => all,
            UxMode::Simple => all
                .into_iter()
                .filter(|(name, _value, _kind, _help)| {
                    self.field_visible_in_simple_mode(self.current_section, name)
                })
                .collect(),
        }
    }

    fn current_context_help(&self) -> String {
        let section_line = format!(
            "Раздел [{}]: {}",
            section_key(self.current_section),
            section_desc(self.current_section)
        );
        let field_line = self
            .selected_field_help()
            .unwrap_or_else(|| "Поля недоступны для выбранного раздела".to_owned());
        format!("{section_line}\n\n{field_line}\n\nПодсказка: Enter редактирует, bool-поля переключаются сразу.")
    }

    fn visible_sections(&self) -> Vec<Section> {
        match self.ux_mode {
            UxMode::Advanced => vec![
                Section::Dns,
                Section::Tls,
                Section::Anticensorship,
                Section::Privacy,
                Section::PrivacyHeaders,
                Section::Pt,
                Section::Download,
                Section::SystemProxy,
                Section::Blocklist,
                Section::Updater,
            ],
            UxMode::Simple => vec![
                Section::Dns,
                Section::Privacy,
                Section::PrivacyHeaders,
                Section::SystemProxy,
                Section::Pt,
                Section::Blocklist,
            ],
        }
    }

    fn ensure_selected_section_visible(&mut self) {
        let visible = self.visible_sections();
        if let Some(idx) = visible
            .iter()
            .position(|section| *section == self.current_section)
        {
            self.selected_section_idx = idx;
        } else {
            self.selected_section_idx = 0;
            self.current_section = visible.first().copied().unwrap_or(Section::Dns);
        }
        let max_field_idx = self.fields_for_section().len().saturating_sub(1);
        self.selected_field_idx = self.selected_field_idx.min(max_field_idx);
    }

    fn field_visible_in_simple_mode(&self, section: Section, name: &str) -> bool {
        match section {
            Section::Dns => matches!(name, "doh_enabled" | "doh_providers" | "system_dns_enabled"),
            Section::Privacy => matches!(
                name,
                "privacy_tracker_enabled"
                    | "privacy_referer_enabled"
                    | "privacy_referer_mode"
                    | "privacy_send_gpc"
            ),
            Section::PrivacyHeaders => matches!(
                name,
                "privacy_headers_ua_enabled"
                    | "privacy_headers_ua_preset"
                    | "privacy_headers_referer_override_enabled"
                    | "privacy_headers_ip_spoof_enabled"
                    | "privacy_headers_webrtc_block_enabled"
                    | "privacy_headers_location_api_block_enabled"
            ),
            Section::SystemProxy => matches!(name, "template" | "mode" | "socks_endpoint"),
            Section::Pt => matches!(
                name,
                "kind"
                    | "local_socks5_bind"
                    | "trojan_server"
                    | "trojan_password"
                    | "trojan_sni"
                    | "ss_server"
                    | "ss_password"
                    | "ss_method"
            ),
            Section::Blocklist => matches!(name, "enabled" | "auto_update"),
            _ => false,
        }
    }

}
