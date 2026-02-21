impl ConfigEditor {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            current_section: Section::Dns,
            current_field: None,
            edit_history: Vec::new(),
            validation_errors: HashMap::new(),
            selected_section_idx: 0,
            selected_field_idx: 0,
            edit_input: None,
            pending_save: false,
            pending_diff: Vec::new(),
            help_text: None,
            template_wizard_open: false,
            redo_history: Vec::new(),
            ux_mode: UxMode::Advanced,
        }
    }

    pub fn set_ux_mode(&mut self, mode: UxMode) {
        self.ux_mode = mode;
        self.template_wizard_open = false;
        self.ensure_selected_section_visible();
    }

    pub fn render(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(14),
                Constraint::Min(8),
                Constraint::Length(3),
            ])
            .split(area);
        let sections = self.visible_sections();
        let left = sections
            .iter()
            .enumerate()
            .map(|(idx, section)| {
                let style = if idx == self.selected_section_idx {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("[{}]", section_key(*section)), style),
                    Span::raw(format!("  {}", section_desc(*section))),
                ]))
            })
            .collect::<Vec<_>>();

        frame.render_widget(
            List::new(left).block(
                Block::default()
                    .title(match self.ux_mode {
                        UxMode::Simple => "Редактор конфигурации (простой)",
                        UxMode::Advanced => "Редактор конфигурации (продвинутый)",
                    })
                    .borders(Borders::ALL),
            ),
            chunks[0],
        );

        let middle = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(chunks[1]);

        let fields = self.fields_for_section();
        let field_items = fields
            .iter()
            .enumerate()
            .map(|(idx, (name, value, _kind, _help))| {
                let key = format!("{}.{}", section_key(self.current_section), name);
                let mut style = Style::default();
                if idx == self.selected_field_idx {
                    style = style.fg(Color::Yellow).add_modifier(Modifier::BOLD);
                }
                if self.validation_errors.contains_key(&key) {
                    style = style.fg(Color::Red);
                }
                ListItem::new(Line::from(Span::styled(format!("{name} = {value}"), style)))
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            List::new(field_items).block(
                Block::default()
                    .title(format!(
                        "[{}] Редактор раздела",
                        section_key(self.current_section)
                    ))
                    .borders(Borders::ALL),
            ),
            middle[0],
        );

        frame.render_widget(
            Paragraph::new(self.current_context_help())
                .block(
                    Block::default()
                        .title("Подсказка по выбранному пункту")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: true }),
            middle[1],
        );

        let footer = if self.pending_save {
            "Есть несохраненные изменения: [y] подтвердить  [n] отмена"
        } else {
            "[Up/Down] поля  [Left/Right] разделы  [Enter/e] редактировать  [p] следующий шаблон  [t] мастер шаблонов  [s] сохранить  [r] перезагрузить  [Ctrl+Z/Ctrl+Y] отмена/повтор  [?] справка"
        };
        frame.render_widget(
            Paragraph::new(footer).block(Block::default().borders(Borders::ALL)),
            chunks[2],
        );

        if let Some(input) = &self.edit_input {
            self.render_popup(frame, area, "Редактирование значения", input);
        } else if self.pending_save {
            self.render_popup(
                frame,
                area,
                "Изменения перед сохранением",
                &self.pending_diff.join("\n"),
            );
        } else if let Some(help) = &self.help_text {
            self.render_popup(frame, area, "Справка", help);
        } else if self.template_wizard_open {
            self.render_popup(frame, area, "Мастер шаблонов", &self.template_wizard_text());
        }
    }

    pub fn handle_input(&mut self, key: KeyEvent) -> Result<Action> {
        if let Some(buf) = &mut self.edit_input {
            match key.code {
                KeyCode::Esc => {
                    self.edit_input = None;
                    return Ok(Action::None);
                }
                KeyCode::Enter => {
                    let value = buf.clone();
                    self.edit_input = None;
                    self.apply_edit_value(&value)?;
                    return Ok(Action::None);
                }
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char(c) => {
                    buf.push(c);
                }
                _ => {}
            }
            return Ok(Action::None);
        }

        if self.pending_save {
            match key.code {
                KeyCode::Char('y') => {
                    self.pending_save = false;
                    return Ok(Action::Saved);
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.pending_save = false;
                    self.pending_diff.clear();
                    return Ok(Action::None);
                }
                _ => return Ok(Action::None),
            }
        }

        if self.help_text.is_some() {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                self.help_text = None;
            }
            return Ok(Action::None);
        }

        if self.template_wizard_open {
            match key.code {
                KeyCode::Esc => {
                    self.template_wizard_open = false;
                }
                KeyCode::Char('1') => {
                    self.push_history();
                    self.apply_template("direct")?;
                    self.template_wizard_open = false;
                }
                KeyCode::Char('2') => {
                    self.push_history();
                    self.apply_template("trojan")?;
                    self.template_wizard_open = false;
                }
                KeyCode::Char('3') => {
                    self.push_history();
                    self.apply_template("shadowsocks")?;
                    self.template_wizard_open = false;
                }
                _ => {}
            }
            return Ok(Action::None);
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('z')) {
            self.undo();
            return Ok(Action::None);
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('y')) {
            self.redo();
            return Ok(Action::None);
        }

        match key.code {
            KeyCode::Esc => Ok(Action::Back),
            KeyCode::Up => {
                self.selected_field_idx = self.selected_field_idx.saturating_sub(1);
                Ok(Action::None)
            }
            KeyCode::Down => {
                let max = self.fields_for_section().len().saturating_sub(1);
                self.selected_field_idx = (self.selected_field_idx + 1).min(max);
                Ok(Action::None)
            }
            KeyCode::Left => {
                self.selected_section_idx = self.selected_section_idx.saturating_sub(1);
                let sections = self.visible_sections();
                if let Some(section) = sections.get(self.selected_section_idx) {
                    self.current_section = *section;
                }
                self.selected_field_idx = 0;
                Ok(Action::None)
            }
            KeyCode::Right => {
                let sections = self.visible_sections();
                self.selected_section_idx =
                    (self.selected_section_idx + 1).min(sections.len().saturating_sub(1));
                if let Some(section) = sections.get(self.selected_section_idx) {
                    self.current_section = *section;
                }
                self.selected_field_idx = 0;
                Ok(Action::None)
            }
            KeyCode::Enter | KeyCode::Char('e') => self.start_edit_selected(),
            KeyCode::Char('?') => {
                self.help_text = self.selected_field_help();
                Ok(Action::None)
            }
            KeyCode::Char('s') => {
                self.pending_diff = self.diff_preview();
                self.pending_save = true;
                Ok(Action::SaveRequested)
            }
            KeyCode::Char('p') => {
                self.push_history();
                self.cycle_template()?;
                Ok(Action::None)
            }
            KeyCode::Char('t') => {
                self.template_wizard_open = true;
                Ok(Action::None)
            }
            KeyCode::Char('r') => Ok(Action::Reloaded),
            _ => Ok(Action::None),
        }
    }

    pub fn validate_current(&self) -> std::result::Result<(), ValidationError> {
        self.config.validate().map_err(|e| ValidationError {
            message: e.to_string(),
            field_errors: HashMap::new(),
        })
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        self.validate_current()
            .map_err(|e| EngineError::Config(e.message))?;
        let rendered = toml::to_string_pretty(&self.config)
            .map_err(|e| EngineError::Config(format!("ошибка сериализации toml: {e}")))?;
        let doc = toml_edit::DocumentMut::from_str(&rendered)
            .map_err(|e| EngineError::Config(format!("ошибка разбора toml: {e}")))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, doc.to_string())?;
        Ok(())
    }

    pub fn reload_from_file(&mut self, path: &Path) -> Result<()> {
        let raw = fs::read_to_string(path)?;
        let cfg = toml::from_str::<EngineConfig>(&raw)
            .map_err(|e| EngineError::Config(format!("ошибка разбора конфига: {e}")))?;
        self.push_history();
        self.config = cfg;
        self.validation_errors.clear();
        Ok(())
    }

    fn start_edit_selected(&mut self) -> Result<Action> {
        let fields = self.fields_for_section();
        if fields.is_empty() {
            return Ok(Action::None);
        }
        let (key, value, kind, _) = fields[self.selected_field_idx].clone();
        self.current_field = Some(key.clone());
        match kind {
            FieldKind::Bool => {
                self.push_history();
                self.toggle_bool(&key)?;
            }
            _ => {
                self.edit_input = Some(value);
            }
        }
        Ok(Action::None)
    }

    fn apply_edit_value(&mut self, value: &str) -> Result<()> {
        let Some(field) = self.current_field.clone() else {
            return Ok(());
        };
        self.push_history();
        self.set_field(&field, value)?;
        match self.validate_current() {
            Ok(_) => {
                self.validation_errors.clear();
            }
            Err(e) => {
                self.validation_errors.insert(field, e.message.to_owned());
            }
        }
        Ok(())
    }

    fn push_history(&mut self) {
        self.edit_history.push(ConfigSnapshot {
            config: self.config.clone(),
            current_section: self.current_section,
            selected_field_idx: self.selected_field_idx,
        });
        if self.edit_history.len() > 10 {
            self.edit_history.remove(0);
        }
        self.redo_history.clear();
    }

    fn undo(&mut self) {
        if let Some(snapshot) = self.edit_history.pop() {
            self.redo_history.push(ConfigSnapshot {
                config: self.config.clone(),
                current_section: self.current_section,
                selected_field_idx: self.selected_field_idx,
            });
            self.config = snapshot.config;
            self.current_section = snapshot.current_section;
            self.selected_field_idx = snapshot.selected_field_idx;
            self.selected_section_idx = section_idx(self.current_section);
            self.ensure_selected_section_visible();
        }
    }

    fn redo(&mut self) {
        if let Some(snapshot) = self.redo_history.pop() {
            self.edit_history.push(ConfigSnapshot {
                config: self.config.clone(),
                current_section: self.current_section,
                selected_field_idx: self.selected_field_idx,
            });
            self.config = snapshot.config;
            self.current_section = snapshot.current_section;
            self.selected_field_idx = snapshot.selected_field_idx;
            self.selected_section_idx = section_idx(self.current_section);
            self.ensure_selected_section_visible();
        }
    }

    fn diff_preview(&self) -> Vec<String> {
        let Some(prev) = self.edit_history.last() else {
            return vec!["Нет предыдущего снимка".to_owned()];
        };
        let old = toml::to_string_pretty(&prev.config).unwrap_or_default();
        let new = toml::to_string_pretty(&self.config).unwrap_or_default();
        let old_lines: Vec<_> = old.lines().collect();
        let new_lines: Vec<_> = new.lines().collect();
        let mut diff = Vec::new();
        let max = old_lines.len().max(new_lines.len());
        for idx in 0..max {
            let a = old_lines.get(idx).copied().unwrap_or("");
            let b = new_lines.get(idx).copied().unwrap_or("");
            if a != b {
                diff.push(format!("- {a}"));
                diff.push(format!("+ {b}"));
            }
            if diff.len() >= 16 {
                break;
            }
        }
        if diff.is_empty() {
            diff.push("Изменений нет".to_owned());
        }
        diff
    }

    fn render_popup(&self, frame: &mut ratatui::Frame, area: Rect, title: &str, body: &str) {
        let popup = centered_rect(80, 60, area);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(body)
                .block(Block::default().title(title).borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            popup,
        );
    }

    fn selected_field_help(&self) -> Option<String> {
        let fields = self.fields_for_section();
        fields
            .get(self.selected_field_idx)
            .map(|(name, _value, _kind, help)| format!("{}: {}", name, help))
    }

    fn toggle_bool(&mut self, field: &str) -> Result<()> {
        let current = self.get_field(field).unwrap_or_else(|| "false".to_owned());
        let next = if current.eq_ignore_ascii_case("true") {
            "false"
        } else {
            "true"
        };
        self.set_field(field, next)
    }

    fn current_template_name(&self) -> &'static str {
        match self.config.pt.as_ref().map(|p| &p.kind) {
            None => "direct",
            Some(PluggableTransportKind::Trojan) => "trojan",
            Some(PluggableTransportKind::Shadowsocks) => "shadowsocks",
            Some(PluggableTransportKind::Snowflake) => "direct",
            Some(PluggableTransportKind::Obfs4) => "direct",
        }
    }

    fn apply_template(&mut self, value: &str) -> Result<()> {
        let template = value.trim().to_ascii_lowercase();
        match template.as_str() {
            "direct" | "none" => {
                self.config.pt = None;
            }
            "trojan" => {
                self.ensure_pt_for_kind(PluggableTransportKind::Trojan);
            }
            "shadowsocks" | "ss" => {
                self.ensure_pt_for_kind(PluggableTransportKind::Shadowsocks);
            }
            _ => {
                return Err(EngineError::InvalidInput(
                    "шаблон должен быть direct|trojan|shadowsocks".to_owned(),
                ));
            }
        }
        self.config.system_proxy.auto_configure = true;
        self.config.system_proxy.mode = SystemProxyMode::All;
        self.ensure_selected_section_visible();
        Ok(())
    }

    fn cycle_template(&mut self) -> Result<()> {
        let next = match self.current_template_name() {
            "direct" => "trojan",
            "trojan" => "shadowsocks",
            "shadowsocks" => "direct",
            _ => "direct",
        };
        self.apply_template(next)
    }

    fn template_wizard_text(&self) -> String {
        let current = self.current_template_name();
        format!(
            "Текущий шаблон: {current}\n\n1) direct       - локальный прокси без обхода\n2) trojan       - использовать ваш trojan-сервер\n3) shadowsocks  - использовать ваш shadowsocks-сервер\n\nНажмите [1-3] для применения, [Esc] для закрытия."
        )
    }

    fn ensure_pt_for_kind(&mut self, kind: PluggableTransportKind) {
        let mut pt = self.config.pt.clone().unwrap_or_else(default_pt_config);
        pt.kind = kind.clone();
        pt.local_socks5_bind = self.config.system_proxy.socks_endpoint.clone();
        match kind {
            PluggableTransportKind::Trojan => {
                if pt.trojan.is_none() {
                    pt.trojan = Some(TrojanPtConfig {
                        server: "server.example.com:443".to_owned(),
                        password: "change-me".to_owned(),
                        sni: Some("server.example.com".to_owned()),
                        alpn_protocols: vec!["http/1.1".to_owned()],
                        insecure_skip_verify: false,
                    });
                }
            }
            PluggableTransportKind::Shadowsocks => {
                if pt.shadowsocks.is_none() {
                    pt.shadowsocks = Some(ShadowsocksPtConfig {
                        server: "server.example.com:443".to_owned(),
                        password: "change-me".to_owned(),
                        method: "chacha20-ietf-poly1305".to_owned(),
                    });
                }
            }
            PluggableTransportKind::Snowflake | PluggableTransportKind::Obfs4 => {}
        }
        self.config.pt = Some(pt);
    }

    fn get_field(&self, field: &str) -> Option<String> {
        match field {
            "template" => Some(self.current_template_name().to_owned()),
            "doh_enabled" => Some(self.config.anticensorship.doh_enabled.to_string()),
            "doh_providers" => Some(format!("{:?}", self.config.anticensorship.doh_providers)),
            "dot_servers" => Some(format!("{:?}", self.config.anticensorship.dot_servers)),
            "doq_servers" => Some(format!("{:?}", self.config.anticensorship.doq_servers)),
            "dns_query_timeout_secs" => Some(
                self.config
                    .anticensorship
                    .dns_query_timeout_secs
                    .to_string(),
            ),
            "system_dns_enabled" => Some(self.config.anticensorship.system_dns_enabled.to_string()),
            "alpn_protocols" => Some(format!("{:?}", self.config.tls.alpn_protocols)),
            "http3_insecure_skip_verify" => {
                Some(self.config.transport.http3_insecure_skip_verify.to_string())
            }
            "http3_only" => Some(self.config.transport.http3_only.to_string()),
            "domain_fronting_enabled" => Some(
                self.config
                    .anticensorship
                    .domain_fronting_enabled
                    .to_string(),
            ),
            "tls_randomization_enabled" => Some(
                self.config
                    .anticensorship
                    .tls_randomization_enabled
                    .to_string(),
            ),
            "privacy_tracker_enabled" => {
                Some(self.config.privacy.tracker_blocker.enabled.to_string())
            }
            "privacy_tracker_mode" => {
                Some(format!("{:?}", self.config.privacy.tracker_blocker.mode))
            }
            "privacy_on_block" => Some(format!(
                "{:?}",
                self.config.privacy.tracker_blocker.on_block
            )),
            "privacy_allowlist" => Some(format!(
                "{:?}",
                self.config.privacy.tracker_blocker.allowlist
            )),
            "privacy_referer_enabled" => Some(self.config.privacy.referer.enabled.to_string()),
            "privacy_referer_mode" => Some(format!("{:?}", self.config.privacy.referer.mode)),
            "privacy_search_strip" => Some(
                self.config
                    .privacy
                    .referer
                    .strip_from_search_engines
                    .to_string(),
            ),
            "privacy_search_domains" => Some(format!(
                "{:?}",
                self.config.privacy.referer.search_engine_domains
            )),
            "privacy_send_dnt" => Some(self.config.privacy.signals.send_dnt.to_string()),
            "privacy_send_gpc" => Some(self.config.privacy.signals.send_gpc.to_string()),
            "privacy_headers_ua_enabled" => {
                Some(self.config.privacy.user_agent.enabled.to_string())
            }
            "privacy_headers_ua_preset" => {
                Some(format!("{:?}", self.config.privacy.user_agent.preset))
            }
            "privacy_headers_ua_custom_value" => {
                Some(self.config.privacy.user_agent.custom_value.clone())
            }
            "privacy_headers_referer_override_enabled" => {
                Some(self.config.privacy.referer_override.enabled.to_string())
            }
            "privacy_headers_referer_override_value" => {
                Some(self.config.privacy.referer_override.value.clone())
            }
            "privacy_headers_ip_spoof_enabled" => {
                Some(self.config.privacy.ip_spoof.enabled.to_string())
            }
            "privacy_headers_ip_spoofed_ip" => {
                Some(self.config.privacy.ip_spoof.spoofed_ip.clone())
            }
            "privacy_headers_webrtc_block_enabled" => {
                Some(self.config.privacy.webrtc.block_enabled.to_string())
            }
            "privacy_headers_location_api_block_enabled" => {
                Some(self.config.privacy.location_api.block_enabled.to_string())
            }
            "kind" => Some(
                self.config
                    .pt
                    .as_ref()
                    .map(|v| format!("{:?}", v.kind))
                    .unwrap_or_else(|| "direct".to_owned()),
            ),
            "local_socks5_bind" => Some(
                self.config
                    .pt
                    .as_ref()
                    .map(|v| v.local_socks5_bind.clone())
                    .unwrap_or_else(|| self.config.system_proxy.socks_endpoint.clone()),
            ),
            "trojan_server" => self
                .config
                .pt
                .as_ref()
                .and_then(|v| v.trojan.as_ref().map(|t| t.server.clone())),
            "trojan_password" => self
                .config
                .pt
                .as_ref()
                .and_then(|v| v.trojan.as_ref().map(|t| t.password.clone())),
            "trojan_sni" => self
                .config
                .pt
                .as_ref()
                .and_then(|v| v.trojan.as_ref().and_then(|t| t.sni.clone())),
            "ss_server" => self
                .config
                .pt
                .as_ref()
                .and_then(|v| v.shadowsocks.as_ref().map(|s| s.server.clone())),
            "ss_password" => self
                .config
                .pt
                .as_ref()
                .and_then(|v| v.shadowsocks.as_ref().map(|s| s.password.clone())),
            "ss_method" => self
                .config
                .pt
                .as_ref()
                .and_then(|v| v.shadowsocks.as_ref().map(|s| s.method.clone())),
            "initial_concurrency" => Some(self.config.download.initial_concurrency.to_string()),
            "max_concurrency" => Some(self.config.download.max_concurrency.to_string()),
            "request_timeout_secs" => Some(self.config.download.request_timeout_secs.to_string()),
            "mode" => Some(format!("{:?}", self.config.system_proxy.mode)),
            "socks_endpoint" => Some(self.config.system_proxy.socks_endpoint.clone()),
            "pac_port" => Some(self.config.system_proxy.pac_port.to_string()),
            "enabled" => Some(self.config.blocklist.enabled.to_string()),
            "source" => Some(self.config.blocklist.source.clone()),
            "auto_update" => Some(self.config.blocklist.auto_update.to_string()),
            "repo" => Some(self.config.updater.repo.clone()),
            "check_interval_hours" => Some(self.config.updater.check_interval_hours.to_string()),
            _ => None,
        }
    }

}
