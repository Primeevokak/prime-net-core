use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};

use crate::config::{
    EngineConfig, PluggableTransportConfig, PluggableTransportKind, ShadowsocksPtConfig,
    SystemProxyMode, TrojanPtConfig, UserAgentPreset,
};
use crate::error::{EngineError, Result};

#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    pub config: EngineConfig,
    pub current_section: Section,
    pub selected_field_idx: usize,
}

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub message: String,
    pub field_errors: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Back,
    SaveRequested,
    Saved,
    Reloaded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Dns,
    Tls,
    Anticensorship,
    Privacy,
    PrivacyHeaders,
    Pt,
    Download,
    SystemProxy,
    Blocklist,
    Updater,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UxMode {
    Simple,
    Advanced,
}

pub struct ConfigEditor {
    pub config: EngineConfig,
    pub current_section: Section,
    pub current_field: Option<String>,
    pub edit_history: Vec<ConfigSnapshot>,
    pub validation_errors: HashMap<String, String>,
    selected_section_idx: usize,
    selected_field_idx: usize,
    edit_input: Option<String>,
    pending_save: bool,
    pending_diff: Vec<String>,
    help_text: Option<String>,
    template_wizard_open: bool,
    redo_history: Vec<ConfigSnapshot>,
    ux_mode: UxMode,
}

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

#[derive(Clone)]
enum FieldKind {
    Bool,
    Number,
    Text,
    Array,
}

fn item(
    name: &str,
    value: Option<String>,
    kind: FieldKind,
    help: &str,
) -> (String, String, FieldKind, String) {
    (
        name.to_owned(),
        value.unwrap_or_else(|| "<нет>".to_owned()),
        kind,
        help.to_owned(),
    )
}

fn section_idx(section: Section) -> usize {
    match section {
        Section::Dns => 0,
        Section::Tls => 1,
        Section::Anticensorship => 2,
        Section::Privacy => 3,
        Section::PrivacyHeaders => 4,
        Section::Pt => 5,
        Section::Download => 6,
        Section::SystemProxy => 7,
        Section::Blocklist => 8,
        Section::Updater => 9,
    }
}

fn section_desc(section: Section) -> &'static str {
    match section {
        Section::Dns => "Выбор DNS и резервирования. Влияет на доступ к сайтам и утечки DNS.",
        Section::Tls => "Тонкие параметры TLS/HTTP3. Может ломать совместимость при ошибках.",
        Section::Anticensorship => {
            "Механики обхода блокировок. Неправильные значения ухудшают доступ."
        }
        Section::Privacy => {
            "Защита приватности HTTP: блокировка трекеров, Referer policy и сигналы DNT/GPC."
        }
        Section::PrivacyHeaders => {
            "Подмена и подавление заголовков: User-Agent, Referer, X-Forwarded-For, Permissions-Policy."
        }
        Section::Pt => "Подключаемые транспорты (PT) для сложных сетей и DPI.",
        Section::Download => "Скорость/параллелизм загрузки. Влияет на нагрузку и стабильность.",
        Section::SystemProxy => "Как система направляет трафик через ядро.",
        Section::Blocklist => "Фильтрация доменов. Влияет на блокировку нежелательных хостов.",
        Section::Updater => "Проверка обновлений приложения.",
    }
}

fn section_key(section: Section) -> &'static str {
    match section {
        Section::Dns => "dns",
        Section::Tls => "tls",
        Section::Anticensorship => "anticensorship",
        Section::Privacy => "privacy",
        Section::PrivacyHeaders => "privacy_headers",
        Section::Pt => "pt",
        Section::Download => "download",
        Section::SystemProxy => "system_proxy",
        Section::Blocklist => "blocklist",
        Section::Updater => "updater",
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(EngineError::InvalidInput(
            "ожидалось булево значение".to_owned(),
        )),
    }
}

fn parse_u64(value: &str, min: u64, max: u64) -> Result<u64> {
    let parsed = value
        .trim()
        .parse::<u64>()
        .map_err(|e| EngineError::InvalidInput(format!("некорректное число: {e}")))?;
    if parsed < min || parsed > max {
        return Err(EngineError::InvalidInput(format!(
            "число должно быть в диапазоне {min}..={max}"
        )));
    }
    Ok(parsed)
}

fn parse_u16(value: &str, min: u16, max: u16) -> Result<u16> {
    let parsed = value
        .trim()
        .parse::<u16>()
        .map_err(|e| EngineError::InvalidInput(format!("некорректное число: {e}")))?;
    if parsed < min || parsed > max {
        return Err(EngineError::InvalidInput(format!(
            "число должно быть в диапазоне {min}..={max}"
        )));
    }
    Ok(parsed)
}

fn parse_usize(value: &str, min: usize, max: usize) -> Result<usize> {
    let parsed = value
        .trim()
        .parse::<usize>()
        .map_err(|e| EngineError::InvalidInput(format!("некорректное число: {e}")))?;
    if parsed < min || parsed > max {
        return Err(EngineError::InvalidInput(format!(
            "число должно быть в диапазоне {min}..={max}"
        )));
    }
    Ok(parsed)
}

fn parse_array(value: &str) -> Vec<String> {
    value
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_owned())
        .filter(|v| !v.is_empty())
        .collect()
}

fn parse_pt_kind(value: &str) -> Result<PluggableTransportKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "trojan" => Ok(PluggableTransportKind::Trojan),
        "shadowsocks" | "ss" => Ok(PluggableTransportKind::Shadowsocks),
        _ => Err(EngineError::InvalidInput(
            "kind должен быть trojan|shadowsocks".to_owned(),
        )),
    }
}

fn default_pt_config() -> PluggableTransportConfig {
    PluggableTransportConfig {
        kind: PluggableTransportKind::Trojan,
        local_socks5_bind: "127.0.0.1:1080".to_owned(),
        silent_drop: false,
        trojan: Some(TrojanPtConfig {
            server: "server.example.com:443".to_owned(),
            password: "change-me".to_owned(),
            sni: Some("server.example.com".to_owned()),
            alpn_protocols: vec!["http/1.1".to_owned()],
            insecure_skip_verify: false,
        }),
        shadowsocks: None,
        obfs4: None,
        snowflake: None,
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
