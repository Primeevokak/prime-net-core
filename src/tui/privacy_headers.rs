use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};

use crate::config::{EngineConfig, UserAgentPreset};

/// Interactive TUI tab for privacy header controls.
pub struct PrivacyHeadersTab {
    /// Selected menu item index (`0..=4`).
    pub selected_item: usize,
    /// Whether popup edit mode is active.
    pub edit_mode: bool,
    /// Input buffer used by popup edit mode.
    pub edit_buffer: String,
}

impl PrivacyHeadersTab {
    /// Creates a new tab state.
    pub fn new() -> Self {
        Self {
            selected_item: 0,
            edit_mode: false,
            edit_buffer: String::new(),
        }
    }

    /// Handles keyboard input for the privacy headers tab.
    ///
    /// Returns `true` when the event is consumed.
    pub fn handle_key(&mut self, key: KeyEvent, cfg: &mut EngineConfig) -> bool {
        if self.edit_mode {
            match key.code {
                KeyCode::Esc => {
                    self.edit_mode = false;
                    self.edit_buffer.clear();
                }
                KeyCode::Enter => {
                    self.apply_edit_value(cfg);
                    self.edit_mode = false;
                    self.edit_buffer.clear();
                }
                KeyCode::Backspace => {
                    self.edit_buffer.pop();
                }
                KeyCode::Char(c) => {
                    self.edit_buffer.push(c);
                }
                _ => {}
            }
            return true;
        }

        match key.code {
            KeyCode::Up => {
                self.selected_item = self.selected_item.saturating_sub(1);
                true
            }
            KeyCode::Down => {
                self.selected_item = (self.selected_item + 1).min(4);
                true
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.toggle_selected(cfg);
                true
            }
            KeyCode::Char('e') => {
                if let Some(initial) = self.current_edit_value(cfg) {
                    self.edit_mode = true;
                    self.edit_buffer = initial;
                    true
                } else {
                    false
                }
            }
            KeyCode::Char('p') => {
                if self.selected_item == 0 {
                    cfg.privacy.user_agent.preset = cycle_ua_preset(&cfg.privacy.user_agent.preset);
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Renders the tab UI into the provided area.
    pub fn render(&self, frame: &mut ratatui::Frame, area: Rect, cfg: &EngineConfig) {
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(8), Constraint::Length(3)])
            .split(area);
        let main = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(root[0]);

        let menu_items = [
            format!(
                "[UA]  Подмена User-Agent     {}  {}",
                on_off(cfg.privacy.user_agent.enabled),
                ua_summary(cfg)
            ),
            format!(
                "[REF] Подмена Referer        {}  {}",
                on_off(cfg.privacy.referer_override.enabled),
                short(&cfg.privacy.referer_override.value, 32)
            ),
            format!(
                "[IP]  Подмена IP (X-FF)      {}  {}",
                on_off(cfg.privacy.ip_spoof.enabled),
                short(&cfg.privacy.ip_spoof.spoofed_ip, 24)
            ),
            format!(
                "[WRT] Блок WebRTC            {}",
                on_off(cfg.privacy.webrtc.block_enabled)
            ),
            format!(
                "[LOC] Блок геолокации API    {}",
                on_off(cfg.privacy.location_api.block_enabled)
            ),
        ];

        let items = menu_items
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let style = if idx == self.selected_item {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::styled(item.clone(), style))
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            List::new(items).block(
                Block::default()
                    .title("Заголовки приватности")
                    .borders(Borders::ALL),
            ),
            main[0],
        );

        frame.render_widget(
            Paragraph::new(detail_lines(self.selected_item, cfg))
                .block(Block::default().title("Детали").borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            main[1],
        );

        frame.render_widget(
            Paragraph::new(
                "Up/Down навигация  Space переключить  e редактировать  p пресет (UA)  Tab след. вкладка",
            )
            .block(Block::default().borders(Borders::ALL)),
            root[1],
        );

        if self.edit_mode {
            let popup = centered_rect(62, 28, area);
            frame.render_widget(Clear, popup);
            frame.render_widget(
                Paragraph::new(format!(
                    "{}\n\nEnter подтвердить  Esc отмена",
                    self.edit_buffer
                ))
                .block(
                    Block::default()
                        .title("Редактирование значения")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false }),
                popup,
            );
        }
    }

    fn toggle_selected(&mut self, cfg: &mut EngineConfig) {
        match self.selected_item {
            0 => cfg.privacy.user_agent.enabled = !cfg.privacy.user_agent.enabled,
            1 => cfg.privacy.referer_override.enabled = !cfg.privacy.referer_override.enabled,
            2 => cfg.privacy.ip_spoof.enabled = !cfg.privacy.ip_spoof.enabled,
            3 => cfg.privacy.webrtc.block_enabled = !cfg.privacy.webrtc.block_enabled,
            4 => cfg.privacy.location_api.block_enabled = !cfg.privacy.location_api.block_enabled,
            _ => {}
        }
    }

    fn current_edit_value(&self, cfg: &EngineConfig) -> Option<String> {
        match self.selected_item {
            0 => Some(cfg.privacy.user_agent.custom_value.clone()),
            1 => Some(cfg.privacy.referer_override.value.clone()),
            2 => Some(cfg.privacy.ip_spoof.spoofed_ip.clone()),
            _ => None,
        }
    }

    fn apply_edit_value(&mut self, cfg: &mut EngineConfig) {
        match self.selected_item {
            0 => cfg.privacy.user_agent.custom_value = self.edit_buffer.clone(),
            1 => cfg.privacy.referer_override.value = self.edit_buffer.clone(),
            2 => cfg.privacy.ip_spoof.spoofed_ip = self.edit_buffer.clone(),
            _ => {}
        }
    }
}

impl Default for PrivacyHeadersTab {
    fn default() -> Self {
        Self::new()
    }
}

fn on_off(v: bool) -> &'static str {
    if v {
        "ВКЛ"
    } else {
        "ВЫКЛ"
    }
}

fn short(value: &str, max_len: usize) -> String {
    let v = value.trim();
    if v.is_empty() {
        return "<пусто>".to_owned();
    }
    if v.chars().count() <= max_len {
        return v.to_owned();
    }
    let mut out = String::new();
    for ch in v.chars().take(max_len.saturating_sub(3)) {
        out.push(ch);
    }
    out.push_str("...");
    out
}

fn ua_summary(cfg: &EngineConfig) -> String {
    match cfg.privacy.user_agent.preset {
        UserAgentPreset::ChromeWindows => "пресет=chrome_windows".to_owned(),
        UserAgentPreset::FirefoxWindows => "пресет=firefox_windows".to_owned(),
        UserAgentPreset::FirefoxLinux => "пресет=firefox_linux".to_owned(),
        UserAgentPreset::SafariMacOs => "пресет=safari_macos".to_owned(),
        UserAgentPreset::Custom => {
            format!(
                "пресет=custom ({})",
                short(&cfg.privacy.user_agent.custom_value, 20)
            )
        }
    }
}

fn detail_lines(selected_item: usize, cfg: &EngineConfig) -> Vec<Line<'static>> {
    match selected_item {
        0 => vec![
            Line::from(format!(
                "Подмена User-Agent: {}",
                on_off(cfg.privacy.user_agent.enabled)
            )),
            Line::from(format!(
                "Пресет: {}",
                match cfg.privacy.user_agent.preset {
                    UserAgentPreset::ChromeWindows => "chrome_windows",
                    UserAgentPreset::FirefoxWindows => "firefox_windows",
                    UserAgentPreset::FirefoxLinux => "firefox_linux",
                    UserAgentPreset::SafariMacOs => "safari_macos",
                    UserAgentPreset::Custom => "custom",
                }
            )),
            Line::from(format!(
                "Пользовательское значение: {}",
                short(&cfg.privacy.user_agent.custom_value, 64)
            )),
            Line::from(""),
            Line::from("p: сменить пресет, e: редактировать своё значение"),
        ],
        1 => vec![
            Line::from(format!(
                "Подмена Referer: {}",
                on_off(cfg.privacy.referer_override.enabled)
            )),
            Line::from(format!("Значение: {}", cfg.privacy.referer_override.value)),
            Line::from(""),
            Line::from("e: редактировать URL подмены"),
        ],
        2 => vec![
            Line::from(format!(
                "Подмена IP: {}",
                on_off(cfg.privacy.ip_spoof.enabled)
            )),
            Line::from(format!("Подменный IP: {}", cfg.privacy.ip_spoof.spoofed_ip)),
            Line::from("Заголовки: X-Forwarded-For, X-Real-IP"),
            Line::from(""),
            Line::from("e: редактировать подменный IP"),
        ],
        3 => vec![
            Line::from(format!(
                "Сигнал блокировки WebRTC: {}",
                on_off(cfg.privacy.webrtc.block_enabled)
            )),
            Line::from("Добавляет Permissions-Policy для camera/microphone/geolocation."),
            Line::from("Сигнал добавляется по возможности для HTTP-трафика через прокси."),
        ],
        4 => vec![
            Line::from(format!(
                "Сигнал блокировки Location API: {}",
                on_off(cfg.privacy.location_api.block_enabled)
            )),
            Line::from("Добавляет Permissions-Policy для geolocation."),
            Line::from("Объединяется с политикой WebRTC, если включены оба режима."),
        ],
        _ => vec![Line::from("Выберите пункт")],
    }
}

fn cycle_ua_preset(current: &UserAgentPreset) -> UserAgentPreset {
    match current {
        UserAgentPreset::ChromeWindows => UserAgentPreset::FirefoxWindows,
        UserAgentPreset::FirefoxWindows => UserAgentPreset::FirefoxLinux,
        UserAgentPreset::FirefoxLinux => UserAgentPreset::SafariMacOs,
        UserAgentPreset::SafariMacOs => UserAgentPreset::Custom,
        UserAgentPreset::Custom => UserAgentPreset::ChromeWindows,
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
