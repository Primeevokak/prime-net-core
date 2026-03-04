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

include!("config_editor_parts/editor_flow.rs");
include!("config_editor_parts/editor_fields.rs");
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
    use rand::{distributions::Alphanumeric, Rng};
    let random_password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    PluggableTransportConfig {
        kind: PluggableTransportKind::Trojan,
        local_socks5_bind: "127.0.0.1:1080".to_owned(),
        silent_drop: false,
        trojan: Some(TrojanPtConfig {
            server: "server.example.com:443".to_owned(),
            password: random_password,
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
