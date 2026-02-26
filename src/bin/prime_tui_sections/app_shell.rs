use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, UNIX_EPOCH, SystemTime};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use prime_net_engine_core::blocklist::{expand_tilde, BlocklistCache};
use prime_net_engine_core::config::{EngineConfig, SystemProxyMode};
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::health::{HealthChecker, HealthLevel};
use prime_net_engine_core::platform::diagnostics::{
    DiagnosticLevel, DiagnosticResult, ProxyDiagnostics,
};
use prime_net_engine_core::platform::{system_proxy_manager, ProxyMode};
use prime_net_engine_core::telemetry::tui_layer::TuiLayer;
use prime_net_engine_core::tui::config_editor::{Action as ConfigAction, ConfigEditor, UxMode};
use prime_net_engine_core::tui::connection_monitor::ConnectionMonitor;
use prime_net_engine_core::tui::help::show_help_overlay;
use prime_net_engine_core::tui::log_viewer::{format_timestamp, LogViewer, LogEntry};
use prime_net_engine_core::tui::privacy_dashboard::{cycle_referer_mode, PrivacyDashboard};
use prime_net_engine_core::tui::privacy_headers::PrivacyHeadersTab;
use prime_net_engine_core::version::PRIME_TUI_VERSION_LABEL;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::{Frame, Terminal};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Config,
    Monitor,
    Privacy,
    PrivacyHeaders,
    Logs,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogInputMode {
    Normal,
    Search,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserMode {
    Simple,
    Advanced,
}

const AUTHOR_TELEGRAM_URL: &str = "https://t.me/o00000000i";

pub(crate) struct App {
    tab: Tab,
    config_path: PathBuf,
    config_editor: ConfigEditor,
    conn_monitor: ConnectionMonitor,
    privacy_dashboard: PrivacyDashboard,
    privacy_headers_tab: PrivacyHeadersTab,
    log_viewer: Arc<LogViewer>,
    diagnostics: Vec<DiagnosticResult>,
    status_line: String,
    log_input_mode: LogInputMode,
    log_search_buf: String,
    log_level_idx: usize,
    log_category_idx: usize,
    log_filter_level: Option<Level>,
    log_use_regex: bool,
    log_auto_scroll: bool,
    log_selected_line: usize,
    last_diag_refresh: Instant,
    help_overlay: Option<String>,
    packet_bypass_bootstrap_prompt: Option<PacketBypassBootstrapPrompt>,
    packet_bypass_unsafe_confirm_prompt: Option<PacketBypassUnsafeConfirmPrompt>,
    classifier_cache_clear_prompt: Option<ClassifierCacheClearPrompt>,
    user_mode: UserMode,
    core_process: Option<Child>,
    core_event_rx: Option<mpsc::Receiver<CoreUiEvent>>,
    allow_unverified_packet_bypass_next_start: bool,
    proxy_managed_by_tui: bool,
    core_start_pending: Option<(String, Instant)>,
}

#[derive(Debug, Clone)]
struct ClassifierCacheClearPrompt {
    path: PathBuf,
    exists: bool,
    size_bytes: u64,
    modified_unix: Option<u64>,
}

#[derive(Debug, Clone)]
struct PacketBypassBootstrapPrompt {
    source_url: Option<String>,
}

#[derive(Debug, Clone)]
struct PacketBypassUnsafeConfirmPrompt {
    source_url: Option<String>,
    started_at: Instant,
}

#[derive(Debug, Clone)]
enum CoreUiEvent {
    PacketBypassIntegrityCheckFailed { source_url: Option<String> },
}

impl App {
    pub fn new(config_path: PathBuf, config: EngineConfig, log_viewer: Arc<LogViewer>) -> Self {
        log_viewer.set_filter_level(None);
        log_viewer.set_category_filter(None);
        log_viewer.set_search_query(String::new());
        log_viewer.set_use_regex(false);
        log_viewer.set_auto_scroll(true);

        Self {
            tab: Tab::Config,
            config_path,
            config_editor: ConfigEditor::new(config),
            conn_monitor: ConnectionMonitor::new(),
            privacy_dashboard: PrivacyDashboard::new(),
            privacy_headers_tab: PrivacyHeadersTab::new(),
            log_viewer,
            diagnostics: Vec::new(),
            status_line: "Готово".to_owned(),
            log_input_mode: LogInputMode::Normal,
            log_search_buf: String::new(),
            log_level_idx: 0,
            log_category_idx: 0,
            log_filter_level: None,
            log_use_regex: false,
            log_auto_scroll: true,
            log_selected_line: 0,
            last_diag_refresh: Instant::now() - Duration::from_secs(60),
            help_overlay: None,
            packet_bypass_bootstrap_prompt: None,
            packet_bypass_unsafe_confirm_prompt: None,
            classifier_cache_clear_prompt: None,
            user_mode: UserMode::Simple,
            core_process: None,
            core_event_rx: None,
            allow_unverified_packet_bypass_next_start: false,
            proxy_managed_by_tui: false,
            core_start_pending: None,
        }
    }

    async fn refresh_proxy_diagnostics(&mut self) {
        let mut out = Vec::new();
        let endpoint = self.config_editor.config.system_proxy.socks_endpoint.clone();
        let packet_bypass_enabled = self.config_editor.config.evasion.packet_bypass_enabled;
        
        if self.config_editor.config.pt.is_none() {
            if packet_bypass_enabled {
                out.push(DiagnosticResult::info("Активен Packet Bypass", "Используется ciadpi"));
            } else {
                out.push(DiagnosticResult::warn("Обход отключен", "PT = direct"));
            }
        }
        if let Ok(status) = system_proxy_manager().status() {
            if status.enabled { out.push(ProxyDiagnostics::check_socks5_listening(&endpoint)); }
            out.push(ProxyDiagnostics::check_system_proxy_config());
        }
        self.diagnostics = out;
        self.last_diag_refresh = Instant::now();
    }

    fn apply_log_level_filter(&mut self) {
        self.log_filter_level = match self.log_level_idx {
            0 => None,
            1 => Some(Level::ERROR),
            2 => Some(Level::WARN),
            3 => Some(Level::INFO),
            4 => Some(Level::DEBUG),
            _ => Some(Level::TRACE),
        };
        self.log_viewer.set_filter_level(self.log_filter_level);
    }

    fn cycle_user_mode(&mut self) {
        self.user_mode = match self.user_mode {
            UserMode::Simple => UserMode::Advanced,
            UserMode::Advanced => UserMode::Simple,
        };
        self.config_editor.set_ux_mode(match self.user_mode {
            UserMode::Simple => UxMode::Simple,
            UserMode::Advanced => UxMode::Advanced,
        });
    }
}

impl Drop for App {
    fn drop(&mut self) {
        if let Some(mut child) = self.core_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.proxy_managed_by_tui { let _ = system_proxy_manager().disable(); }
    }
}
