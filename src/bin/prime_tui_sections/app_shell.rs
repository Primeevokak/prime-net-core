use std::fs;
use std::io::{BufRead};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, UNIX_EPOCH, SystemTime};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    MouseEvent,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use prime_net_engine_core::blocklist::{expand_tilde, BlocklistCache};
use prime_net_engine_core::config::{EngineConfig};
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::platform::diagnostics::{
    DiagnosticLevel, DiagnosticResult, ProxyDiagnostics,
};
use prime_net_engine_core::platform::{system_proxy_manager, ProxyMode, ProxyStatus};
use prime_net_engine_core::telemetry::tui_layer::TuiLayer;
use prime_net_engine_core::tui::config_editor::{Action as ConfigAction, ConfigEditor, UxMode};
use prime_net_engine_core::tui::connection_monitor::ConnectionMonitor;
use prime_net_engine_core::tui::help::show_help_overlay;
use prime_net_engine_core::tui::log_viewer::{format_timestamp, LogViewer, LogEntry};
use prime_net_engine_core::tui::privacy_dashboard::{PrivacyDashboard};
use prime_net_engine_core::tui::privacy_headers::PrivacyHeadersTab;
use prime_net_engine_core::version::PRIME_TUI_VERSION_LABEL;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Clear};
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
    
    proxy_status_rx: mpsc::Receiver<ProxyStatus>,
    current_proxy_status: Option<ProxyStatus>,
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
    _started_at: Instant,
}

#[derive(Debug, Clone)]
enum CoreUiEvent {
    PacketBypassIntegrityCheckFailed { source_url: Option<String> },
}

impl App {
    pub fn new(config_path: PathBuf, config: EngineConfig, log_viewer: Arc<LogViewer>, proxy_status_rx: mpsc::Receiver<ProxyStatus>) -> Self {
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
            proxy_status_rx,
            current_proxy_status: None,
        }
    }

    fn update_from_channels(&mut self) {
        while let Ok(status) = self.proxy_status_rx.try_recv() {
            self.current_proxy_status = Some(status);
        }
    }

    async fn refresh_proxy_diagnostics(&mut self) {
        let mut out = Vec::new();
        let endpoint = self.config_editor.config.system_proxy.socks_endpoint.clone();
        
        if self.config_editor.config.pt.is_none() {
            if self.config_editor.config.evasion.packet_bypass_enabled {
                out.push(DiagnosticResult::info("Активен Packet Bypass", "Используется ciadpi"));
            }
        }
        
        if let Some(status) = &self.current_proxy_status {
            if status.enabled {
                out.push(ProxyDiagnostics::check_socks5_listening(&endpoint));
            }
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    install_panic_report_hook();
    if let Err(e) = run_main().await {
        eprintln!("критическая ошибка: {e}");
        std::process::exit(1);
    }
}

async fn run_main() -> Result<()> {
    let config_path = parse_config_path(std::env::args().skip(1).collect::<Vec<_>>())?;
    let (config, startup_note) = load_config_for_tui(&config_path);

    let log_viewer = Arc::new(LogViewer::new());
    init_tui_tracing(log_viewer.clone())?;

    let (proxy_tx, proxy_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let manager = system_proxy_manager();
        loop {
            if let Ok(status) = manager.status() { let _ = proxy_tx.send(status); }
            std::thread::sleep(Duration::from_secs(2));
        }
    });

    enable_raw_mode().map_err(EngineError::Io)?;
    execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture).map_err(EngineError::Io)?;
    let backend = ratatui::backend::CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend).map_err(EngineError::Io)?;

    let mut app = App::new(config_path, config, log_viewer, proxy_rx);
    if let Some(note) = startup_note { app.status_line = note; }
    else { app.status_line = startup_health_summary(&app.config_editor.config); }
    app.refresh_proxy_diagnostics().await;
    
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(100);

    loop {
        app.update_from_channels();
        poll_core_startup(&mut app)?;
        drain_core_events(&mut app);
        app.conn_monitor.tick();
        if app.log_auto_scroll { app.log_viewer.jump_to_bottom(); app.log_selected_line = app.log_viewer.selected_line(); }
        if app.last_diag_refresh.elapsed() >= Duration::from_secs(10) { app.refresh_proxy_diagnostics().await; }

        terminal.draw(|f| render(f, &mut app)).map_err(EngineError::Io)?;

        let timeout = tick_rate.checked_sub(last_tick.elapsed()).unwrap_or(Duration::from_secs(0));
        if event::poll(timeout).map_err(EngineError::Io)? {
            match event::read().map_err(EngineError::Io)? {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Release { continue; }
                    match handle_key(&mut app, key).await {
                        Ok(true) => break,
                        Err(e) => app.status_line = format!("Ошибка: {e}"),
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => handle_mouse(&mut app, mouse),
                _ => {}
            }
        }
        if last_tick.elapsed() >= tick_rate { last_tick = Instant::now(); }
    }

    disable_raw_mode().map_err(EngineError::Io)?;
    execute!(std::io::stdout(), DisableMouseCapture, LeaveAlternateScreen).map_err(EngineError::Io)?;
    Ok(())
}

fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.size();
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(2)]).split(area);

    frame.render_widget(tab_bar(app.tab, app.user_mode), chunks[0]);
    match app.tab {
        Tab::Config => app.config_editor.render(frame, chunks[1]),
        Tab::Monitor => app.conn_monitor.render(frame, chunks[1]),
        Tab::Privacy => app.privacy_dashboard.render(frame, chunks[1], &app.config_editor.config),
        Tab::PrivacyHeaders => app.privacy_headers_tab.render(frame, chunks[1], &app.config_editor.config),
        Tab::Logs => render_logs(frame, chunks[1], app),
        Tab::Proxy => render_proxy(frame, chunks[1], app),
    }

    let footer = Paragraph::new(compose_status_line(app)).block(Block::default().title("Статус").borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);

    if let Some(help) = &app.help_overlay {
        let popup = centered_rect(75, 70, area);
        frame.render_widget(Clear, popup);
        frame.render_widget(Paragraph::new(help.clone()).block(Block::default().title("Справка").borders(Borders::ALL)), popup);
    }
}

fn tab_bar(tab: Tab, mode: UserMode) -> Paragraph<'static> {
    let tabs = match mode {
        UserMode::Simple => vec![(Tab::Config, "1 Конфиг"), (Tab::Privacy, "2 Приват"), (Tab::Proxy, "3 Прокси")],
        UserMode::Advanced => vec![(Tab::Config, "1 Конфиг"), (Tab::Monitor, "2 Мон"), (Tab::Privacy, "3 Приват"), (Tab::PrivacyHeaders, "4 Заг"), (Tab::Logs, "5 Логи"), (Tab::Proxy, "6 Прокси")],
    };
    let spans = tabs.into_iter().flat_map(|(t, name)| {
        let style = if t == tab { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default() };
        vec![Span::styled(name, style), Span::raw("  ")]
    }).collect::<Vec<_>>();
    Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL).title(PRIME_TUI_VERSION_LABEL))
}

fn render_logs(frame: &mut Frame, area: Rect, app: &mut App) {
    let logs = app.log_viewer.visible_logs(area.height as usize);
    let items = logs.iter().map(|entry| {
        let ts = format_timestamp(entry.timestamp);
        let count_label = if entry.count > 1 { format!(" (x{})", entry.count) } else { String::new() };
        let style = match entry.level { Level::ERROR => Style::default().fg(Color::Red), Level::WARN => Style::default().fg(Color::Yellow), _ => Style::default().fg(Color::Green) };
        ListItem::new(Line::from(vec![Span::styled(format!("{ts} {:5} {} {}{}", entry.level, entry.target, entry.message, count_label), style)]))
    }).collect::<Vec<_>>();
    frame.render_widget(List::new(items).block(Block::default().borders(Borders::ALL).title("Логи")), area);
}

fn render_proxy(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    if let Some(status) = &app.current_proxy_status {
        lines.push(Line::from(format!("Статус: {}", if status.enabled { "Включен" } else { "Выключен" })));
        lines.push(Line::from(format!("Режим: {:?}", status.mode)));
        if let Some(ep) = &status.socks_endpoint { lines.push(Line::from(format!("SOCKS5: {}", ep))); }
    } else { lines.push(Line::from("Статус: получение данных...")); }

    let blocklist_path = expand_tilde(&app.config_editor.config.blocklist.cache_path);
    if let Ok(Some(cache)) = BlocklistCache::status(Path::new(&blocklist_path)) {
        lines.push(Line::from(format!("Блоклист: {} доменов", cache.domains.len())));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Диагностика:"));
    if app.diagnostics.is_empty() { lines.push(Line::from("  (нажмите [u] для запуска)")); }
    for d in &app.diagnostics { lines.push(Line::from(format!("[{:?}] {}", d.level, d.message))); }
    lines.push(Line::from(""));
    lines.push(Line::from("[a] Запуск ядра  [x] Остановка  [u] Обновить диагностику  [d] Очистить кэш"));
    lines.push(Line::from(format!("Telegram: {}", AUTHOR_TELEGRAM_URL)));
    frame.render_widget(Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Прокси ")), area);
}

async fn handle_key(app: &mut App, key: KeyEvent) -> Result<bool> {
    if app.help_overlay.is_some() { app.help_overlay = None; return Ok(false); }
    if matches!(key.code, KeyCode::Char('?')) { app.help_overlay = Some(show_help_overlay("main")); return Ok(false); }
    if matches!(key.code, KeyCode::Char('q')) { return Ok(true); }
    if matches!(key.code, KeyCode::Char('m')) { app.cycle_user_mode(); return Ok(false); }
    if matches!(key.code, KeyCode::Tab) { 
        let tabs = tabs_for_mode(app.user_mode);
        let current_pos = tabs.iter().position(|&t| t == app.tab).unwrap_or(0);
        app.tab = tabs[(current_pos + 1) % tabs.len()];
        return Ok(false);
    }
    match key.code {
        KeyCode::Char('1') => app.tab = Tab::Config,
        KeyCode::Char('2') => app.tab = if app.user_mode == UserMode::Simple { Tab::Privacy } else { Tab::Monitor },
        KeyCode::Char('3') => app.tab = if app.user_mode == UserMode::Simple { Tab::Proxy } else { Tab::Privacy },
        KeyCode::Char('4') if app.user_mode == UserMode::Advanced => app.tab = Tab::PrivacyHeaders,
        KeyCode::Char('5') if app.user_mode == UserMode::Advanced => app.tab = Tab::Logs,
        KeyCode::Char('6') if app.user_mode == UserMode::Advanced => app.tab = Tab::Proxy,
        _ => {}
    }
    match app.tab {
        Tab::Config => match app.config_editor.handle_input(key)? {
            ConfigAction::Saved => { app.config_editor.save_to_file(&app.config_path)?; app.status_line = "Сохранено".to_owned(); }
            _ => {}
        },
        Tab::Monitor => match key.code { KeyCode::Up => app.conn_monitor.select_prev(), KeyCode::Down => app.conn_monitor.select_next(), _ => {} },
        Tab::Logs => handle_logs_key(app, key)?,
        Tab::Proxy => match key.code {
            KeyCode::Char('a') => activate_core(app)?,
            KeyCode::Char('x') => deactivate_core(app)?,
            KeyCode::Char('u') => app.refresh_proxy_diagnostics().await,
            KeyCode::Char('d') => { app.classifier_cache_clear_prompt = Some(build_classifier_cache_clear_prompt(&app.config_editor.config)); }
            KeyCode::Enter => { let _ = Command::new("cmd").args(["/C", "start", "", AUTHOR_TELEGRAM_URL]).spawn(); }
            _ => {}
        },
        _ => {}
    }
    Ok(false)
}

fn handle_mouse(app: &mut App, mouse: MouseEvent) {
    if mouse.row < 3 { 
        let tabs = tabs_for_mode(app.user_mode);
        let width = crossterm::terminal::size().map(|(w, _)| w).unwrap_or(120);
        let idx = (mouse.column as usize * tabs.len()) / width as usize;
        if let Some(&t) = tabs.get(idx) { app.tab = t; }
    }
}
