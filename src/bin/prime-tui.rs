use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use prime_net_engine_core::blocklist::{expand_tilde, BlocklistCache};
use prime_net_engine_core::config::DnsResolverKind;
use prime_net_engine_core::config::EchMode;
use prime_net_engine_core::config::EngineConfig;
use prime_net_engine_core::config::EvasionStrategy;
use prime_net_engine_core::config::PluggableTransportKind;
use prime_net_engine_core::config::SystemProxyMode;
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::health::{HealthChecker, HealthLevel};
use prime_net_engine_core::platform::diagnostics::{
    DiagnosticLevel, DiagnosticResult, ProxyDiagnostics,
};
use prime_net_engine_core::platform::system_proxy_manager;
use prime_net_engine_core::platform::ProxyMode;
use prime_net_engine_core::privacy::{privacy_level, PrivacyLevel};
use prime_net_engine_core::telemetry::tui_layer::TuiLayer;
use prime_net_engine_core::tui::config_editor::{Action as ConfigAction, ConfigEditor, UxMode};
use prime_net_engine_core::tui::connection_monitor::ConnectionMonitor;
use prime_net_engine_core::tui::first_run_wizard::default_config_path;
use prime_net_engine_core::tui::help::show_help_overlay;
use prime_net_engine_core::tui::log_viewer::{format_timestamp, LogEntry, LogViewer};
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

struct App {
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
    user_mode: UserMode,
    core_process: Option<Child>,
    proxy_managed_by_tui: bool,
    core_start_pending: Option<(String, Instant)>,
}

impl App {
    fn new(config_path: PathBuf, config: EngineConfig, log_viewer: Arc<LogViewer>) -> Self {
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
            user_mode: UserMode::Simple,
            core_process: None,
            proxy_managed_by_tui: false,
            core_start_pending: None,
        }
    }

    async fn refresh_proxy_diagnostics(&mut self) {
        let mut out = Vec::new();
        let endpoint = self
            .config_editor
            .config
            .system_proxy
            .socks_endpoint
            .clone();
        if self.config_editor.config.pt.is_none() {
            out.push(DiagnosticResult::warn(
                "Транспорт обхода отключен (шаблон PT = direct)",
                "Установите шаблон trojan/shadowsocks в Конфиг -> Системный прокси",
            ));
        }
        let status = system_proxy_manager().status();
        if let Ok(status) = status {
            let core_running = self
                .core_process
                .as_mut()
                .map(|c| c.try_wait().ok().flatten().is_none())
                .unwrap_or(false);
            if status.enabled || core_running {
                out.push(ProxyDiagnostics::check_socks5_listening(&endpoint));
            } else {
                out.push(DiagnosticResult::info(
                    "SOCKS5-сервер остановлен",
                    "Нажмите [a], чтобы запустить ядро и включить прокси",
                ));
            }
            out.push(ProxyDiagnostics::check_system_proxy_config());
            if let Some(url) = status.pac_url {
                out.push(ProxyDiagnostics::check_pac_server(&url).await);
            }
        } else if let Ok(mut fallback) = ProxyDiagnostics::run_sync_basic(&endpoint) {
            out.append(&mut fallback);
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
        if self.user_mode == UserMode::Simple
            && !matches!(
                self.tab,
                Tab::Config | Tab::Privacy | Tab::PrivacyHeaders | Tab::Proxy
            )
        {
            self.tab = Tab::Config;
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        if let Some(mut child) = self.core_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.core_start_pending = None;
        if self.proxy_managed_by_tui {
            let _ = system_proxy_manager().disable();
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    install_panic_report_hook();
    if let Err(e) = run_main().await {
        let body = format!("критическая ошибка: {e}");
        if let Some(path) = write_crash_report("fatal-error", &body) {
            eprintln!("критическая ошибка: {e}\nотчёт: {}", path.display());
        } else {
            eprintln!("критическая ошибка: {e}");
        }
        std::process::exit(1);
    }
}

async fn run_main() -> Result<()> {
    let config_path = parse_config_path(std::env::args().skip(1).collect::<Vec<_>>())?;
    let (config, startup_note) = load_config_for_tui(&config_path);

    let log_viewer = Arc::new(LogViewer::new());
    init_tui_tracing(log_viewer.clone())?;

    enable_raw_mode().map_err(EngineError::Io)?;
    execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture)
        .map_err(EngineError::Io)?;
    let backend = ratatui::backend::CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend).map_err(EngineError::Io)?;

    let mut app = App::new(config_path, config, log_viewer);
    app.config_editor.set_ux_mode(UxMode::Simple);
    if let Some(note) = startup_note {
        app.status_line = note.clone();
        app.help_overlay = Some(format!(
            "{note}\n\nПроверьте параметры и сохраните конфиг клавишей [s]."
        ));
    } else {
        app.status_line = startup_health_summary(&app.config_editor.config).await;
    }
    app.refresh_proxy_diagnostics().await;
    let mut tick = Instant::now();

    let run_res = run_app(&mut terminal, &mut app, &mut tick).await;

    disable_raw_mode().map_err(EngineError::Io)?;
    execute!(std::io::stdout(), DisableMouseCapture, LeaveAlternateScreen)
        .map_err(EngineError::Io)?;
    run_res
}

async fn run_app(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    tick: &mut Instant,
) -> Result<()> {
    loop {
        poll_core_startup(app)?;
        app.conn_monitor.tick();
        if app.log_auto_scroll {
            app.log_viewer.jump_to_bottom();
            app.log_selected_line = app.log_viewer.selected_line();
        }
        if app.last_diag_refresh.elapsed() >= Duration::from_secs(10) {
            app.refresh_proxy_diagnostics().await;
        }

        terminal.draw(|f| render(f, app)).map_err(EngineError::Io)?;

        if event::poll(Duration::from_millis(50)).map_err(EngineError::Io)? {
            match event::read().map_err(EngineError::Io)? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match handle_key(app, key).await {
                        Ok(should_quit) => {
                            if should_quit {
                                break;
                            }
                        }
                        Err(e) => {
                            app.status_line = format!("Ошибка действия: {e}");
                            let _ = write_crash_report("runtime-error", &format!("{e}"));
                        }
                    }
                }
                Event::Mouse(mouse) => handle_mouse(app, mouse),
                _ => {}
            }
        }

        if tick.elapsed() >= Duration::from_secs(1) {
            *tick = Instant::now();
        }
    }
    Ok(())
}

fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(area);

    frame.render_widget(tab_bar(app.tab, app.user_mode), chunks[0]);
    match app.tab {
        Tab::Config => app.config_editor.render(frame, chunks[1]),
        Tab::Monitor => app.conn_monitor.render(frame, chunks[1]),
        Tab::Privacy => app
            .privacy_dashboard
            .render(frame, chunks[1], &app.config_editor.config),
        Tab::PrivacyHeaders => {
            app.privacy_headers_tab
                .render(frame, chunks[1], &app.config_editor.config)
        }
        Tab::Logs => render_logs(frame, chunks[1], app),
        Tab::Proxy => render_proxy(frame, chunks[1], app),
    }

    let footer = Paragraph::new(compose_status_line(app))
        .block(Block::default().title("Статус").borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);

    if let Some(help) = &app.help_overlay {
        let popup = centered_rect(75, 70, area);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(help.clone())
                .block(Block::default().title("Справка").borders(Borders::ALL)),
            popup,
        );
    } else if let Some((endpoint, started)) = &app.core_start_pending {
        let popup = centered_rect(75, 45, area);
        let text = format!(
            "Запуск ядра...\n\nSOCKS endpoint: {endpoint}\nВремя: {} с\n\nЕсли PT недоступен, ядро автоматически переключится в direct-режим.\nДетали: вкладка «Логи» (targets: socks_cmd, socks5).",
            started.elapsed().as_secs()
        );
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(text).block(Block::default().title("Запуск ядра").borders(Borders::ALL)),
            popup,
        );
    }
}

fn tab_bar(tab: Tab, mode: UserMode) -> Paragraph<'static> {
    let tabs = match mode {
        UserMode::Simple => vec![
            (Tab::Config, "1 Конфиг"),
            (Tab::Privacy, "2 Приватность"),
            (Tab::PrivacyHeaders, "3 Заголовки приватности"),
            (Tab::Proxy, "4 Прокси"),
        ],
        UserMode::Advanced => vec![
            (Tab::Config, "1 Конфиг"),
            (Tab::Monitor, "2 Монитор"),
            (Tab::Privacy, "3 Приватность"),
            (Tab::PrivacyHeaders, "4 Заголовки приватности"),
            (Tab::Logs, "5 Логи"),
            (Tab::Proxy, "6 Прокси"),
        ],
    };
    let spans = tabs
        .iter()
        .flat_map(|(t, name)| {
            let active = *t == tab;
            let style = if active {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            vec![Span::styled(*name, style), Span::raw("  ")]
        })
        .collect::<Vec<_>>();
    let mode_label = match mode {
        UserMode::Simple => "простой",
        UserMode::Advanced => "расширенный",
    };
    Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL).title(format!(
        "{PRIME_TUI_VERSION_LABEL}  [q] выход  [Tab] далее  [m] режим: {mode_label}  [?] справка"
    )))
}

fn render_logs(frame: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(3),
        ])
        .split(area);
    let level = match app.log_filter_level {
        None => "ВСЕ",
        Some(Level::ERROR) => "ERROR",
        Some(Level::WARN) => "WARN",
        Some(Level::INFO) => "INFO",
        Some(Level::DEBUG) => "DEBUG",
        Some(Level::TRACE) => "TRACE",
    };
    let mode = if app.log_use_regex {
        "regex"
    } else {
        "текст"
    };
    let search = if app.log_input_mode == LogInputMode::Search {
        format!("{}_", app.log_search_buf)
    } else {
        app.log_search_buf.clone()
    };
    let category = app
        .log_viewer
        .category_filter()
        .unwrap_or_else(|| "ВСЕ".to_owned());
    let header = format!("Фильтр: {level}  Категория: {category}  Поиск({mode}): {search}");
    let total_logs = app.log_viewer.filtered_logs().len();
    let live_marker = if app.log_auto_scroll {
        " [LIVE]".to_owned()
    } else {
        let current = if total_logs == 0 {
            0
        } else {
            (app.log_selected_line + 1).min(total_logs)
        };
        format!(" [{current}/{total_logs}]")
    };
    frame.render_widget(
        Paragraph::new(header).block(
            Block::default()
                .title(format!("Просмотр логов{live_marker}"))
                .borders(Borders::ALL),
        ),
        chunks[0],
    );
    let viewport_height = chunks[1].height as usize;
    let start_index = if app.log_auto_scroll || app.log_selected_line == 0 {
        total_logs.saturating_sub(viewport_height)
    } else {
        app.log_selected_line.min(total_logs.saturating_sub(1))
    };
    let highlighted_index = if app.log_auto_scroll || app.log_selected_line == 0 {
        total_logs.saturating_sub(1)
    } else {
        app.log_selected_line
    };
    let logs = app.log_viewer.visible_logs(viewport_height);
    let items = logs
        .iter()
        .enumerate()
        .map(|(idx, entry)| {
            let ts = format_timestamp(entry.timestamp);
            let mut style = match entry.level {
                Level::ERROR => Style::default().fg(Color::Red),
                Level::WARN => Style::default().fg(Color::Yellow),
                Level::INFO => Style::default().fg(Color::Green),
                Level::DEBUG => Style::default().fg(Color::Cyan),
                Level::TRACE => Style::default().fg(Color::Gray),
            };
            if start_index + idx == highlighted_index {
                style = style.add_modifier(Modifier::BOLD).bg(Color::DarkGray);
            }
            ListItem::new(Line::from(vec![Span::styled(
                format!("{ts} {:5} {} {}", entry.level, entry.target, entry.message),
                style,
            )]))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL)),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(
            "[/] поиск  [f] уровень  [k] категория  [r] regex  [s] автопрокрутка  [e] экспорт  [y] копировать  [c] очистить",
        )
        .block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );
}
fn render_proxy(frame: &mut Frame, area: Rect, app: &App) {
    let status = system_proxy_manager().status();
    let mut lines = Vec::new();
    match status {
        Ok(status) => {
            let indicator = if status.enabled {
                "ВКЛЮЧЕН"
            } else {
                "ВЫКЛЮЧЕН"
            };
            lines.push(Line::from(format!("Статус: {indicator}")));
            lines.push(Line::from(format!(
                "Режим: {}",
                proxy_mode_label(&status.mode)
            )));
            lines.push(Line::from(format!(
                "SOCKS5: {}",
                status.socks_endpoint.unwrap_or_else(|| "н/д".to_owned())
            )));
            lines.push(Line::from(format!(
                "URL PAC: {}",
                status.pac_url.unwrap_or_else(|| "н/д".to_owned())
            )));
        }
        Err(e) => lines.push(Line::from(format!("Статус недоступен: {e}"))),
    }

    let blocklist_path = expand_tilde(&app.config_editor.config.blocklist.cache_path);
    if let Ok(Some(cache)) = BlocklistCache::status(Path::new(&blocklist_path)) {
        lines.push(Line::from(format!(
            "Блоклист: {} доменов (обновлено: {})",
            cache.domains.len(),
            cache.updated_at_unix
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Диагностика:"));
    for d in &app.diagnostics {
        let level = match d.level {
            DiagnosticLevel::Ok => "[OK]",
            DiagnosticLevel::Info => "[INFO]",
            DiagnosticLevel::Warn => "[WARN]",
            DiagnosticLevel::Error => "[ERROR]",
        };
        lines.push(Line::from(format!("{level} {}", d.message)));
        if !d.suggestion.is_empty() {
            lines.push(Line::from(format!("  исправить: {}", d.suggestion)));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "[a] включить ядро  [x] выключить ядро  [u] обновить диагностику",
    ));

    lines.push(Line::from(""));
    lines.push(Line::from("Author links:"));
    lines.push(Line::from(format!(
        "  [Enter] Open Telegram channel: {}",
        AUTHOR_TELEGRAM_URL
    )));

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title("Системный прокси")
                .borders(Borders::ALL),
        ),
        area,
    );
}

async fn handle_key(app: &mut App, key: KeyEvent) -> Result<bool> {
    if app.help_overlay.is_some() {
        app.help_overlay = None;
        return Ok(false);
    }
    if matches!(key.code, KeyCode::Char('?')) {
        let context = match app.tab {
            Tab::Config => "config_editor",
            Tab::Monitor => "connection_monitor",
            Tab::Privacy => "privacy_dashboard",
            Tab::PrivacyHeaders => "privacy_headers",
            Tab::Logs => "log_viewer",
            Tab::Proxy => "proxy",
        };
        app.help_overlay = Some(show_help_overlay(context));
        return Ok(false);
    }
    if matches!(key.code, KeyCode::Char('q')) {
        return Ok(true);
    }
    if matches!(key.code, KeyCode::Char('c'))
        && key
            .modifiers
            .contains(crossterm::event::KeyModifiers::CONTROL)
    {
        return Ok(true);
    }
    if matches!(key.code, KeyCode::Char('m')) {
        app.cycle_user_mode();
        app.status_line = match app.user_mode {
            UserMode::Simple => "Режим интерфейса: простой".to_owned(),
            UserMode::Advanced => "Режим интерфейса: расширенный".to_owned(),
        };
        return Ok(false);
    }
    if matches!(key.code, KeyCode::Tab) {
        app.tab = match app.user_mode {
            UserMode::Simple => match app.tab {
                Tab::Config => Tab::Privacy,
                Tab::Privacy => Tab::PrivacyHeaders,
                Tab::PrivacyHeaders => Tab::Proxy,
                Tab::Proxy => Tab::Config,
                Tab::Monitor | Tab::Logs => Tab::Config,
            },
            UserMode::Advanced => match app.tab {
                Tab::Config => Tab::Monitor,
                Tab::Monitor => Tab::Privacy,
                Tab::Privacy => Tab::PrivacyHeaders,
                Tab::PrivacyHeaders => Tab::Logs,
                Tab::Logs => Tab::Proxy,
                Tab::Proxy => Tab::Config,
            },
        };
        return Ok(false);
    }

    match key.code {
        KeyCode::Char('1') => app.tab = Tab::Config,
        KeyCode::Char('2') => {
            app.tab = match app.user_mode {
                UserMode::Simple => Tab::Privacy,
                UserMode::Advanced => Tab::Monitor,
            }
        }
        KeyCode::Char('3') => {
            app.tab = match app.user_mode {
                UserMode::Simple => Tab::PrivacyHeaders,
                UserMode::Advanced => Tab::Privacy,
            }
        }
        KeyCode::Char('4') => {
            app.tab = match app.user_mode {
                UserMode::Simple => Tab::Proxy,
                UserMode::Advanced => Tab::PrivacyHeaders,
            }
        }
        KeyCode::Char('5') => {
            if app.user_mode == UserMode::Advanced {
                app.tab = Tab::Logs;
            }
        }
        KeyCode::Char('6') => {
            if app.user_mode == UserMode::Advanced {
                app.tab = Tab::Proxy;
            }
        }
        _ => {}
    }

    match app.tab {
        Tab::Config => match app.config_editor.handle_input(key)? {
            ConfigAction::Saved => {
                app.config_editor.save_to_file(&app.config_path)?;
                app.status_line = format!("Сохранено {}", app.config_path.display());
            }
            ConfigAction::Reloaded => {
                app.config_editor.reload_from_file(&app.config_path)?;
                app.status_line = "Конфигурация перезагружена".to_owned();
            }
            ConfigAction::SaveRequested => {}
            ConfigAction::Back | ConfigAction::None => {}
        },
        Tab::Monitor => match key.code {
            KeyCode::Up => app.conn_monitor.select_prev(),
            KeyCode::Down => app.conn_monitor.select_next(),
            KeyCode::Char('r') => app.conn_monitor.refresh(),
            _ => {}
        },
        Tab::Privacy => match key.code {
            KeyCode::Char('v') => {
                cycle_referer_mode(&mut app.config_editor.config);
                app.status_line = format!(
                    "Режим Referer: {:?}",
                    app.config_editor.config.privacy.referer.mode
                );
            }
            KeyCode::Char('b') => {
                let v = &mut app.config_editor.config.privacy.tracker_blocker.enabled;
                *v = !*v;
                app.status_line =
                    format!("Блокировщик трекеров: {}", if *v { "вкл" } else { "выкл" });
            }
            KeyCode::Char('n') => {
                let v = &mut app.config_editor.config.privacy.signals.send_dnt;
                *v = !*v;
                app.status_line = format!("DNT: {}", if *v { "вкл" } else { "выкл" });
            }
            KeyCode::Char('g') => {
                let v = &mut app.config_editor.config.privacy.signals.send_gpc;
                *v = !*v;
                app.status_line = format!("GPC: {}", if *v { "вкл" } else { "выкл" });
            }
            _ => {}
        },
        Tab::PrivacyHeaders => {
            let _ = app
                .privacy_headers_tab
                .handle_key(key, &mut app.config_editor.config);
        }
        Tab::Logs => handle_logs_key(app, key)?,
        Tab::Proxy => match key.code {
            KeyCode::Char('u') => {
                app.refresh_proxy_diagnostics().await;
                app.status_line = "Диагностика обновлена".to_owned();
            }
            KeyCode::Char('a') => {
                activate_core(app)?;
            }
            KeyCode::Char('x') => {
                deactivate_core(app)?;
                app.refresh_proxy_diagnostics().await;
            }
            KeyCode::Enter => {
                open_author_telegram_channel()?;
                app.status_line = format!("Opening Telegram channel: {AUTHOR_TELEGRAM_URL}");
            }
            _ => {}
        },
    }

    Ok(false)
}

fn handle_mouse(app: &mut App, mouse: MouseEvent) {
    if !matches!(
        mouse.kind,
        MouseEventKind::Down(crossterm::event::MouseButton::Left)
            | MouseEventKind::Drag(crossterm::event::MouseButton::Left)
    ) {
        return;
    }
    if mouse.row > 2 {
        return;
    }

    let tabs = tabs_for_mode(app.user_mode);
    if tabs.is_empty() {
        return;
    }
    let width = crossterm::terminal::size().map(|(w, _)| w).unwrap_or(120);
    let idx = ((mouse.column as usize) * tabs.len()) / (width as usize);
    let idx = idx.min(tabs.len().saturating_sub(1));
    app.tab = tabs[idx];
}

fn tabs_for_mode(mode: UserMode) -> Vec<Tab> {
    match mode {
        UserMode::Simple => vec![Tab::Config, Tab::Privacy, Tab::PrivacyHeaders, Tab::Proxy],
        UserMode::Advanced => vec![
            Tab::Config,
            Tab::Monitor,
            Tab::Privacy,
            Tab::PrivacyHeaders,
            Tab::Logs,
            Tab::Proxy,
        ],
    }
}

fn handle_logs_key(app: &mut App, key: KeyEvent) -> Result<()> {
    if app.log_input_mode == LogInputMode::Search {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.log_input_mode = LogInputMode::Normal;
            }
            KeyCode::Backspace => {
                app.log_search_buf.pop();
                app.log_viewer.set_search_query(app.log_search_buf.clone());
            }
            KeyCode::Char(c) => {
                app.log_search_buf.push(c);
                app.log_viewer.set_search_query(app.log_search_buf.clone());
            }
            _ => {}
        }
        return Ok(());
    }
    match key.code {
        KeyCode::Up => {
            app.log_viewer.scroll_up();
            app.log_selected_line = app.log_viewer.selected_line();
            app.log_auto_scroll = app.log_viewer.auto_scroll();
        }
        KeyCode::Down => {
            app.log_viewer.scroll_down();
            app.log_selected_line = app.log_viewer.selected_line();
            app.log_auto_scroll = app.log_viewer.auto_scroll();
        }
        KeyCode::End | KeyCode::Char('G') => {
            app.log_viewer.jump_to_bottom();
            app.log_selected_line = app.log_viewer.selected_line();
            app.log_auto_scroll = app.log_viewer.auto_scroll();
        }
        KeyCode::Char('/') => app.log_input_mode = LogInputMode::Search,
        KeyCode::Char('f') => {
            app.log_level_idx = (app.log_level_idx + 1) % 6;
            app.apply_log_level_filter();
        }
        KeyCode::Char('k') => {
            app.log_category_idx = (app.log_category_idx + 1) % 4;
            let cat = match app.log_category_idx {
                0 => None,
                1 => Some("[BLOCKED]".to_owned()),
                2 => Some("[PRIVACY]".to_owned()),
                _ => Some("[TRACKER]".to_owned()),
            };
            app.log_viewer.set_category_filter(cat);
        }
        KeyCode::Char('r') => {
            app.log_use_regex = !app.log_use_regex;
            app.log_viewer.set_use_regex(app.log_use_regex);
        }
        KeyCode::Char('s') => {
            app.log_auto_scroll = !app.log_auto_scroll;
            app.log_viewer.set_auto_scroll(app.log_auto_scroll);
            if app.log_auto_scroll {
                app.log_viewer.jump_to_bottom();
                app.log_selected_line = app.log_viewer.selected_line();
            }
        }
        KeyCode::Char('c') => {
            app.log_viewer.clear();
            app.log_selected_line = 0;
        }
        KeyCode::Char('e') => {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let path = PathBuf::from(format!("prime-tui-logs-{ts}.log"));
            export_filtered_logs(app, &path)?;
            app.status_line = format!("Логи экспортированы: {}", path.display());
        }
        KeyCode::Char('y') => {
            let lines = filtered_logs(app);
            if let Some(line) = lines.get(app.log_selected_line) {
                copy_log_line(line)?;
                app.status_line = "Выбранная строка лога скопирована в буфер обмена".to_owned();
            }
        }
        _ => {}
    }
    Ok(())
}

fn open_author_telegram_channel() -> Result<()> {
    open_url_in_browser(AUTHOR_TELEGRAM_URL)
}

fn open_url_in_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .map_err(|e| EngineError::Internal(format!("failed to open browser: {e}")))?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url)
            .spawn()
            .map_err(|e| EngineError::Internal(format!("failed to open browser: {e}")))?;
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| EngineError::Internal(format!("failed to open browser: {e}")))?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(EngineError::Internal(
        "opening browser is not supported on this platform".to_owned(),
    ))
}

fn activate_core(app: &mut App) -> Result<()> {
    let endpoint = app.config_editor.config.system_proxy.socks_endpoint.clone();
    let socks_check = ProxyDiagnostics::check_socks5_listening(&endpoint);
    if matches!(socks_check.level, DiagnosticLevel::Ok) {
        system_proxy_manager().enable(&endpoint)?;
        app.proxy_managed_by_tui = true;
        app.core_start_pending = None;
        app.status_line = format!("Core already running, system proxy -> {endpoint}");
        return Ok(());
    }

    if let Some(child) = app.core_process.as_mut() {
        match child.try_wait() {
            Ok(None) => {
                app.core_start_pending = Some((endpoint.clone(), Instant::now()));
                app.status_line = format!("Core is starting for {endpoint}...");
                return Ok(());
            }
            Ok(Some(_)) | Err(_) => {
                app.core_process = None;
            }
        }
    }

    let mut bin = std::env::current_exe()?;
    bin.set_file_name(if cfg!(windows) {
        "prime-net-engine.exe"
    } else {
        "prime-net-engine"
    });

    let child = Command::new(&bin)
        .arg("--config")
        .arg(&app.config_path)
        .arg("--log-level")
        .arg("info")
        .arg("--log-format")
        .arg("text")
        .arg("socks")
        .arg("--bind")
        .arg(&endpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            EngineError::Internal(format!(
                "не удалось запустить ядро ({}) : {e}",
                bin.display()
            ))
        })?;

    app.core_process = Some(child);
    if let Some(child) = app.core_process.as_mut() {
        attach_core_log_pump(child, app.log_viewer.clone());
    }
    app.core_start_pending = Some((endpoint.clone(), Instant::now()));
    app.status_line = format!("Запуск ядра для {endpoint}...");
    Ok(())
}

fn deactivate_core(app: &mut App) -> Result<()> {
    if let Some(mut child) = app.core_process.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    app.core_start_pending = None;
    system_proxy_manager().disable()?;
    app.proxy_managed_by_tui = false;
    app.status_line = "Ядро остановлено: системный прокси отключён".to_owned();
    Ok(())
}

fn poll_core_startup(app: &mut App) -> Result<()> {
    let Some((endpoint, started)) = app.core_start_pending.clone() else {
        return Ok(());
    };
    let Some(child) = app.core_process.as_mut() else {
        app.core_start_pending = None;
        return Ok(());
    };

    match child.try_wait() {
        Ok(Some(status)) => {
            app.core_process = None;
            app.core_start_pending = None;
            app.proxy_managed_by_tui = false;
            app.status_line = format!("Ядро не запустилось (статус: {status})");
            return Ok(());
        }
        Ok(None) => {}
        Err(e) => {
            app.core_process = None;
            app.core_start_pending = None;
            app.proxy_managed_by_tui = false;
            app.status_line = format!("Не удалось проверить процесс ядра: {e}");
            return Ok(());
        }
    }

    let socks_check = ProxyDiagnostics::check_socks5_listening(&endpoint);
    if matches!(socks_check.level, DiagnosticLevel::Ok) {
        system_proxy_manager().enable(&endpoint)?;
        app.proxy_managed_by_tui = true;
        app.core_start_pending = None;
        app.status_line = format!("Ядро запущено, системный прокси -> {endpoint}");
        return Ok(());
    }

    if started.elapsed() > Duration::from_secs(90) {
        let _ = child.kill();
        let _ = child.wait();
        app.core_process = None;
        app.core_start_pending = None;
        app.proxy_managed_by_tui = false;
        app.status_line = "Таймаут запуска ядра (см. вкладку «Логи»)".to_owned();
    }
    Ok(())
}

fn attach_core_log_pump(child: &mut Child, log_viewer: Arc<LogViewer>) {
    let Some(stderr) = child.stderr.take() else {
        log_viewer.add_log(LogEntry {
            timestamp: SystemTime::now(),
            level: Level::WARN,
            target: "prime_tui".to_owned(),
            message: "stderr ядра не подключён; логи ядра недоступны".to_owned(),
        });
        return;
    };

    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let Ok(n) = reader.read_until(b'\n', &mut buf) else {
                break;
            };
            if n == 0 {
                break;
            }
            while matches!(buf.last(), Some(b'\n' | b'\r')) {
                let _ = buf.pop();
            }
            if buf.is_empty() {
                continue;
            }
            let line = String::from_utf8_lossy(&buf).into_owned();
            let (level, target, message) = parse_core_log_line(&line);
            log_viewer.add_log(LogEntry {
                timestamp: SystemTime::now(),
                level,
                target,
                message,
            });
        }
    });
}

fn parse_core_log_line(line: &str) -> (Level, String, String) {
    let mut parts = line.split_whitespace();
    let _ts = parts.next();
    let Some(raw_level) = parts.next() else {
        return (Level::INFO, "prime_core_raw".to_owned(), line.to_owned());
    };
    let level = match raw_level {
        "ERROR" => Level::ERROR,
        "WARN" => Level::WARN,
        "INFO" => Level::INFO,
        "DEBUG" => Level::DEBUG,
        "TRACE" => Level::TRACE,
        _ => return (Level::INFO, "prime_core_raw".to_owned(), line.to_owned()),
    };
    let Some(target) = parts.next() else {
        return (level, "prime_core".to_owned(), line.to_owned());
    };
    let message = parts.collect::<Vec<_>>().join(" ");
    (level, target.to_owned(), message)
}

fn proxy_mode_label(mode: &ProxyMode) -> &'static str {
    match mode {
        ProxyMode::Off => "Выключен",
        ProxyMode::All => "Весь трафик через SOCKS",
        ProxyMode::Pac => "Через PAC",
    }
}

fn copy_log_line(line: &LogEntry) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| EngineError::Internal(format!("буфер обмена недоступен: {e}")))?;
    let text = format!(
        "{} {:5} {} {}",
        format_timestamp(line.timestamp),
        line.level,
        line.target,
        line.message
    );
    clipboard
        .set_text(text)
        .map_err(|e| EngineError::Internal(format!("ошибка записи в буфер обмена: {e}")))?;
    Ok(())
}

fn load_config_for_tui(path: &Path) -> (EngineConfig, Option<String>) {
    if !path.exists() {
        let cfg = default_tui_config();
        let note = "Конфиг не найден: создан конфиг по умолчанию (обход включен: direct + aggressive DNS/evasion)"
            .to_owned();
        let _ = persist_default_config(path, &cfg);
        return (cfg, Some(note));
    }

    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) => {
            let cfg = default_tui_config();
            return (
                cfg,
                Some(format!(
                    "Не удалось прочитать конфиг ({}): {}. Загружены значения по умолчанию (обход: direct + aggressive DNS/evasion).",
                    path.display(),
                    e
                )),
            );
        }
    };

    match toml::from_str::<EngineConfig>(&raw) {
        Ok(mut cfg) => {
            let repairs = cfg.apply_compat_repairs();
            let runtime_note = apply_runtime_pt_repair(&mut cfg);
            if let Err(e) = cfg.validate() {
                let fallback = default_tui_config();
                (
                    fallback,
                    Some(format!(
                        "Ошибка в конфигурации: {}. Загружены значения по умолчанию (обход: direct + aggressive DNS/evasion); исправьте конфиг и сохраните.",
                        e,
                    )),
                )
            } else if !repairs.is_empty() || runtime_note.is_some() {
                let persisted = !repairs.is_empty() && persist_default_config(path, &cfg).is_ok();
                let mut notes = Vec::new();
                if !repairs.is_empty() {
                    notes.push(format!(
                        "Применены совместимые исправления конфига: {}",
                        repairs.join("; ")
                    ));
                }
                if let Some(n) = runtime_note {
                    notes.push(n);
                }
                (
                    cfg,
                    Some(format!(
                        "{}. {}",
                        notes.join(" "),
                        if !repairs.is_empty() && persisted {
                            "Исправления сохранены автоматически."
                        } else if !repairs.is_empty() {
                            "Сохраните конфиг клавишей [s]."
                        } else {
                            "Исправление времени выполнения применено только для текущего запуска."
                        }
                    )),
                )
            } else {
                (cfg, None)
            }
        }
        Err(e) => {
            let cfg = default_tui_config();
            (
                cfg,
                Some(format!(
                    "Ошибка разбора конфига: {}. Загружены значения по умолчанию (обход: direct + aggressive DNS/evasion).",
                    e
                )),
            )
        }
    }
}

fn default_tui_config() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.system_proxy.auto_configure = true;
    cfg.system_proxy.mode = SystemProxyMode::All;
    // Default simple profile must work without external PT binaries.
    cfg.pt = None;
    apply_aggressive_direct_profile(&mut cfg);
    cfg
}

fn apply_aggressive_direct_profile(cfg: &mut EngineConfig) {
    cfg.anticensorship.dot_enabled = true;
    cfg.anticensorship.doq_enabled = true;
    cfg.anticensorship.system_dns_enabled = true;
    cfg.anticensorship.doh_providers = vec![
        "adguard".to_owned(),
        "google".to_owned(),
        "quad9".to_owned(),
    ];
    cfg.anticensorship.dot_servers = vec![
        "94.140.14.14:853".to_owned(),
        "94.140.15.15:853".to_owned(),
        "8.8.8.8:853".to_owned(),
        "8.8.4.4:853".to_owned(),
    ];
    cfg.anticensorship.dot_sni = "dns.adguard-dns.com".to_owned();
    cfg.anticensorship.doq_servers =
        vec!["94.140.14.14:784".to_owned(), "94.140.15.15:784".to_owned()];
    cfg.anticensorship.doq_sni = "dns.adguard-dns.com".to_owned();
    cfg.anticensorship.dns_fallback_chain = vec![
        DnsResolverKind::Doh,
        DnsResolverKind::Dot,
        DnsResolverKind::Doq,
        DnsResolverKind::System,
    ];
    cfg.anticensorship.ech_mode = Some(EchMode::Auto);
    cfg.evasion.strategy = Some(EvasionStrategy::Auto);
    cfg.evasion.traffic_shaping_enabled = true;
    if cfg.evasion.client_hello_split_offsets.is_empty() {
        cfg.evasion.client_hello_split_offsets = vec![1, 6, 40];
    }
}

fn persist_default_config(path: &Path, cfg: &EngineConfig) -> std::io::Result<()> {
    let rendered = toml::to_string_pretty(cfg).unwrap_or_else(|_| String::new());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, rendered)
}

fn apply_runtime_pt_repair(cfg: &mut EngineConfig) -> Option<String> {
    let pt = cfg.pt.as_ref()?;

    if pt_auto_bootstrap_enabled() {
        return None;
    }
    let missing = match pt.kind {
        PluggableTransportKind::Snowflake => {
            let s = pt.snowflake.as_ref()?;
            let mut tools = Vec::new();
            if !binary_exists_for_tui(&s.tor_bin, Some("tor")) {
                tools.push(format!("tor ({})", s.tor_bin));
            }
            if !binary_exists_for_tui(&s.snowflake_bin, Some("snowflake-client")) {
                tools.push(format!("snowflake-client ({})", s.snowflake_bin));
            }
            tools
        }
        PluggableTransportKind::Obfs4 => {
            let o = pt.obfs4.as_ref()?;
            let mut tools = Vec::new();
            if !binary_exists_for_tui(&o.tor_bin, Some("tor")) {
                tools.push(format!("tor ({})", o.tor_bin));
            }
            if !binary_exists_for_tui(&o.obfs4proxy_bin, Some("obfs4proxy")) {
                tools.push(format!("obfs4proxy ({})", o.obfs4proxy_bin));
            }
            tools
        }
        // Trojan/Shadowsocks do not depend on tor binaries.
        PluggableTransportKind::Trojan | PluggableTransportKind::Shadowsocks => Vec::new(),
    };
    if missing.is_empty() {
        return None;
    }

    cfg.pt = None;
    apply_aggressive_direct_profile(cfg);

    Some(format!(
        "PT автоматически отключен: отсутствуют инструменты [{}], при выключенном PRIME_PT_AUTO_BOOTSTRAP; включен профиль direct + aggressive DNS/evasion",
        missing.join(", ")
    ))
}

fn pt_auto_bootstrap_enabled() -> bool {
    std::env::var("PRIME_PT_AUTO_BOOTSTRAP")
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off"
            )
        })
        .unwrap_or(true)
}

fn binary_exists_for_tui(bin: &str, bundled_tool: Option<&str>) -> bool {
    let p = Path::new(bin);
    if p.is_absolute() || bin.contains(std::path::MAIN_SEPARATOR) || bin.contains('/') {
        return p.is_file();
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return bundled_tool
            .and_then(resolve_bundled_tool_path_for_tui)
            .is_some_and(|p| p.is_file());
    };
    for dir in std::env::split_paths(&path_var) {
        let direct = dir.join(bin);
        if direct.is_file() {
            return true;
        }
        #[cfg(windows)]
        {
            for ext in windows_pathexts_for_tui() {
                let with_ext = dir.join(format!("{bin}{ext}"));
                if with_ext.is_file() {
                    return true;
                }
            }
        }
    }
    bundled_tool
        .and_then(resolve_bundled_tool_path_for_tui)
        .is_some_and(|p| p.is_file())
}

fn resolve_bundled_tool_path_for_tui(tool: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join("pt-tools").join(tool_file_name_for_tui(tool)))
}

fn tool_file_name_for_tui(tool: &str) -> String {
    #[cfg(windows)]
    {
        if tool.ends_with(".exe") {
            return tool.to_owned();
        }
        format!("{tool}.exe")
    }
    #[cfg(not(windows))]
    {
        tool.to_owned()
    }
}

#[cfg(windows)]
fn windows_pathexts_for_tui() -> Vec<String> {
    let from_env = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned());
    from_env
        .split(';')
        .filter_map(|v| {
            let t = v.trim();
            if t.is_empty() {
                None
            } else if t.starts_with('.') {
                Some(t.to_owned())
            } else {
                Some(format!(".{t}"))
            }
        })
        .collect()
}

fn install_panic_report_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_owned());
        let payload = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            (*s).to_owned()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "полезная нагрузка panic недоступна".to_owned()
        };
        let body = format!("panic в {location}\n{payload}\n");
        let _ = write_crash_report("panic", &body);
    }));
}

fn write_crash_report(kind: &str, body: &str) -> Option<PathBuf> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let file_name = format!("prime-tui-{kind}-{ts}.txt");
    let base = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .or_else(|| std::env::current_dir().ok())?;
    let path = base.join(file_name);
    if fs::write(&path, body).is_ok() {
        Some(path)
    } else {
        None
    }
}

fn init_tui_tracing(log_viewer: Arc<LogViewer>) -> Result<()> {
    let layer = TuiLayer::new(log_viewer);
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        EngineError::Internal(format!("не удалось инициализировать трассировку: {e}"))
    })?;
    Ok(())
}

fn filtered_logs(app: &App) -> Vec<LogEntry> {
    app.log_viewer.filtered_logs()
}
fn export_filtered_logs(app: &App, path: &Path) -> Result<()> {
    let mut file = std::fs::File::create(path)?;
    for entry in filtered_logs(app) {
        writeln!(
            file,
            "{} {:5} {:<24} {}",
            format_timestamp(entry.timestamp),
            entry.level,
            entry.target,
            entry.message
        )?;
    }
    Ok(())
}

fn compose_status_line(app: &App) -> String {
    let privacy = match privacy_level(&app.config_editor.config.privacy) {
        PrivacyLevel::Low => "низкий",
        PrivacyLevel::Medium => "средний",
        PrivacyLevel::High => "высокий",
    };
    format!(
        "{} | конфиг={} | пресет={} | приватность={}",
        app.status_line,
        app.config_path.display(),
        detect_preset(&app.config_editor.config),
        privacy
    )
}

fn detect_preset(cfg: &EngineConfig) -> &'static str {
    if cfg.privacy.tracker_blocker.enabled
        && cfg.privacy.referer.enabled
        && matches!(
            cfg.privacy.referer.mode,
            prime_net_engine_core::config::RefererMode::Strip
        )
    {
        return "strict-privacy";
    }
    if cfg.privacy.referer.enabled
        && matches!(
            cfg.privacy.referer.mode,
            prime_net_engine_core::config::RefererMode::OriginOnly
        )
        && !cfg.privacy.tracker_blocker.enabled
    {
        return "balanced-privacy";
    }
    if matches!(cfg.evasion.strategy, Some(EvasionStrategy::Auto))
        && cfg.anticensorship.dot_enabled
        && cfg.anticensorship.doq_enabled
    {
        return "aggressive-evasion";
    }
    if cfg.evasion.strategy.is_none() && cfg.anticensorship.system_dns_enabled {
        return "max-compatibility";
    }
    "custom"
}

fn parse_config_path(args: Vec<String>) -> Result<PathBuf> {
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--config" {
            let p = args
                .get(i + 1)
                .ok_or_else(|| EngineError::InvalidInput("--config требует путь".to_owned()))?;
            return Ok(PathBuf::from(p));
        }
        i += 1;
    }
    Ok(default_config_path())
}

async fn startup_health_summary(config: &EngineConfig) -> String {
    let checker = HealthChecker::new(config.clone());
    let results = checker.run_all_checks().await;
    let mut ok = 0usize;
    let mut warn = 0usize;
    let mut err = 0usize;
    for r in &results {
        match r.level {
            HealthLevel::Ok => ok += 1,
            HealthLevel::Info => {}
            HealthLevel::Warn => warn += 1,
            HealthLevel::Error => err += 1,
        }
    }
    if err > 0 {
        format!("Состояние: {ok} OK, {warn} ПРЕДУПР, {err} ОШИБОК")
    } else if warn > 0 {
        format!("Состояние: {ok} OK, {warn} ПРЕДУПР")
    } else {
        format!("Состояние: {ok} OK")
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
