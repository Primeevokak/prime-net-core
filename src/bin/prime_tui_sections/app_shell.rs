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

