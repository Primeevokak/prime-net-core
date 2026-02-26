fn handle_logs_key(app: &mut App, key: KeyEvent) -> Result<()> {
    if app.log_input_mode == LogInputMode::Search {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => { app.log_input_mode = LogInputMode::Normal; }
            KeyCode::Backspace => { app.log_search_buf.pop(); app.log_viewer.set_search_query(app.log_search_buf.clone()); }
            KeyCode::Char(c) => { app.log_search_buf.push(c); app.log_viewer.set_search_query(app.log_search_buf.clone()); }
            _ => {}
        }
        return Ok(());
    }
    match key.code {
        KeyCode::Up => { app.log_viewer.scroll_up(); app.log_selected_line = app.log_viewer.selected_line(); app.log_auto_scroll = app.log_viewer.auto_scroll(); }
        KeyCode::Down => { app.log_viewer.scroll_down(); app.log_selected_line = app.log_viewer.selected_line(); app.log_auto_scroll = app.log_viewer.auto_scroll(); }
        KeyCode::Char('/') => app.log_input_mode = LogInputMode::Search,
        KeyCode::Char('s') => { app.log_auto_scroll = !app.log_auto_scroll; app.log_viewer.set_auto_scroll(app.log_auto_scroll); }
        KeyCode::Char('c') => { app.log_viewer.clear(); app.log_selected_line = 0; }
        KeyCode::Char('y') => {
            let lines = app.log_viewer.filtered_logs();
            if let Some(line) = lines.get(app.log_selected_line) { let _ = copy_log_line(line); app.status_line = "Строка скопирована".to_owned(); }
        }
        _ => {}
    }
    Ok(())
}

fn copy_log_line(entry: &LogEntry) -> Result<()> {
    let ts = format_timestamp(entry.timestamp);
    let count_label = if entry.count > 1 { format!(" (x{})", entry.count) } else { String::new() };
    let text = format!("{ts} {:5} {} {}{}", entry.level, entry.target, entry.message, count_label);
    #[cfg(windows)]
    {
        use std::io::Write;
        let mut child = Command::new("clip").stdin(Stdio::piped()).spawn().map_err(|e| EngineError::Internal(format!("failed clip: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() { let _ = stdin.write_all(text.as_bytes()); }
        let _ = child.wait();
    }
    Ok(())
}

fn activate_core(app: &mut App) -> Result<()> {
    let endpoint = app.config_editor.config.system_proxy.socks_endpoint.clone();
    let mut bin = std::env::current_exe()?;
    bin.set_file_name(if cfg!(windows) { "prime-net-engine.exe" } else { "prime-net-engine" });
    let mut command = Command::new(&bin);
    command.arg("--config").arg(&app.config_path).arg("--bind").arg(&endpoint).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    let child = command.spawn().map_err(|e| EngineError::Internal(format!("запуск провален: {e}")))?;
    app.core_process = Some(child);
    let (event_tx, event_rx) = mpsc::channel();
    if let Some(child) = app.core_process.as_mut() { attach_core_log_pump(child, app.log_viewer.clone(), event_tx); }
    app.core_event_rx = Some(event_rx);
    app.core_start_pending = Some((endpoint.clone(), Instant::now()));
    app.status_line = format!("Ядро запускается...");
    Ok(())
}

fn deactivate_core(app: &mut App) -> Result<()> {
    if let Some(mut child) = app.core_process.take() { let _ = child.kill(); let _ = child.wait(); }
    app.core_event_rx = None; app.core_start_pending = None;
    let _ = system_proxy_manager().disable();
    app.proxy_managed_by_tui = false;
    app.status_line = "Ядро остановлено".to_owned();
    Ok(())
}

fn poll_core_startup(app: &mut App) -> Result<()> {
    if let Some(child) = app.core_process.as_mut() {
        if let Ok(Some(status)) = child.try_wait() {
            app.core_process = None; app.core_start_pending = None; app.proxy_managed_by_tui = false;
            let _ = system_proxy_manager().disable();
            app.status_line = format!("Ядро упало: {status}");
            return Ok(());
        }
    }
    if let Some((endpoint, started)) = app.core_start_pending.clone() {
        if let Some(status) = &app.current_proxy_status {
            if status.enabled { app.core_start_pending = None; app.proxy_managed_by_tui = true; app.status_line = format!("Ядро активно на {endpoint}"); }
        }
        if started.elapsed() > Duration::from_secs(30) { let _ = deactivate_core(app); app.status_line = "Таймаут старта".to_owned(); }
    }
    Ok(())
}

fn drain_core_events(app: &mut App) {
    if let Some(rx) = app.core_event_rx.as_ref() {
        while let Ok(event) = rx.try_recv() {
            match event { CoreUiEvent::PacketBypassIntegrityCheckFailed { source_url } => { app.packet_bypass_bootstrap_prompt = Some(PacketBypassBootstrapPrompt { source_url }); } }
        }
    }
}

fn attach_core_log_pump(child: &mut Child, log_viewer: Arc<LogViewer>, _event_tx: mpsc::Sender<CoreUiEvent>) {
    let Some(stderr) = child.stderr.take() else { return; };
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stderr);
        let mut line = String::new();
        while let Ok(n) = reader.read_line(&mut line) {
            if n == 0 { break; }
            log_viewer.add_log(LogEntry { timestamp: SystemTime::now(), level: Level::INFO, target: "core".to_owned(), message: line.trim().to_owned(), count: 1 });
            line.clear();
        }
    });
}

fn export_filtered_logs(app: &App, path: &Path) -> Result<()> {
    use std::io::Write;
    let mut file = fs::File::create(path).map_err(EngineError::Io)?;
    for entry in app.log_viewer.filtered_logs() {
        let ts = format_timestamp(entry.timestamp);
        let _ = writeln!(file, "{} [{}] {}", ts, entry.target, entry.message);
    }
    Ok(())
}

fn tabs_for_mode(mode: UserMode) -> Vec<Tab> {
    match mode {
        UserMode::Simple => vec![Tab::Config, Tab::Privacy, Tab::Proxy],
        UserMode::Advanced => vec![Tab::Config, Tab::Monitor, Tab::Privacy, Tab::PrivacyHeaders, Tab::Logs, Tab::Proxy],
    }
}

fn build_classifier_cache_clear_prompt(cfg: &EngineConfig) -> ClassifierCacheClearPrompt {
    let path = classifier_cache_path_for(cfg);
    let mut exists = false;
    let mut size_bytes = 0u64;
    let mut modified_unix = None;
    if let Ok(meta) = fs::metadata(&path) {
        exists = true;
        size_bytes = meta.len();
        modified_unix = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs());
    }
    ClassifierCacheClearPrompt { path, exists, size_bytes, modified_unix }
}

fn classifier_cache_path_for(cfg: &EngineConfig) -> PathBuf {
    let configured = cfg.evasion.classifier_cache_path.trim();
    if !configured.is_empty() { return expand_tilde(configured); }
    if let Some(dir) = dirs::cache_dir() { return dir.join("prime-net-engine").join("relay-classifier.json"); }
    expand_tilde("~/.cache/prime-net-engine/relay-classifier.json")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassifierCacheClearResult { Removed, Missing }

fn clear_classifier_cache_file(path: &Path) -> Result<ClassifierCacheClearResult> {
    match fs::remove_file(path) {
        Ok(()) => Ok(ClassifierCacheClearResult::Removed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ClassifierCacheClearResult::Missing),
        Err(e) => Err(EngineError::Internal(format!("fail remove cache {}: {e}", path.display()))),
    }
}

fn startup_health_summary(cfg: &EngineConfig) -> String { format!("Конфиг: {:?}", cfg.evasion.strategy) }
fn load_config_for_tui(path: &Path) -> (EngineConfig, Option<String>) {
    match EngineConfig::from_file(path.to_path_buf()) { Ok(c) => (c, None), Err(e) => (EngineConfig::default(), Some(format!("Ошибка конфига: {e}"))) }
}
fn parse_config_path(args: Vec<String>) -> Result<PathBuf> { if let Some(p) = args.get(0) { return Ok(PathBuf::from(p)); } Ok(PathBuf::from("config.toml")) }
fn init_tui_tracing(viewer: Arc<LogViewer>) -> Result<()> {
    let layer = TuiLayer::new(viewer);
    let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer));
    Ok(())
}
fn install_panic_report_hook() {}
fn proxy_mode_label(mode: &ProxyMode) -> &'static str { match mode { ProxyMode::All => "Весь трафик", ProxyMode::Off => "Выключен", ProxyMode::Pac => "PAC скрипт" } }
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage((100 - percent_y) / 2), Constraint::Percentage(percent_y), Constraint::Percentage((100 - percent_y) / 2)]).split(r);
    Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage((100 - percent_x) / 2), Constraint::Percentage(percent_x), Constraint::Percentage((100 - percent_x) / 2)]).split(popup_layout[1])[1]
}
fn compose_status_line(app: &App) -> String { app.status_line.clone() }
fn restart_core_for_packet_bypass_prompt(app: &mut App, _allow_unverified: bool) -> Result<()> { let _ = deactivate_core(app); activate_core(app) }
