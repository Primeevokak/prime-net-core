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
                app.core_event_rx = None;
            }
        }
    }

    let mut bin = std::env::current_exe()?;
    bin.set_file_name(if cfg!(windows) {
        "prime-net-engine.exe"
    } else {
        "prime-net-engine"
    });

    let mut command = Command::new(&bin);
    command
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
        .stderr(Stdio::piped());
    let child = command.spawn().map_err(|e| {
        EngineError::Internal(format!(
            "не удалось запустить ядро ({}) : {e}",
            bin.display()
        ))
    })?;

    app.core_process = Some(child);
    let (event_tx, event_rx) = mpsc::channel();
    if let Some(child) = app.core_process.as_mut() {
        attach_core_log_pump(child, app.log_viewer.clone(), event_tx);
    }
    app.core_event_rx = Some(event_rx);
    app.core_start_pending = Some((endpoint.clone(), Instant::now()));
    app.status_line = format!("Запуск ядра для {endpoint}...");
    Ok(())
}

fn deactivate_core(app: &mut App) -> Result<()> {
    if let Some(mut child) = app.core_process.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    app.core_event_rx = None;
    app.core_start_pending = None;
    system_proxy_manager().disable()?;
    app.proxy_managed_by_tui = false;
    app.status_line = "Ядро остановлено: системный прокси отключён".to_owned();
    Ok(())
}

fn restart_core_for_packet_bypass_prompt(app: &mut App, allow_unverified: bool) -> Result<()> {
    if app.core_process.is_some() {
        deactivate_core(app)?;
    }
    if allow_unverified {
        app.status_line =
            "Небезопасный запуск packet bypass отклонен: включен строгий trust mode".to_owned();
    }
    activate_core(app)
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
            app.core_event_rx = None;
            app.core_start_pending = None;
            app.proxy_managed_by_tui = false;
            app.status_line = format!("Ядро не запустилось (статус: {status})");
            return Ok(());
        }
        Ok(None) => {}
        Err(e) => {
            app.core_process = None;
            app.core_event_rx = None;
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
        app.core_event_rx = None;
        app.core_start_pending = None;
        app.proxy_managed_by_tui = false;
        app.status_line = "Таймаут запуска ядра (см. вкладку «Логи»)".to_owned();
    }
    Ok(())
}

fn drain_core_events(app: &mut App) {
    let mut disconnected = false;
    if let Some(rx) = app.core_event_rx.as_ref() {
        loop {
            match rx.try_recv() {
                Ok(CoreUiEvent::PacketBypassIntegrityCheckFailed { source_url }) => {
                    if app.packet_bypass_bootstrap_prompt.is_none()
                        && app.packet_bypass_unsafe_confirm_prompt.is_none()
                    {
                        app.packet_bypass_bootstrap_prompt =
                            Some(PacketBypassBootstrapPrompt { source_url });
                        app.status_line = "Packet bypass не запущен безопасно: выберите дальнейшее действие".to_owned();
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
    }
    if disconnected {
        app.core_event_rx = None;
    }
}

fn attach_core_log_pump(
    child: &mut Child,
    log_viewer: Arc<LogViewer>,
    event_tx: mpsc::Sender<CoreUiEvent>,
) {
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
        let mut integrity_alert_sent = false;
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
            if !integrity_alert_sent && is_packet_bypass_missing_sidecar_issue(&target, &message) {
                let source_url = extract_sidecar_source_url(&message);
                let _ = event_tx.send(CoreUiEvent::PacketBypassIntegrityCheckFailed { source_url });
                integrity_alert_sent = true;
            }
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

fn is_packet_bypass_missing_sidecar_issue(target: &str, message: &str) -> bool {
    if target != "socks_cmd" && target != "packet_bypass" {
        return false;
    }
    message.contains("packet bypass integrity check failed: no sha256 sidecar")
        || message.contains("packet bypass integrity check failed")
}

fn extract_sidecar_source_url(message: &str) -> Option<String> {
    let marker = "no sha256 sidecar for '";
    let idx = message.find(marker)?;
    let rest = &message[idx + marker.len()..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_owned())
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
                let _ = persist_default_config(path, &fallback);
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
            let _ = persist_default_config(path, &cfg);
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
    let rendered = toml::to_string_pretty(cfg).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to serialize config: {e}"),
        )
    })?;
    if rendered.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "refusing to write empty config",
        ));
    }
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

fn compose_status_line(app: &App) -> Line<'static> {
    let mut spans = Vec::new();
    
    // 1. Core Process Status
    let core_running = app.core_process.is_some();
    if core_running {
        spans.push(Span::styled(" ЯДРО: ВКЛ ", Style::default().bg(Color::Green).fg(Color::Black)));
    } else {
        spans.push(Span::styled(" ЯДРО: ВЫКЛ ", Style::default().bg(Color::Red).fg(Color::White)));
    }
    spans.push(Span::raw("  "));

    // 2. Mode Status
    let cfg = &app.config_editor.config;
    let pt_active = cfg.pt.is_some();
    
    // Check if we actually have active bypass backends in the log history or process state
    // For now, we'll use a slightly smarter heuristic for the TUI
    let packet_bypass_configured = cfg.evasion.packet_bypass_enabled;
    let internal_relay_active = cfg.evasion.prime_mode || cfg.evasion.strategy.is_some();

    if core_running && pt_active {
        spans.push(Span::styled(" PT: АКТИВЕН ", Style::default().fg(Color::Cyan)));
    } else if core_running && packet_bypass_configured {
        // If it's configured but maybe failed, we show it in yellow to indicate 'trying' or 'fallback'
        spans.push(Span::styled(" PACKET BYPASS: ВКЛ ", Style::default().fg(Color::Magenta)));
    } else if core_running && internal_relay_active {
        spans.push(Span::styled(" РЕЛЕ: АКТИВНО ", Style::default().fg(Color::Yellow)));
    } else if core_running {
        spans.push(Span::styled(" ПРОКСИ: DIRECT ", Style::default().fg(Color::Gray)));
    }

    spans.push(Span::raw(" | "));
    spans.push(Span::raw(app.status_line.clone()));

    Line::from(spans)
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
