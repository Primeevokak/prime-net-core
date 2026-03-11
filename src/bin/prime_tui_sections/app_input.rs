async fn handle_key(app: &mut App, key: KeyEvent) -> Result<bool> {
    if let Some(confirm) = app.packet_bypass_unsafe_confirm_prompt.clone() {
        match key.code {
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.packet_bypass_unsafe_confirm_prompt = None;
                app.packet_bypass_bootstrap_prompt = None;
                app.status_line = "Запуск в риск-режиме отменён".to_owned();
            }
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                let remaining = 10u64.saturating_sub(confirm.started_at.elapsed().as_secs());
                if remaining > 0 {
                    app.status_line = format!(
                        "Подтверждение риск-режима станет доступно через {remaining} с"
                    );
                } else {
                    app.packet_bypass_unsafe_confirm_prompt = None;
                    app.packet_bypass_bootstrap_prompt = None;
                    restart_core_for_packet_bypass_prompt(app, true)?;
                    app.status_line =
                        "Запуск в небезопасном режиме: проверка целостности отключена"
                            .to_owned();
                }
            }
            _ => {}
        }
        return Ok(false);
    }
    if app.packet_bypass_bootstrap_prompt.is_some() {
        match key.code {
            KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => {
                app.packet_bypass_bootstrap_prompt = None;
                restart_core_for_packet_bypass_prompt(app, false)?;
                app.status_line = "Повтор безопасного запуска packet bypass".to_owned();
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                let source_url = app.packet_bypass_bootstrap_prompt
                    .as_ref()
                    .and_then(|p| p.source_url.clone());
                app.packet_bypass_bootstrap_prompt = None;
                app.packet_bypass_unsafe_confirm_prompt = Some(PacketBypassUnsafeConfirmPrompt {
                    source_url,
                    started_at: Instant::now(),
                });
                app.status_line = "Подтвердите запуск без проверки целостности".to_owned();
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.packet_bypass_bootstrap_prompt = None;
                app.status_line =
                    "Оставлен direct-режим: запуск packet bypass без проверки отменён".to_owned();
            }
            _ => {}
        }
        return Ok(false);
    }
    if let Some(prompt) = app.classifier_cache_clear_prompt.clone() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                app.classifier_cache_clear_prompt = None;
                match clear_classifier_cache_file(&prompt.path)? {
                    ClassifierCacheClearResult::Removed => {
                        app.status_line = format!(
                            "Кэш relay-классификатора очищен: {} (перезапустите ядро, чтобы применить изменения в памяти)",
                            prompt.path.display()
                        );
                    }
                    ClassifierCacheClearResult::Missing => {
                        app.status_line = format!(
                            "Файл кэша relay-классификатора уже отсутствует: {}",
                            prompt.path.display()
                        );
                    }
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                app.classifier_cache_clear_prompt = None;
                app.status_line = "Очистка кэша relay-классификатора отменена".to_owned();
            }
            _ => {}
        }
        return Ok(false);
    }
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
                Tab::Proxy => Tab::Config,
                Tab::Config => Tab::Privacy,
                Tab::Privacy => Tab::Proxy,
                _ => Tab::Proxy,
            },
            UserMode::Advanced => match app.tab {
                Tab::Proxy => Tab::Config,
                Tab::Config => Tab::Monitor,
                Tab::Monitor => Tab::Privacy,
                Tab::Privacy => Tab::PrivacyHeaders,
                Tab::PrivacyHeaders => Tab::Logs,
                Tab::Logs => Tab::Proxy,
            },
        };
        return Ok(false);
    }

    match key.code {
        KeyCode::Char('1') => app.tab = Tab::Proxy,
        KeyCode::Char('2') => app.tab = Tab::Config,
        KeyCode::Char('3') => {
            app.tab = match app.user_mode {
                UserMode::Simple => Tab::Privacy,
                UserMode::Advanced => Tab::Monitor,
            }
        }
        KeyCode::Char('4') => {
            app.tab = match app.user_mode {
                UserMode::Simple => Tab::Proxy, // no-op fallback
                UserMode::Advanced => Tab::Privacy,
            }
        }
        KeyCode::Char('5') => {
            if app.user_mode == UserMode::Advanced {
                app.tab = Tab::PrivacyHeaders;
            }
        }
        KeyCode::Char('6') => {
            if app.user_mode == UserMode::Advanced {
                app.tab = Tab::Logs;
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
            KeyCode::Char('d') => {
                app.classifier_cache_clear_prompt =
                    Some(build_classifier_cache_clear_prompt(&app.config_editor.config));
                app.status_line = "Подтвердите очистку кэша relay-классификатора".to_owned();
            }
            KeyCode::Char('a') => {
                if app.network_mode == NetworkMode::Vpn {
                    deactivate_tun(app)?;
                }
                activate_core(app, false)?;
            }
            KeyCode::Char('x') => {
                if app.network_mode == NetworkMode::Vpn {
                    deactivate_tun(app)?;
                } else {
                    deactivate_core(app)?;
                    app.refresh_proxy_diagnostics().await;
                }
            }
            KeyCode::Char('v') => {
                match app.network_mode {
                    NetworkMode::Proxy => activate_tun(app)?,
                    NetworkMode::Vpn   => {
                        deactivate_tun(app)?;
                        app.refresh_proxy_diagnostics().await;
                    }
                }
            }
            KeyCode::Enter => {
                open_author_telegram_channel()?;
                app.status_line = format!("Открываю Telegram-канал: {AUTHOR_TELEGRAM_URL}");
            }
            _ => {}
        },
    }

    Ok(false)
}

fn handle_mouse(app: &mut App, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollUp => {
            if app.tab == Tab::Logs {
                app.log_viewer.scroll_up();
                app.log_selected_line = app.log_viewer.selected_line();
                app.log_auto_scroll = app.log_viewer.auto_scroll();
            }
            return;
        }
        MouseEventKind::ScrollDown => {
            if app.tab == Tab::Logs {
                app.log_viewer.scroll_down();
                app.log_selected_line = app.log_viewer.selected_line();
                app.log_auto_scroll = app.log_viewer.auto_scroll();
            }
            return;
        }
        _ => {}
    }
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
        UserMode::Simple => vec![Tab::Proxy, Tab::Config, Tab::Privacy],
        UserMode::Advanced => vec![
            Tab::Proxy,
            Tab::Config,
            Tab::Monitor,
            Tab::Privacy,
            Tab::PrivacyHeaders,
            Tab::Logs,
        ],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassifierCacheClearResult {
    Removed,
    Missing,
}

fn classifier_cache_path_for(cfg: &EngineConfig) -> PathBuf {
    let configured = cfg.evasion.classifier_cache_path.trim();
    if !configured.is_empty() {
        return expand_tilde(configured);
    }
    if let Some(dir) = dirs::cache_dir() {
        return dir.join("prime-net-engine").join("relay-classifier.json");
    }
    expand_tilde("~/.cache/prime-net-engine/relay-classifier.json")
}

fn build_classifier_cache_clear_prompt(cfg: &EngineConfig) -> ClassifierCacheClearPrompt {
    let path = classifier_cache_path_for(cfg);
    let mut exists = false;
    let mut size_bytes = 0u64;
    let mut modified_unix = None;
    if let Ok(meta) = fs::metadata(&path) {
        exists = true;
        size_bytes = meta.len();
        modified_unix = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
    }
    ClassifierCacheClearPrompt {
        path,
        exists,
        size_bytes,
        modified_unix,
    }
}

fn clear_classifier_cache_file(path: &Path) -> Result<ClassifierCacheClearResult> {
    match fs::remove_file(path) {
        Ok(()) => Ok(ClassifierCacheClearResult::Removed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(ClassifierCacheClearResult::Missing)
        }
        Err(e) => Err(EngineError::Internal(format!(
            "не удалось очистить кэш relay-классификатора {}: {e}",
            path.display()
        ))),
    }
}
