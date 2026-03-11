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
    } else if let Some(confirm) = &app.packet_bypass_unsafe_confirm_prompt {
        let popup = centered_rect(90, 70, area);
        let source = confirm.source_url.as_deref().unwrap_or("н/д");
        let remaining = 10u64.saturating_sub(confirm.started_at.elapsed().as_secs());
        let confirm_hint = if remaining == 0 {
            "[y]/[Enter] Да, я понимаю риск"
        } else {
            "Ожидайте завершения таймера перед подтверждением"
        };
        let text = format!(
            "Режим запуска без проверки SHA256\n\n\
Источник: {source}\n\
До разблокировки подтверждения: {remaining} с\n\n\
Риски:\n\
  - может быть запущен подменённый бинарный файл\n\
  - возможны кража данных и перехват трафика\n\
  - вы обходите защиту целостности загрузки\n\n\
Действия:\n\
  {confirm_hint}\n\
  [n]/[Esc] Нет, я передумал"
        );
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(text).block(
                Block::default()
                    .title("Подтверждение риск-режима")
                    .borders(Borders::ALL),
            ),
            popup,
        );
    } else if let Some(prompt) = &app.packet_bypass_bootstrap_prompt {
        let popup = centered_rect(90, 70, area);
        let source = prompt.source_url.as_deref().unwrap_or("н/д");
        let text = format!(
            "Packet bypass не удалось запустить в безопасном режиме.\n\n\
Причина: не найден SHA256 sidecar для скачанного пакета.\n\
Источник: {source}\n\n\
Что можно сделать:\n\
  [r]/[Enter] Повторить безопасный запуск (рекомендуется)\n\
  [u] Запустить без проверки целостности (небезопасно)\n\
  [n]/[Esc] Оставить direct-режим\n\n\
Режим без проверки включается только вручную и только на один запуск."
        );
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(text)
                .block(Block::default().title("Проблема запуска bypass").borders(Borders::ALL)),
            popup,
        );
    } else if let Some(prompt) = &app.classifier_cache_clear_prompt {
        let popup = centered_rect(85, 70, area);
        let modified_label = prompt
            .modified_unix
            .map(|ts| ts.to_string())
            .unwrap_or_else(|| "н/д".to_owned());
        let exists_label = if prompt.exists { "да" } else { "нет" };
        let text = format!(
            "Очистить кэш relay-классификатора?\n\n\
Путь: {}\n\
Файл существует: {exists_label}\n\
Размер: {} байт\n\
Изменён (unix): {modified_label}\n\n\
Плюсы:\n\
  + удаляются устаревшие обученные решения маршрутизации\n\
  + проще исправлять некорректные состояния adaptive-маршрутов\n\
  + следующие сессии обучаются на актуальных условиях сети\n\n\
Минусы:\n\
  - первые запросы могут быть медленнее (холодный старт обучения)\n\
  - временно могут участиться route race/fallback\n\
  - будет потеряна история удачных обученных профилей\n\n\
Нажмите [y]/[Enter] для подтверждения, [n]/[Esc] для отмены.",
            prompt.path.display(),
            prompt.size_bytes
        );
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(text)
                .block(Block::default().title("Подтверждение очистки кэша").borders(Borders::ALL)),
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
            (Tab::Proxy, "1 Прокси"),
            (Tab::Config, "2 Конфиг"),
            (Tab::Privacy, "3 Приватность"),
        ],
        UserMode::Advanced => vec![
            (Tab::Proxy, "1 Прокси"),
            (Tab::Config, "2 Конфиг"),
            (Tab::Monitor, "3 Монитор"),
            (Tab::Privacy, "4 Приватность"),
            (Tab::PrivacyHeaders, "5 Заголовки приватности"),
            (Tab::Logs, "6 Логи"),
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
    let mode_label = match app.network_mode {
        NetworkMode::Proxy => "ПРОКСИ (SOCKS5)",
        NetworkMode::Vpn   => "VPN (TUN — весь трафик)",
    };
    lines.push(Line::from(format!("Режим сети: {mode_label}")));
    lines.push(Line::from(
        "[a] включить прокси  [x] выключить  [v] переключить VPN/Прокси  [u] диагностика",
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(
        "[d] очистить кэш relay-классификатора (с подтверждением)",
    ));
    lines.push(Line::from(""));
    lines.push(Line::from("─── VPN / TUN режим ───"));
    lines.push(Line::from(
        "Маршрутизирует весь IP-трафик через движок. [v] — запустить / остановить.",
    ));
    lines.push(Line::from("  На Linux/macOS требуется root или CAP_NET_ADMIN."));
    lines.push(Line::from("  На Windows — Administrator (wintun.dll скачивается автоматически)."));
    lines.push(Line::from(""));
    lines.push(Line::from("Ссылки автора:"));
    lines.push(Line::from(format!(
        "  [Enter] Открыть Telegram-канал: {}",
        AUTHOR_TELEGRAM_URL
    )));

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title("Прокси и управление")
                .borders(Borders::ALL),
        ),
        area,
    );
}
