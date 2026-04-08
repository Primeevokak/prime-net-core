use std::collections::BTreeMap;

use ratatui::prelude::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use tokio::sync::broadcast;

use crate::telemetry::connection_tracker::{
    global_connection_tracker, ConnectionInfo, ConnectionStatus, ConnectionTracker,
};

pub struct ConnectionMonitor {
    tracker: ConnectionTracker,
    rx: broadcast::Receiver<ConnectionInfo>,
    connections: BTreeMap<u64, ConnectionInfo>,
    pub selected_id: Option<u64>,
    table_state: TableState,
}

impl ConnectionMonitor {
    pub fn new() -> Self {
        let tracker = global_connection_tracker();
        let rx = tracker.subscribe();
        Self {
            tracker,
            rx,
            connections: BTreeMap::new(),
            selected_id: None,
            table_state: TableState::default(),
        }
    }

    pub fn tick(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(info) => {
                    self.connections.insert(info.id, info);
                    while self.connections.len() > 500 {
                        if let Some(first) = self.connections.keys().next().copied() {
                            self.connections.remove(&first);
                        } else {
                            break;
                        }
                    }
                }
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    self.refresh();
                    break;
                }
                Err(broadcast::error::TryRecvError::Closed) => break,
            }
        }
        if self.selected_id.is_none() {
            self.selected_id = self.connections.keys().next().copied();
        } else if let Some(selected) = self.selected_id {
            if !self.connections.contains_key(&selected) {
                self.selected_id = self.connections.keys().next().copied();
            }
        }
        // Keep TableState index in sync with selected_id.
        let ids: Vec<u64> = self.connections.keys().copied().collect();
        let idx = self
            .selected_id
            .and_then(|id| ids.iter().position(|x| *x == id));
        self.table_state.select(idx);
    }

    pub fn select_next(&mut self) {
        let ids: Vec<u64> = self.connections.keys().copied().collect();
        if ids.is_empty() {
            self.selected_id = None;
            self.table_state.select(None);
            return;
        }
        let next = match self.selected_id {
            Some(id) => ids
                .iter()
                .position(|x| *x == id)
                .map(|i| (i + 1).min(ids.len().saturating_sub(1)))
                .unwrap_or(0),
            None => 0,
        };
        self.selected_id = ids.get(next).copied();
        self.table_state.select(Some(next));
    }

    pub fn select_prev(&mut self) {
        let ids: Vec<u64> = self.connections.keys().copied().collect();
        if ids.is_empty() {
            self.selected_id = None;
            self.table_state.select(None);
            return;
        }
        let prev = match self.selected_id {
            Some(id) => ids
                .iter()
                .position(|x| *x == id)
                .map(|i| i.saturating_sub(1))
                .unwrap_or(0),
            None => 0,
        };
        self.selected_id = ids.get(prev).copied();
        self.table_state.select(Some(prev));
    }

    pub fn selected(&self) -> Option<&ConnectionInfo> {
        self.selected_id.and_then(|id| self.connections.get(&id))
    }

    pub fn render(&mut self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(7),
                Constraint::Min(8),
                Constraint::Length(8),
            ])
            .split(area);

        let mut rows = Vec::new();
        let mut active = 0usize;
        let mut completed = 0usize;
        let mut failed = 0usize;
        let all: Vec<_> = self.connections.values().collect();
        for conn in &all {
            match conn.status {
                ConnectionStatus::Completed => completed += 1,
                ConnectionStatus::Failed => failed += 1,
                _ => active += 1,
            }

            let privacy = if conn.blocked_by_privacy {
                "БЛОК"
            } else if conn.privacy_filtered {
                "ФИЛЬТР"
            } else {
                "-"
            };
            let row_style = if conn.blocked_by_privacy {
                Style::default().fg(Color::Red)
            } else if conn.privacy_filtered {
                Style::default().fg(Color::Gray)
            } else {
                Style::default()
            };

            rows.push(
                Row::new(vec![
                    Cell::from(format!("#{}", conn.id)),
                    Cell::from(trim_host(&conn.url)),
                    Cell::from(status_label(conn.status)),
                    Cell::from(privacy),
                    Cell::from(format_speed(conn.download_info.speed_bytes_per_sec)),
                    Cell::from(progress_bar(
                        conn.download_info.bytes_downloaded,
                        conn.download_info.total_bytes,
                    )),
                ])
                .style(row_style),
            );
        }

        let table = Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Percentage(34),
                Constraint::Length(11),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(12),
            ],
        )
        .header(
            Row::new([
                "ID",
                "Хост",
                "Статус",
                "Приватность",
                "Скорость",
                "Прогресс",
            ])
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .title(format!(
                    "Монитор соединений  Активно:{} Завершено:{} Ошибок:{} Всего:{}",
                    active,
                    completed,
                    failed,
                    all.len()
                ))
                .borders(Borders::ALL),
        );
        frame.render_stateful_widget(table, chunks[0], &mut self.table_state);

        let summary = self
            .selected()
            .map(format_detail)
            .unwrap_or_else(|| "Соединение не выбрано".to_owned());
        frame.render_widget(
            Paragraph::new(summary)
                .block(Block::default().title("Выбранное").borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            chunks[1],
        );
        let footer = Paragraph::new("[Up/Down] Выбор  [r] Обновить")
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, chunks[2]);
    }

    pub fn refresh(&mut self) {
        self.connections = self
            .tracker
            .connections
            .read()
            .iter()
            .map(|(id, conn)| (*id, conn.clone()))
            .collect();
        while self.connections.len() > 500 {
            if let Some(first) = self.connections.keys().next().copied() {
                self.connections.remove(&first);
            } else {
                break;
            }
        }
        if let Some(selected) = self.selected_id {
            if !self.connections.contains_key(&selected) {
                self.selected_id = self.connections.keys().next().copied();
            }
        } else {
            self.selected_id = self.connections.keys().next().copied();
        }
    }
}

impl Default for ConnectionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

fn trim_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|v| v.to_owned()))
        .unwrap_or_else(|| url.to_owned())
}

fn status_label(status: ConnectionStatus) -> &'static str {
    match status {
        ConnectionStatus::Queued => "В очереди",
        ConnectionStatus::Resolving => "DNS",
        ConnectionStatus::Connecting => "Подключение",
        ConnectionStatus::TlsHandshake => "TLS-HS",
        ConnectionStatus::Sending => "Отправка",
        ConnectionStatus::Receiving => "Прием",
        ConnectionStatus::Completed => "Готово",
        ConnectionStatus::Failed => "Ошибка",
    }
}

fn format_speed(speed: f64) -> String {
    format!("{:.1}КБ/с", speed / 1024.0)
}

fn progress_bar(done: u64, total: Option<u64>) -> String {
    let Some(total) = total else {
        return "[????]".to_owned();
    };
    if total == 0 {
        return "[----]".to_owned();
    }
    let ratio = (done as f64 / total as f64).clamp(0.0, 1.0);
    let ticks = (ratio * 8.0).round() as usize;
    let filled = "=".repeat(ticks);
    let empty = " ".repeat(8usize.saturating_sub(ticks));
    format!("[{}{}]", filled, empty)
}

fn format_detail(conn: &ConnectionInfo) -> String {
    let dns = conn
        .dns_info
        .as_ref()
        .map(|d| {
            format!(
                "DNS: {} {} ({}ms) {}",
                d.resolver_used,
                d.resolved_ip,
                d.resolution_time_ms,
                d.chain.join(" -> ")
            )
        })
        .unwrap_or_else(|| "DNS: н/д".to_owned());
    let tls = conn
        .tls_info
        .as_ref()
        .map(|t| {
            format!(
                "TLS: {}, {}, ECH {}, {}ms",
                t.version, t.cipher_suite, t.ech_status, t.handshake_time_ms
            )
        })
        .unwrap_or_else(|| "TLS: н/д".to_owned());
    let err = conn
        .error
        .as_ref()
        .map(|e| format!("Ошибка: {e}"))
        .unwrap_or_default();
    format!(
        "ID #{} {}\nПриватность: отфильтровано={} блокировано={}\n{}\n{}\nСкачано: {} байт\n{}",
        conn.id,
        conn.url,
        conn.privacy_filtered,
        conn.blocked_by_privacy,
        dns,
        tls,
        conn.download_info.bytes_downloaded,
        err
    )
}
