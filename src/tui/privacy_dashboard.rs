use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::config::{EngineConfig, RefererMode};
use crate::privacy::{privacy_level, privacy_stats_snapshot, PrivacyLevel};
use crate::tui::log_viewer::format_timestamp;

pub struct PrivacyDashboard;

impl PrivacyDashboard {
    pub fn new() -> Self {
        Self
    }

    pub fn render(&self, frame: &mut ratatui::Frame, area: Rect, cfg: &EngineConfig) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Min(8),
                Constraint::Length(3),
            ])
            .split(area);

        let stats = privacy_stats_snapshot(20);
        let level = privacy_level(&cfg.privacy);
        let (level_label, level_style) = match level {
            PrivacyLevel::Low => ("НИЗКИЙ", Style::default().fg(Color::Gray)),
            PrivacyLevel::Medium => ("СРЕДНИЙ", Style::default().fg(Color::Yellow)),
            PrivacyLevel::High => ("ВЫСОКИЙ", Style::default().fg(Color::Green)),
        };

        let summary = Paragraph::new(vec![
            Line::from(vec![
                Span::raw("Уровень приватности: "),
                Span::styled(level_label, level_style.add_modifier(Modifier::BOLD)),
            ]),
            Line::from(format!(
                "Заблокировано трекеров (сессия): {}",
                stats.session_blocked
            )),
            Line::from(format!(
                "Заблокировано трекеров (всего): {}",
                stats.total_blocked
            )),
        ])
        .block(
            Block::default()
                .title("Сводка приватности")
                .borders(Borders::ALL),
        );
        frame.render_widget(summary, chunks[0]);

        let status = Paragraph::new(vec![
            Line::from(format!(
                "Блокировщик трекеров: {} ({:?}, {:?})",
                on_off(cfg.privacy.tracker_blocker.enabled),
                cfg.privacy.tracker_blocker.mode,
                cfg.privacy.tracker_blocker.on_block
            )),
            Line::from(format!(
                "Referer: {} ({:?})",
                on_off(cfg.privacy.referer.enabled),
                cfg.privacy.referer.mode
            )),
            Line::from(format!(
                "Сигналы: DNT={}  GPC={}",
                on_off(cfg.privacy.signals.send_dnt),
                on_off(cfg.privacy.signals.send_gpc)
            )),
        ])
        .block(
            Block::default()
                .title("Управление приватностью")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(status, chunks[1]);

        let items = stats
            .recent_blocked
            .iter()
            .map(|entry| {
                let ts = format_timestamp(entry.at);
                ListItem::new(Line::from(format!("{ts}  {}", entry.domain)))
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            List::new(items).block(
                Block::default()
                    .title("Недавно заблокированные домены")
                    .borders(Borders::ALL),
            ),
            chunks[2],
        );

        frame.render_widget(
            Paragraph::new("[v] смена режима referer  [b] блокировщик  [n] DNT  [g] GPC")
                .block(Block::default().borders(Borders::ALL)),
            chunks[3],
        );
    }
}

impl Default for PrivacyDashboard {
    fn default() -> Self {
        Self::new()
    }
}

/// Cycle through referer modes in order: disabled → Strip → OriginOnly → PassThrough → disabled.
pub fn cycle_referer_mode(cfg: &mut EngineConfig) {
    if cfg.privacy.referer.enabled {
        match cfg.privacy.referer.mode {
            RefererMode::Strip => cfg.privacy.referer.mode = RefererMode::OriginOnly,
            RefererMode::OriginOnly => cfg.privacy.referer.mode = RefererMode::PassThrough,
            RefererMode::PassThrough => cfg.privacy.referer.enabled = false,
        }
    } else {
        cfg.privacy.referer.enabled = true;
        cfg.privacy.referer.mode = RefererMode::Strip;
    }
}

fn on_off(v: bool) -> &'static str {
    if v {
        "вкл"
    } else {
        "выкл"
    }
}
