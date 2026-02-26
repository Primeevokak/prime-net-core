use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::mpsc;
use tracing_subscriber::Layer;

use crate::tui::log_viewer::{LogEntry, LogViewer};

pub struct TuiLayer {
    pub log_viewer: Arc<LogViewer>,
    tx: mpsc::UnboundedSender<LogEntry>,
}

impl TuiLayer {
    pub fn new(log_viewer: Arc<LogViewer>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<LogEntry>();
        let sink = log_viewer.clone();
        let _ = std::thread::Builder::new()
            .name("prime-tui-log-drain".to_owned())
            .spawn(move || {
                while let Some(entry) = rx.blocking_recv() {
                    sink.add_log(entry);
                }
            });

        Self { log_viewer, tx }
    }
}

impl<S> Layer<S> for TuiLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);
        let message = if visitor.message.is_empty() {
            event.metadata().name().to_owned()
        } else {
            visitor.message
        };
        let entry = LogEntry {
            timestamp: SystemTime::now(),
            level: *event.metadata().level(),
            message,
            target: event.metadata().target().to_owned(),
            count: 1,
        };
        if let Err(err) = self.tx.send(entry) {
            self.log_viewer.add_log(err.0);
        }
    }
}

#[derive(Default)]
struct LogVisitor {
    message: String,
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}").trim_matches('"').to_owned();
        }
    }
}
