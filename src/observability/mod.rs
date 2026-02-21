use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{EngineError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn from_str(v: &str) -> Self {
        match v.trim().to_ascii_lowercase().as_str() {
            "error" => Self::Error,
            "warn" | "warning" => Self::Warn,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => Self::Info,
        }
    }

    fn allows(&self, other: tracing::Level) -> bool {
        other
            <= match self {
                Self::Error => tracing::Level::ERROR,
                Self::Warn => tracing::Level::WARN,
                Self::Info => tracing::Level::INFO,
                Self::Debug => tracing::Level::DEBUG,
                Self::Trace => tracing::Level::TRACE,
            }
    }
}

#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// "info", "debug", ...
    pub level: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

pub struct ObservabilityGuard {
    _private: (),
}

pub fn init_observability(cfg: ObservabilityConfig) -> Result<ObservabilityGuard> {
    if !cfg!(feature = "observability") {
        return Err(EngineError::Internal(
            "observability is not enabled in this build (enable feature \"observability\")"
                .to_owned(),
        ));
    }

    let level = LogLevel::from_str(&cfg.level);
    let subscriber = SimpleSubscriber::new(level);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| EngineError::Internal(format!("tracing init failed: {e}")))?;
    Ok(ObservabilityGuard { _private: () })
}

#[derive(Debug)]
struct SimpleSubscriber {
    level: LogLevel,
    next_id: AtomicU64,
}

impl SimpleSubscriber {
    fn new(level: LogLevel) -> Self {
        Self {
            level,
            next_id: AtomicU64::new(1),
        }
    }
}

impl tracing::Subscriber for SimpleSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        self.level.allows(*metadata.level())
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if !self.level.allows(*event.metadata().level()) {
            return;
        }

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        // Minimal, grep-friendly format.
        // Example: "INFO prime_net_engine::core::http_client url=... status=200"
        eprintln!(
            "{:<5} {} {}",
            event.metadata().level().as_str(),
            event.metadata().target(),
            visitor.finish()
        );
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[derive(Default)]
struct FieldVisitor {
    parts: Vec<String>,
}

impl FieldVisitor {
    fn finish(self) -> String {
        if self.parts.is_empty() {
            String::new()
        } else {
            self.parts.join(" ")
        }
    }
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.parts.push(format!("{}={:?}", field.name(), value));
    }
}

#[cfg(feature = "observability")]
pub mod prometheus {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use once_cell::sync::Lazy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn format_f64(v: f64) -> String {
        // Prometheus text format expects plain number; keep it stable.
        if v.is_finite() {
            format!("{v}")
        } else {
            "0".to_owned()
        }
    }

    #[derive(Debug)]
    pub struct Counter {
        v: AtomicU64,
    }

    impl Counter {
        pub const fn new() -> Self {
            Self {
                v: AtomicU64::new(0),
            }
        }

        pub fn inc(&self) {
            self.v.fetch_add(1, Ordering::Relaxed);
        }

        pub fn get(&self) -> u64 {
            self.v.load(Ordering::Relaxed)
        }
    }

    impl Default for Counter {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Debug)]
    pub struct Histogram {
        // buckets are cumulative.
        buckets: &'static [f64],
        bucket_counts: Vec<AtomicU64>,
        sum_micros: AtomicU64,
        count: AtomicU64,
    }

    impl Histogram {
        pub fn new(buckets: &'static [f64]) -> Self {
            Self {
                buckets,
                bucket_counts: (0..buckets.len()).map(|_| AtomicU64::new(0)).collect(),
                sum_micros: AtomicU64::new(0),
                count: AtomicU64::new(0),
            }
        }

        pub fn observe(&self, seconds: f64) {
            let micros = (seconds.max(0.0) * 1_000_000.0) as u64;
            self.sum_micros.fetch_add(micros, Ordering::Relaxed);
            self.count.fetch_add(1, Ordering::Relaxed);

            for (idx, le) in self.buckets.iter().copied().enumerate() {
                if seconds <= le {
                    self.bucket_counts[idx].fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        pub fn render(&self, name: &str, labels: &[(&str, &str)]) -> String {
            let mut out = String::new();
            out.push_str(&format!("# TYPE {name} histogram\n"));

            // Buckets: cumulative.
            let mut cumulative = 0_u64;
            for (idx, le) in self.buckets.iter().copied().enumerate() {
                cumulative += self.bucket_counts[idx].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "{name}_bucket{} {cumulative}\n",
                    render_labels(labels, Some(le))
                ));
            }

            // +Inf bucket equals count.
            let count = self.count.load(Ordering::Relaxed);
            out.push_str(&format!(
                "{name}_bucket{} {count}\n",
                render_labels(labels, None)
            ));

            let sum = self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            out.push_str(&format!(
                "{name}_sum{} {}\n",
                render_labels_no_le(labels),
                format_f64(sum)
            ));
            out.push_str(&format!(
                "{name}_count{} {count}\n",
                render_labels_no_le(labels),
            ));

            out
        }
    }

    fn render_labels_no_le(labels: &[(&str, &str)]) -> String {
        if labels.is_empty() {
            String::new()
        } else {
            let mut out = String::from("{");
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(k);
                out.push_str("=\"");
                out.push_str(v);
                out.push('"');
            }
            out.push('}');
            out
        }
    }

    fn render_labels(labels: &[(&str, &str)], le: Option<f64>) -> String {
        // labels + `le="..."` (required for histogram buckets)
        let mut out = String::from("{");
        for (i, (k, v)) in labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(v);
            out.push('"');
        }
        if !labels.is_empty() {
            out.push(',');
        }
        out.push_str("le=\"");
        if let Some(v) = le {
            let le_s = format_f64(v);
            out.push_str(&le_s);
        } else {
            out.push_str("+Inf");
        }
        out.push_str("\"}");
        out
    }

    static BUCKETS: &[f64] = &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

    pub static HTTP_REQUESTS_OK: Lazy<Counter> = Lazy::new(Counter::new);
    pub static HTTP_REQUESTS_ERROR: Lazy<Counter> = Lazy::new(Counter::new);
    pub static HTTP_REQUEST_DURATION_OK: Lazy<Histogram> = Lazy::new(|| Histogram::new(BUCKETS));
    pub static HTTP_REQUEST_DURATION_ERROR: Lazy<Histogram> = Lazy::new(|| Histogram::new(BUCKETS));

    pub fn gather_text() -> String {
        let mut out = String::new();

        out.push_str("# TYPE prime_http_requests_total counter\n");
        out.push_str(&format!(
            "prime_http_requests_total{{result=\"ok\"}} {}\n",
            HTTP_REQUESTS_OK.get()
        ));
        out.push_str(&format!(
            "prime_http_requests_total{{result=\"error\"}} {}\n",
            HTTP_REQUESTS_ERROR.get()
        ));

        out.push_str(
            &HTTP_REQUEST_DURATION_OK
                .render("prime_http_request_duration_seconds", &[("result", "ok")]),
        );
        out.push_str(&HTTP_REQUEST_DURATION_ERROR.render(
            "prime_http_request_duration_seconds",
            &[("result", "error")],
        ));

        out
    }

    /// Minimal Prometheus scrape endpoint: serves `GET /metrics` over plain HTTP.
    pub async fn serve_metrics(addr: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (mut socket, _) = listener.accept().await?;
            tokio::spawn(async move {
                let mut buf = [0_u8; 2048];
                let _ = socket.read(&mut buf).await;
                let body = gather_text();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    }
}
