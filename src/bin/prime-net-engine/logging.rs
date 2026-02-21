use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde_json::{json, Map, Value};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogRotation {
    Never,
    Daily,
    Hourly,
    Minutely,
}

#[derive(Debug, Clone)]
pub struct LoggingOpts {
    pub level: Level,
    pub format: LogFormat,
    pub file: Option<PathBuf>,
    pub rotation: LogRotation,
}

pub fn init_logging(opts: LoggingOpts) -> io::Result<()> {
    let sub = SimpleSubscriber::new(opts)?;
    tracing::subscriber::set_global_default(sub)
        .map_err(|_| io::Error::other("failed to set global tracing subscriber"))?;
    Ok(())
}

struct SimpleSubscriber {
    level: Level,
    format: LogFormat,
    writer: Mutex<RotatingWriter>,
    next_id: AtomicU64,
}

impl SimpleSubscriber {
    fn new(opts: LoggingOpts) -> io::Result<Self> {
        Ok(Self {
            level: opts.level,
            format: opts.format,
            writer: Mutex::new(RotatingWriter::new(opts.file, opts.rotation)?),
            next_id: AtomicU64::new(1),
        })
    }
}

impl Subscriber for SimpleSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        level_rank(*metadata.level()) <= level_rank(self.level)
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        Id::from_u64(id)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);

        let meta = event.metadata();
        let ts = unix_timestamp_secs();
        let ts_utc = format_ts_rfc3339_utc(ts as i64);

        let line = match self.format {
            LogFormat::Json => {
                let mut obj = Map::<String, Value>::new();
                obj.insert("ts_unix".to_owned(), json!(ts));
                obj.insert("ts_utc".to_owned(), json!(ts_utc));
                obj.insert("level".to_owned(), json!(meta.level().as_str()));
                obj.insert("target".to_owned(), json!(meta.target()));
                if let Some(module) = meta.module_path() {
                    obj.insert("module".to_owned(), json!(module));
                }
                if let Some(file) = meta.file() {
                    obj.insert("file".to_owned(), json!(file));
                }
                if let Some(line) = meta.line() {
                    obj.insert("line".to_owned(), json!(line));
                }
                for (k, v) in visitor.fields {
                    obj.insert(k, v);
                }
                Value::Object(obj).to_string()
            }
            LogFormat::Text => {
                let mut buf = String::new();
                buf.push_str(&format!(
                    "{ts} {} {} ",
                    meta.level().as_str(),
                    meta.target()
                ));
                if let Some(msg) = visitor.message {
                    buf.push_str(&msg);
                }
                if !visitor.kv.is_empty() {
                    for (k, v) in visitor.kv {
                        buf.push_str(&format!(" {k}={v}"));
                    }
                }
                buf
            }
        };

        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_line(&line);
        }
    }

    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

fn level_rank(l: Level) -> u8 {
    match l {
        Level::ERROR => 1,
        Level::WARN => 2,
        Level::INFO => 3,
        Level::DEBUG => 4,
        Level::TRACE => 5,
    }
}

#[derive(Default)]
struct JsonVisitor {
    fields: Map<String, Value>,
    message: Option<String>,
    kv: Vec<(String, String)>,
}

impl Visit for JsonVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field.name(), json!(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field.name(), json!(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field.name(), json!(value));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field.name(), json!(value));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.insert(field.name(), json!(format!("{value:?}")));
    }
}

impl JsonVisitor {
    fn insert(&mut self, name: &str, v: Value) {
        if name == "message" {
            self.message = v
                .as_str()
                .map(|s| s.to_owned())
                .or_else(|| Some(v.to_string()));
        } else {
            // Keep a separate key=value vector for the text formatter.
            self.kv.push((name.to_owned(), v.to_string()));
        }
        self.fields.insert(name.to_owned(), v);
    }
}

struct RotatingWriter {
    file: Option<File>,
    file_path: Option<PathBuf>,
    rotation: LogRotation,
    current_suffix: Option<String>,
}

impl RotatingWriter {
    fn new(file: Option<PathBuf>, rotation: LogRotation) -> io::Result<Self> {
        let mut w = Self {
            file: None,
            file_path: file,
            rotation,
            current_suffix: None,
        };
        w.rotate_if_needed()?;
        Ok(w)
    }

    fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.rotate_if_needed()?;

        // Always log to stderr (operational default). File logging is optional.
        let mut stderr = io::stderr();
        let _ = writeln!(stderr, "{line}");

        if let Some(f) = &mut self.file {
            writeln!(f, "{line}")?;
            f.flush()?;
        }
        Ok(())
    }

    fn rotate_if_needed(&mut self) -> io::Result<()> {
        let Some(base_path) = &self.file_path else {
            return Ok(());
        };

        let suffix = match self.rotation {
            LogRotation::Never => None,
            LogRotation::Daily => Some(format_ts_suffix(TsSuffix::Daily)),
            LogRotation::Hourly => Some(format_ts_suffix(TsSuffix::Hourly)),
            LogRotation::Minutely => Some(format_ts_suffix(TsSuffix::Minutely)),
        };

        if suffix == self.current_suffix && self.file.is_some() {
            return Ok(());
        }

        let path = match &suffix {
            None => base_path.clone(),
            Some(sfx) => {
                let dir = base_path.parent().unwrap_or_else(|| Path::new("."));
                let name = base_path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("prime-net-engine.log");
                dir.join(format!("{name}.{sfx}"))
            }
        };

        let f = OpenOptions::new().create(true).append(true).open(path)?;
        self.file = Some(f);
        self.current_suffix = suffix;
        Ok(())
    }
}

fn unix_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

enum TsSuffix {
    Daily,
    Hourly,
    Minutely,
}

fn format_ts_suffix(kind: TsSuffix) -> String {
    // UTC timestamp to YYYY-MM-DD[-HH[-MM]] without external deps.
    let secs = unix_timestamp_secs() as i64;
    let (y, m, d, hh, mm) = unix_secs_to_ymdhm(secs);
    match kind {
        TsSuffix::Daily => format!("{y:04}-{m:02}-{d:02}"),
        TsSuffix::Hourly => format!("{y:04}-{m:02}-{d:02}-{hh:02}"),
        TsSuffix::Minutely => format!("{y:04}-{m:02}-{d:02}-{hh:02}-{mm:02}"),
    }
}

fn unix_secs_to_ymdhm(secs: i64) -> (i32, u32, u32, u32, u32) {
    let secs = secs.max(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hh = (rem / 3600) as u32;
    let mm = ((rem % 3600) / 60) as u32;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, hh, mm)
}

fn format_ts_rfc3339_utc(secs: i64) -> String {
    let secs = secs.max(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hh = (rem / 3600) as u32;
    let mm = ((rem % 3600) / 60) as u32;
    let ss = (rem % 60) as u32;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

// Howard Hinnant's algorithm: https://howardhinnant.github.io/date_algorithms.html
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let mut y = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (mp + if mp < 10 { 3 } else { -9 }) as i32; // [1, 12]
    y += (m <= 2) as i32;
    (y, m as u32, d)
}
