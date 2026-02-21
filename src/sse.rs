use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::Stream;
use reqwest::Method;
use tokio::io::AsyncBufReadExt;
use tokio::sync::{mpsc, oneshot};

use crate::core::{PrimeHttpClient, RequestData};
use crate::error::{EngineError, Result};

#[derive(Debug, Clone)]
pub struct SseConfig {
    /// Whether to automatically reconnect on EOF / transient errors.
    pub reconnect: bool,
    /// Initial reconnect delay (used if the server does not provide `retry:`).
    pub retry_initial: Duration,
    /// Maximum reconnect delay.
    pub retry_max: Duration,
    /// Whether to send `Last-Event-ID` on reconnect when an `id:` field was observed.
    pub send_last_event_id: bool,
}

impl Default for SseConfig {
    fn default() -> Self {
        Self {
            reconnect: true,
            retry_initial: Duration::from_millis(1_000),
            retry_max: Duration::from_millis(30_000),
            send_last_event_id: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// Optional event name (`event:`).
    pub event: Option<String>,
    /// Event payload (`data:` lines, joined with `\n`).
    pub data: String,
    /// Optional event id (`id:`).
    pub id: Option<String>,
    /// Optional server-provided reconnection delay (`retry:`).
    pub retry: Option<Duration>,
}

#[derive(Debug)]
pub struct SseStream {
    rx: mpsc::Receiver<Result<SseEvent>>,
    stop_tx: Option<oneshot::Sender<()>>,
    _join: tokio::task::JoinHandle<()>,
}

impl Stream for SseStream {
    type Item = Result<SseEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.rx).poll_recv(cx)
    }
}

impl Drop for SseStream {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

fn upsert_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    let name_lc = name.to_ascii_lowercase();
    headers.retain(|(k, _)| k.to_ascii_lowercase() != name_lc);
    headers.push((name.to_owned(), value));
}

struct EventAcc {
    event: Option<String>,
    data: String,
    id: Option<String>,
    retry: Option<Duration>,
}

impl EventAcc {
    fn new() -> Self {
        Self {
            event: None,
            data: String::new(),
            id: None,
            retry: None,
        }
    }

    fn take_event(&mut self) -> Option<SseEvent> {
        let data = if self.data.ends_with('\n') {
            self.data.trim_end_matches('\n').to_owned()
        } else {
            self.data.clone()
        };

        let out = SseEvent {
            event: self.event.take(),
            data,
            id: self.id.take(),
            retry: self.retry.take(),
        };

        // Blank line terminates the event; clear accumulated state unconditionally.
        self.data.clear();

        // Spec: dispatch happens on blank line even if fields are empty, but in practice returning
        // completely empty events is not useful.
        if out.event.is_none() && out.id.is_none() && out.retry.is_none() && out.data.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

async fn run_sse(
    client: Arc<PrimeHttpClient>,
    req_template: RequestData,
    cfg: SseConfig,
    out: mpsc::Sender<Result<SseEvent>>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let mut last_event_id: Option<String> = None;
    let mut retry = cfg.retry_initial;

    loop {
        let mut req = req_template.clone();
        req.method = Method::GET;
        req.body.clear();

        upsert_header(&mut req.headers, "Accept", "text/event-stream".to_owned());
        upsert_header(&mut req.headers, "Cache-Control", "no-cache".to_owned());

        if cfg.send_last_event_id {
            if let Some(id) = last_event_id.as_deref() {
                upsert_header(&mut req.headers, "Last-Event-ID", id.to_owned());
            }
        }

        let mut resp = tokio::select! {
            _ = &mut stop_rx => return,
            r = client.fetch_stream(req) => match r {
                Ok(v) => v,
                Err(e) => {
                    let _ = out.send(Err(e)).await;
                    if !cfg.reconnect {
                        return;
                    }
                    tokio::select! {
                        _ = &mut stop_rx => return,
                        _ = tokio::time::sleep(retry) => {}
                    }
                    retry = (retry.saturating_mul(2)).min(cfg.retry_max);
                    continue;
                }
            }
        };

        // Best-effort: if the server closes the stream, we'll reconnect.
        let mut reader = tokio::io::BufReader::new(&mut resp.stream);
        let mut acc = EventAcc::new();
        let mut buf: Vec<u8> = Vec::new();

        loop {
            buf.clear();
            let n = tokio::select! {
                _ = &mut stop_rx => return,
                r = reader.read_until(b'\n', &mut buf) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = out.send(Err(EngineError::Io(e))).await;
                        break;
                    }
                }
            };
            if n == 0 {
                break; // EOF
            }

            // Trim trailing LF/CRLF.
            while matches!(buf.last(), Some(b'\n' | b'\r')) {
                buf.pop();
            }

            let line = match std::str::from_utf8(&buf) {
                Ok(v) => v,
                Err(e) => {
                    let _ = out
                        .send(Err(EngineError::Internal(format!(
                            "sse utf-8 decode failed: {e}"
                        ))))
                        .await;
                    continue;
                }
            };

            if line.is_empty() {
                if let Some(ev) = acc.take_event() {
                    if let Some(id) = ev.id.as_deref() {
                        // If `id:` is present with an empty value, it resets the last event id.
                        last_event_id = if id.is_empty() {
                            None
                        } else {
                            Some(id.to_owned())
                        };
                    }
                    if let Some(r) = ev.retry {
                        retry = r.max(Duration::from_millis(1)).min(cfg.retry_max);
                    }
                    if out.send(Ok(ev)).await.is_err() {
                        return;
                    }
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix(':') {
                let _ = rest; // comment/keep-alive
                continue;
            }

            let (field, value) = match line.split_once(':') {
                Some((f, v)) => (f.trim(), v.strip_prefix(' ').unwrap_or(v)),
                None => (line.trim(), ""),
            };

            match field {
                "event" => acc.event = Some(value.to_owned()),
                "data" => {
                    acc.data.push_str(value);
                    acc.data.push('\n');
                }
                "id" => acc.id = Some(value.to_owned()),
                "retry" => {
                    if let Ok(ms) = value.trim().parse::<u64>() {
                        acc.retry = Some(Duration::from_millis(ms));
                    }
                }
                _ => {}
            }
        }

        if !cfg.reconnect {
            return;
        }

        tokio::select! {
            _ = &mut stop_rx => return,
            _ = tokio::time::sleep(retry) => {}
        }
        retry = (retry.saturating_mul(2)).min(cfg.retry_max);
    }
}

impl PrimeHttpClient {
    /// Connects to an SSE endpoint and returns a high-level event stream with automatic reconnects.
    ///
    /// This method requires an `Arc<PrimeHttpClient>` so the internal worker task can own the client.
    pub fn sse_connect(self: Arc<Self>, request: RequestData, cfg: SseConfig) -> Result<SseStream> {
        if request.url.trim().is_empty() {
            return Err(EngineError::InvalidInput("sse url is empty".to_owned()));
        }
        if request.method != Method::GET {
            return Err(EngineError::InvalidInput(
                "sse_connect requires a GET request".to_owned(),
            ));
        }
        if !request.body.is_empty() {
            return Err(EngineError::InvalidInput(
                "sse_connect does not support request bodies".to_owned(),
            ));
        }

        let (tx, rx) = mpsc::channel::<Result<SseEvent>>(128);
        let (stop_tx, stop_rx) = oneshot::channel::<()>();

        let join = tokio::spawn(run_sse(self, request, cfg, tx, stop_rx));
        Ok(SseStream {
            rx,
            stop_tx: Some(stop_tx),
            _join: join,
        })
    }
}
