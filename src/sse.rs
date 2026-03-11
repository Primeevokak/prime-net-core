use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::Stream;
use reqwest::Method;
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

fn remove_header(headers: &mut Vec<(String, String)>, name: &str) {
    let name_lc = name.to_ascii_lowercase();
    headers.retain(|(k, _)| k.to_ascii_lowercase() != name_lc);
}

struct EventAcc {
    event: Option<String>,
    data: String,
    id: Option<String>,
    retry: Option<Duration>,
}

const MAX_DATA_SIZE: usize = 8 * 1024 * 1024; // 8MB limit for accumulated event data

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

        // Spec-compliant: dispatch only when event data buffer is non-empty.
        if out.data.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    fn push_data(&mut self, line: &str) -> Result<()> {
        if self.data.len() + line.len() > MAX_DATA_SIZE {
            return Err(EngineError::Internal(
                "sse event data exceeds maximum size".to_owned(),
            ));
        }
        self.data.push_str(line);
        self.data.push('\n');
        Ok(())
    }
}

async fn read_line_sse<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize> {
    use tokio::io::AsyncBufReadExt;
    let mut total_read = 0;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(total_read);
        }

        let mut i = 0;
        while i < available.len() {
            let b = available[i];
            if b == b'\n' {
                reader.consume(i + 1);
                return Ok(total_read + i + 1);
            }
            if b == b'\r' {
                let has_next = i + 1 < available.len();
                if has_next {
                    if available[i + 1] == b'\n' {
                        reader.consume(i + 2);
                        return Ok(total_read + i + 2);
                    } else {
                        reader.consume(i + 1);
                        return Ok(total_read + i + 1);
                    }
                } else {
                    // CR is at the end of the buffer.
                    // To handle \r\n, we consume everything up to CR, push to buf,
                    // and then we must peek one more byte from the stream.
                    reader.consume(i);
                    total_read += i;

                    // Consume the CR now.
                    reader.consume(1);
                    total_read += 1;

                    // Peek if next is LF.
                    let available = reader.fill_buf().await?;
                    if !available.is_empty() && available[0] == b'\n' {
                        reader.consume(1);
                        return Ok(total_read + 1);
                    }
                    return Ok(total_read);
                }
            }
            buf.push(b);
            i += 1;
        }
        reader.consume(i);
        total_read += i;
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
    let mut retry_base = cfg.retry_initial;
    let mut retry_current = cfg.retry_initial;

    loop {
        let mut req = req_template.clone();
        req.method = Method::GET;
        req.body.clear();

        upsert_header(&mut req.headers, "Accept", "text/event-stream".to_owned());
        upsert_header(&mut req.headers, "Cache-Control", "no-cache".to_owned());

        if cfg.send_last_event_id {
            if let Some(id) = last_event_id.as_deref() {
                upsert_header(&mut req.headers, "Last-Event-ID", id.to_owned());
            } else {
                remove_header(&mut req.headers, "Last-Event-ID");
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
                        _ = tokio::time::sleep(retry_current) => {}
                    }
                    retry_current = (retry_current.saturating_mul(2)).min(cfg.retry_max);
                    continue;
                }
            }
        };

        // Best-effort: if the server closes the stream, we'll reconnect.
        let mut reader = tokio::io::BufReader::new(&mut resp.stream);
        let mut acc = EventAcc::new();
        let mut buf: Vec<u8> = Vec::new();
        let mut stream_had_activity = false;

        loop {
            buf.clear();

            // Spec-compliant line reading: handles \n, \r, and \r\n as terminators.
            let n = tokio::select! {
                _ = &mut stop_rx => return,
                r = read_line_sse(&mut reader, &mut buf) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = out.send(Err(EngineError::Io(e))).await;
                        break;
                    }
                }
            };

            if n == 0 {
                if let Some(ev) = acc.take_event() {
                    if out.send(Ok(ev)).await.is_err() {
                        return;
                    }
                }
                break; // EOF
            }
            stream_had_activity = true;

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
                    if let Err(e) = acc.push_data(value) {
                        let _ = out.send(Err(e)).await;
                        return;
                    }
                }
                "retry" => {
                    if let Ok(ms) = value.trim().parse::<u64>() {
                        let retry_value = Duration::from_millis(ms)
                            .max(Duration::from_millis(1))
                            .min(cfg.retry_max);
                        acc.retry = Some(retry_value);
                        retry_base = retry_value;
                        retry_current = retry_value;
                    }
                }
                "id" => {
                    let id = value.to_owned();
                    // Per SSE spec, empty `id:` resets Last-Event-ID even when no event is dispatched.
                    last_event_id = if id.is_empty() {
                        None
                    } else {
                        Some(id.clone())
                    };
                    acc.id = Some(id);
                }
                _ => {}
            }
        }

        if !cfg.reconnect {
            return;
        }

        tokio::select! {
            _ = &mut stop_rx => return,
            _ = tokio::time::sleep(retry_current) => {}
        }
        if stream_had_activity {
            retry_current = retry_base;
        } else {
            retry_current = (retry_current.saturating_mul(2)).min(cfg.retry_max);
        }
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

#[cfg(test)]
mod tests {
    use super::{remove_header, EventAcc};
    use std::time::Duration;

    #[test]
    fn event_acc_does_not_emit_id_only_event() {
        let mut acc = EventAcc::new();
        acc.id = Some("123".to_owned());
        assert!(acc.take_event().is_none());
    }

    #[test]
    fn event_acc_emits_when_data_present() {
        let mut acc = EventAcc::new();
        acc.id = Some("123".to_owned());
        acc.retry = Some(Duration::from_millis(500));
        acc.data.push_str("hello\n");
        let ev = acc.take_event().expect("event");
        assert_eq!(ev.data, "hello");
        assert_eq!(ev.id.as_deref(), Some("123"));
        assert_eq!(ev.retry, Some(Duration::from_millis(500)));
    }

    #[test]
    fn remove_header_is_case_insensitive() {
        let mut headers = vec![
            ("Last-Event-ID".to_owned(), "42".to_owned()),
            ("Accept".to_owned(), "text/event-stream".to_owned()),
        ];
        remove_header(&mut headers, "last-event-id");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Accept");
    }
}
