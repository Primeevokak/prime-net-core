use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rand::RngCore;
use reqwest::header::{HeaderValue, HOST};
use url::Url;

use crate::anticensorship::{DomainFrontingProxy, PrimeReqwestDnsResolver, ResolverChain};
use crate::config::{DomainFrontingRule, EngineConfig};
use crate::core::RequestData;
use crate::error::{EngineError, Result};

#[cfg(feature = "websocket")]
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}

#[cfg(feature = "websocket")]
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite {}

#[cfg(feature = "websocket")]
type DynStream = Box<dyn AsyncReadWrite + Unpin + Send>;

#[derive(Debug, Clone)]
pub struct WsConfig {
    pub headers: Vec<(String, String)>,
    pub ping_interval: Option<Duration>,
    pub max_reconnect_attempts: usize,
    pub reconnect_backoff: Duration,
    pub outbound_queue: usize,
    pub inbound_queue: usize,
    pub permessage_deflate: bool,
    pub max_message_size: usize,
    /// Optional engine configuration for proxying and DPI bypass.
    pub engine_config: Option<EngineConfig>,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            ping_interval: Some(Duration::from_secs(30)),
            max_reconnect_attempts: 3,
            reconnect_backoff: Duration::from_secs(2),
            outbound_queue: 256,
            inbound_queue: 256,
            permessage_deflate: true,
            max_message_size: 8 * 1024 * 1024,
            engine_config: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<WsCloseFrame>),
}

#[derive(Debug, Clone)]
pub struct WsCloseFrame {
    pub code: u16,
    pub reason: String,
}

#[derive(Debug)]
pub struct WebSocketClient {
    config: WsConfig,
    url: Option<String>,
    resolver_chain: Arc<ResolverChain>,
    domain_fronting_enabled: bool,
    fronting: DomainFrontingProxy,
    fronting_v2: Option<Arc<FrontingV2Ws>>,
    #[cfg(feature = "websocket")]
    out_tx: Option<tokio::sync::mpsc::Sender<WsMessage>>,
    #[cfg(feature = "websocket")]
    in_rx: Option<tokio::sync::mpsc::Receiver<Result<WsMessage>>>,
    #[cfg(feature = "websocket")]
    worker: Option<tokio::task::JoinHandle<()>>,
}

impl WebSocketClient {
    /// Creates a new WebSocket client.
    ///
    /// A `ResolverChain` is required to avoid accidental system DNS usage (DNS leak).
    pub fn new(config: WsConfig, resolver_chain: Arc<ResolverChain>) -> Self {
        Self {
            config,
            url: None,
            resolver_chain,
            domain_fronting_enabled: false,
            fronting: DomainFrontingProxy::new(),
            fronting_v2: None,
            #[cfg(feature = "websocket")]
            out_tx: None,
            #[cfg(feature = "websocket")]
            in_rx: None,
            #[cfg(feature = "websocket")]
            worker: None,
        }
    }

    /// Fallible constructor that explicitly validates the presence of a `ResolverChain`.
    pub fn try_new(config: WsConfig, resolver_chain: Option<Arc<ResolverChain>>) -> Result<Self> {
        let Some(chain) = resolver_chain else {
            return Err(EngineError::InvalidInput(
                "WebSocketClient requires a ResolverChain to avoid DNS leaks. Create it via PrimeHttpClient::websocket_client(...) or pass ResolverChain explicitly."
                    .to_owned(),
            ));
        };
        Ok(Self::new(config, chain))
    }

    /// Enables domain fronting for WebSocket URLs using the provided mapping.
    ///
    /// The connection will be made to the front domain/IP, while `Host` header will be set to the real host
    /// (if a rule matches).
    pub fn with_domain_fronting(mut self, enabled: bool, fronting: DomainFrontingProxy) -> Self {
        self.domain_fronting_enabled = enabled;
        self.fronting = fronting;
        self
    }

    /// Enables domain fronting v2 for WebSocket:
    /// dynamically selects a working front domain via `HEAD https://<front>/` probe with `Host: <real_host>`,
    /// and caches the result for `fronting_probe_ttl_secs`.
    pub fn with_domain_fronting_v2(
        mut self,
        enabled: bool,
        rules: &[DomainFrontingRule],
        fronting_probe_ttl_secs: u64,
        fronting_probe_timeout_secs: u64,
    ) -> Self {
        if !enabled {
            self.fronting_v2 = None;
            return self;
        }

        let mut map: HashMap<String, FrontingRuleV2Ws> = HashMap::new();
        for rule in rules {
            let target = rule.target_host.trim().to_ascii_lowercase();
            if target.is_empty() {
                continue;
            }

            let candidates: Vec<String> = if !rule.front_domains.is_empty() {
                rule.front_domains
                    .iter()
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect()
            } else if !rule.front_domain.trim().is_empty() {
                vec![rule.front_domain.trim().to_owned()]
            } else {
                Vec::new()
            };

            if candidates.is_empty() || rule.real_host.trim().is_empty() {
                continue;
            }

            map.insert(
                target,
                FrontingRuleV2Ws {
                    candidates,
                    real_host: rule.real_host.trim().to_owned(),
                },
            );
        }

        if map.is_empty() {
            self.fronting_v2 = None;
            return self;
        }

        let dns = std::sync::Arc::new(PrimeReqwestDnsResolver::new(self.resolver_chain.clone()));
        let probe_client = match reqwest::Client::builder().no_proxy().dns_resolver(dns).build() {
            Ok(v) => v,
            Err(_) => {
                // Best-effort: if probe client can't be built, disable v2 (v1 still works).
                self.fronting_v2 = None;
                return self;
            }
        };

        let ttl = Duration::from_secs(fronting_probe_ttl_secs.max(1));
        let timeout = Duration::from_secs(fronting_probe_timeout_secs.max(1));
        self.fronting_v2 = Some(Arc::new(FrontingV2Ws {
            rules: map,
            cache: parking_lot::Mutex::new(HashMap::new()),
            ttl,
            timeout,
            probe_client,
        }));
        self
    }

    pub async fn connect(&mut self, url: &str) -> Result<()> {
        self.url = Some(url.to_owned());

        #[cfg(feature = "websocket")]
        {
            self.close().await?;
            let (out_tx, out_rx) = tokio::sync::mpsc::channel(self.config.outbound_queue.max(1));
            let (in_tx, in_rx) = tokio::sync::mpsc::channel(self.config.inbound_queue.max(1));
            let url = url.to_owned();
            let cfg = self.config.clone();
            let resolver_chain = self.resolver_chain.clone();
            let fronting_enabled = self.domain_fronting_enabled;
            let fronting = self.fronting.clone();
            let fronting_v2 = self.fronting_v2.clone();

            let worker = tokio::spawn(async move {
                ws_worker(
                    url,
                    cfg,
                    resolver_chain,
                    fronting_enabled,
                    fronting,
                    fronting_v2,
                    out_rx,
                    in_tx,
                )
                .await;
            });

            self.out_tx = Some(out_tx);
            self.in_rx = Some(in_rx);
            self.worker = Some(worker);
            Ok(())
        }

        #[cfg(not(feature = "websocket"))]
        {
            let _ = url;
            Err(EngineError::Internal(
                "websocket support is not enabled in this build (enable feature \"websocket\")"
                    .to_owned(),
            ))
        }
    }

    pub async fn send(&mut self, msg: WsMessage) -> Result<()> {
        #[cfg(feature = "websocket")]
        {
            let Some(tx) = &self.out_tx else {
                return Err(EngineError::InvalidInput(
                    "websocket is not connected".to_owned(),
                ));
            };
            tx.send(msg)
                .await
                .map_err(|_| EngineError::Internal("websocket worker stopped".to_owned()))?;
            Ok(())
        }

        #[cfg(not(feature = "websocket"))]
        {
            let _ = msg;
            Err(EngineError::Internal(
                "websocket support is not enabled in this build (enable feature \"websocket\")"
                    .to_owned(),
            ))
        }
    }

    pub async fn receive(&mut self) -> Result<WsMessage> {
        #[cfg(feature = "websocket")]
        {
            let Some(rx) = &mut self.in_rx else {
                return Err(EngineError::InvalidInput(
                    "websocket is not connected".to_owned(),
                ));
            };
            match rx.recv().await {
                Some(Ok(m)) => Ok(m),
                Some(Err(e)) => Err(e),
                None => Err(EngineError::Internal("websocket worker stopped".to_owned())),
            }
        }

        #[cfg(not(feature = "websocket"))]
        {
            Err(EngineError::Internal(
                "websocket support is not enabled in this build (enable feature \"websocket\")"
                    .to_owned(),
            ))
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        #[cfg(feature = "websocket")]
        {
            if let Some(tx) = &self.out_tx {
                let _ = tx.send(WsMessage::Close(None)).await;
            }
            self.out_tx = None;
            self.in_rx = None;
            if let Some(handle) = self.worker.take() {
                handle.abort();
            }
        }
        Ok(())
    }

    pub fn config(&self) -> &WsConfig {
        &self.config
    }
}

#[cfg(feature = "websocket")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpCode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

#[cfg(feature = "websocket")]
impl OpCode {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            _ => return None,
        })
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[cfg(feature = "websocket")]
#[derive(Debug)]
struct Frame {
    fin: bool,
    rsv1: bool,
    opcode: OpCode,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct FrontingRuleV2Ws {
    candidates: Vec<String>,
    real_host: String,
}

#[derive(Debug)]
struct FrontingCacheEntryV2Ws {
    front_domain: String,
    expires_at: Instant,
}

#[derive(Debug)]
struct FrontingV2Ws {
    rules: HashMap<String, FrontingRuleV2Ws>,
    cache: parking_lot::Mutex<HashMap<String, FrontingCacheEntryV2Ws>>,
    ttl: Duration,
    timeout: Duration,
    probe_client: reqwest::Client,
}

impl FrontingV2Ws {
    async fn apply(&self, req: &mut RequestData) -> Result<bool> {
        let parsed = Url::parse(&req.url)?;
        let Some(host) = parsed.host_str() else {
            return Ok(false);
        };
        let key = host.to_ascii_lowercase();

        let Some(rule) = self.rules.get(&key) else {
            return Ok(false);
        };

        let now = Instant::now();
        if let Some(entry) = self.cache.lock().get(&key).filter(|e| e.expires_at > now) {
            return self.rewrite_request(&parsed, req, &entry.front_domain, &rule.real_host);
        }

        for cand in &rule.candidates {
            if self.probe_front_domain(cand, &rule.real_host).await {
                self.cache.lock().insert(
                    key.clone(),
                    FrontingCacheEntryV2Ws {
                        front_domain: cand.clone(),
                        expires_at: now + self.ttl,
                    },
                );
                return self.rewrite_request(&parsed, req, cand, &rule.real_host);
            }
        }

        // No working candidate; fall back to first (same behavior as HTTP), still rewriting.
        if let Some(first) = rule.candidates.first() {
            return self.rewrite_request(&parsed, req, first, &rule.real_host);
        }

        Ok(false)
    }

    fn rewrite_request(
        &self,
        parsed: &Url,
        req: &mut RequestData,
        front_domain: &str,
        real_host: &str,
    ) -> Result<bool> {
        let mut new_url = parsed.clone();
        new_url.set_host(Some(front_domain))?;
        req.url = new_url.to_string();

        // Override Host header to the real host (domain-fronting).
        req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
        req.headers.push(("Host".to_owned(), real_host.to_owned()));
        Ok(true)
    }

    async fn probe_front_domain(&self, front_domain: &str, real_host: &str) -> bool {
        let Ok(host_header) = HeaderValue::from_str(real_host) else {
            return false;
        };
        let url = format!("https://{front_domain}/");
        let req = self.probe_client.head(url).header(HOST, host_header);

        match tokio::time::timeout(self.timeout, req.send()).await {
            Ok(Ok(resp)) => resp.status().as_u16() < 500,
            _ => false,
        }
    }
}

#[cfg(feature = "websocket")]
#[allow(clippy::too_many_arguments)]
async fn ws_worker(
    url: String,
    cfg: WsConfig,
    resolver_chain: Arc<ResolverChain>,
    domain_fronting_enabled: bool,
    fronting: DomainFrontingProxy,
    fronting_v2: Option<Arc<FrontingV2Ws>>,
    mut out_rx: tokio::sync::mpsc::Receiver<WsMessage>,
    in_tx: tokio::sync::mpsc::Sender<Result<WsMessage>>,
) {
    let mut attempts: usize = 0;

    loop {
        match connect_and_run(
            &url,
            &cfg,
            &resolver_chain,
            domain_fronting_enabled,
            &fronting,
            fronting_v2.as_deref(),
            &mut out_rx,
            &in_tx,
        )
        .await
        {
            Ok(()) => {
                // graceful close
                break;
            }
            Err(e) => {
                attempts += 1;
                if attempts > cfg.max_reconnect_attempts {
                    let _ = in_tx.send(Err(e)).await;
                    break;
                }
                tokio::time::sleep(cfg.reconnect_backoff).await;
            }
        }
    }
}

#[cfg(feature = "websocket")]
#[allow(clippy::too_many_arguments)]
async fn connect_and_run(
    url: &str,
    cfg: &WsConfig,
    resolver_chain: &Arc<ResolverChain>,
    domain_fronting_enabled: bool,
    fronting: &DomainFrontingProxy,
    fronting_v2: Option<&FrontingV2Ws>,
    out_rx: &mut tokio::sync::mpsc::Receiver<WsMessage>,
    in_tx: &tokio::sync::mpsc::Sender<Result<WsMessage>>,
) -> Result<()> {
    // Fronting v2 first (if configured): dynamic front selection + caching via HTTPS HEAD probe.
    // Fall back to v1 mapping for backward compatibility.
    let mut req = RequestData::get(url);
    req.headers = cfg.headers.clone();
    let mut cfg = cfg.clone();

    let parsed_in =
        Url::parse(url).map_err(|e| EngineError::InvalidInput(format!("invalid url: {e}")))?;
    let mut applied_v2 = false;
    if parsed_in.scheme().eq_ignore_ascii_case("wss") {
        if let Some(v2) = fronting_v2 {
            applied_v2 = v2.apply(&mut req).await?;
        }
    }

    if domain_fronting_enabled && !applied_v2 {
        // If v2 didn't match a rule, v1 may still provide a legacy mapping.
        fronting.apply_fronting(&mut req)?;
    }

    cfg.headers = req.headers;
    let url = req.url;

    let parsed =
        Url::parse(&url).map_err(|e| EngineError::InvalidInput(format!("invalid url: {e}")))?;
    let (mut stream, connect_host) =
        connect_transport(&parsed, resolver_chain.as_ref(), cfg.engine_config.as_ref()).await?;
    let handshake = handshake(&mut stream, &parsed, &connect_host, &cfg).await?;

    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut pending: VecDeque<Frame> = VecDeque::new();
    let mut ping = cfg.ping_interval.map(tokio::time::interval);

    // Fragment assembly.
    let mut assembling: Option<(OpCode, bool, Vec<u8>)> = None; // (opcode, compressed, data)

    loop {
        tokio::select! {
            Some(msg) = out_rx.recv() => {
                match msg {
                    WsMessage::Text(t) => {
                        let data = t.into_bytes();
                        pending.push_back(build_data_frame(OpCode::Text, data, handshake.deflate));
                    }
                    WsMessage::Binary(b) => {
                        pending.push_back(build_data_frame(OpCode::Binary, b, handshake.deflate));
                    }
                    WsMessage::Ping(p) => pending.push_back(build_control_frame(OpCode::Ping, p)),
                    WsMessage::Pong(p) => pending.push_back(build_control_frame(OpCode::Pong, p)),
                    WsMessage::Close(frame) => {
                        pending.push_back(build_close_frame(frame));
                        flush_pending(&mut wr, &mut pending).await?;
                        return Ok(());
                    }
                }
            }
            _ = async {
                match &mut ping {
                    Some(i) => i.tick().await,
                    None => std::future::pending().await,
                }
            } => {
                pending.push_back(build_control_frame(OpCode::Ping, Vec::new()));
            }
            frame = read_frame(&mut rd, cfg.max_message_size) => {
                let frame = frame?;

                if frame.opcode.is_control() {
                    match frame.opcode {
                        OpCode::Ping => {
                            pending.push_back(build_control_frame(OpCode::Pong, frame.payload));
                        }
                        OpCode::Pong => {
                            let _ = in_tx.send(Ok(WsMessage::Pong(frame.payload))).await;
                        }
                        OpCode::Close => {
                            let close = parse_close_frame(&frame.payload);
                            let _ = in_tx
                                .send(Ok(WsMessage::Close(close.clone())))
                                .await;
                            // Reply with close if we haven't already.
                            pending.push_back(build_close_frame(close.clone()));
                            flush_pending(&mut wr, &mut pending).await?;
                            return Ok(());
                        }
                        _ => {}
                    }
                } else {
                    match frame.opcode {
                        OpCode::Text | OpCode::Binary => {
                            let compressed = frame.rsv1 && handshake.deflate;
                            let mut data = frame.payload;
                            if frame.fin {
                                if compressed {
                                    data = inflate_message(&data)?;
                                }
                                deliver_data_message(frame.opcode, data, in_tx).await;
                            } else {
                                assembling = Some((frame.opcode, compressed, data));
                            }
                        }
                        OpCode::Continuation => {
                            let Some((opcode, compressed, mut data)) = assembling.take() else {
                                return Err(EngineError::Internal("unexpected continuation frame".to_owned()));
                            };
                            data.extend_from_slice(&frame.payload);
                            if data.len() > cfg.max_message_size {
                                return Err(EngineError::Internal("websocket message too large".to_owned()));
                            }
                            if frame.fin {
                                let data = if compressed { inflate_message(&data)? } else { data };
                                deliver_data_message(opcode, data, in_tx).await;
                            } else {
                                assembling = Some((opcode, compressed, data));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        flush_pending(&mut wr, &mut pending).await?;
    }
}

#[cfg(feature = "websocket")]
async fn deliver_data_message(
    opcode: OpCode,
    data: Vec<u8>,
    in_tx: &tokio::sync::mpsc::Sender<Result<WsMessage>>,
) {
    let msg = match opcode {
        OpCode::Text => match String::from_utf8(data) {
            Ok(v) => WsMessage::Text(v),
            Err(_) => {
                let _ = in_tx
                    .send(Err(EngineError::Internal(
                        "invalid UTF-8 in text message".to_owned(),
                    )))
                    .await;
                return;
            }
        },
        OpCode::Binary => WsMessage::Binary(data),
        _ => return,
    };
    let _ = in_tx.send(Ok(msg)).await;
}

#[cfg(feature = "websocket")]
async fn flush_pending(
    wr: &mut tokio::io::WriteHalf<DynStream>,
    pending: &mut VecDeque<Frame>,
) -> Result<()> {
    while let Some(frame) = pending.pop_front() {
        write_frame(wr, &frame).await?;
    }
    Ok(())
}

#[cfg(feature = "websocket")]
fn build_control_frame(opcode: OpCode, payload: Vec<u8>) -> Frame {
    Frame {
        fin: true,
        rsv1: false,
        opcode,
        payload,
    }
}

#[cfg(feature = "websocket")]
fn build_close_frame(frame: Option<WsCloseFrame>) -> Frame {
    let payload = if let Some(f) = frame {
        let mut out = Vec::new();
        out.extend_from_slice(&f.code.to_be_bytes());
        out.extend_from_slice(f.reason.as_bytes());
        out
    } else {
        Vec::new()
    };
    build_control_frame(OpCode::Close, payload)
}

#[cfg(feature = "websocket")]
fn parse_close_frame(payload: &[u8]) -> Option<WsCloseFrame> {
    if payload.len() < 2 {
        return None;
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let reason = String::from_utf8_lossy(&payload[2..]).to_string();
    Some(WsCloseFrame { code, reason })
}

#[cfg(feature = "websocket")]
fn build_data_frame(opcode: OpCode, payload: Vec<u8>, deflate: bool) -> Frame {
    if deflate {
        if let Ok(compressed) = deflate_message(&payload) {
            return Frame {
                fin: true,
                rsv1: true,
                opcode,
                payload: compressed,
            };
        }
    }
    Frame {
        fin: true,
        rsv1: false,
        opcode,
        payload,
    }
}

#[cfg(feature = "websocket")]
fn deflate_message(input: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(input)
        .map_err(|e| EngineError::Internal(format!("deflate write failed: {e}")))?;
    let mut out = encoder
        .finish()
        .map_err(|e| EngineError::Internal(format!("deflate finish failed: {e}")))?;

    // Per-message deflate requires removing the 0x00 0x00 0xff 0xff tail if present.
    const TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];
    if out.ends_with(&TAIL) {
        out.truncate(out.len() - TAIL.len());
    }
    Ok(out)
}

#[cfg(feature = "websocket")]
fn inflate_message(input: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::DeflateDecoder;

    // Per-message deflate requires adding the tail before inflating.
    const TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];
    let mut data = Vec::with_capacity(input.len() + 4);
    data.extend_from_slice(input);
    data.extend_from_slice(&TAIL);

    let mut decoder = DeflateDecoder::new(&data[..]);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| EngineError::Internal(format!("inflate failed: {e}")))?;
    Ok(out)
}

