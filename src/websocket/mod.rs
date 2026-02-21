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
use crate::config::DomainFrontingRule;
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
        let probe_client = match reqwest::Client::builder().dns_resolver(dns).build() {
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
    let (mut stream, connect_host) = connect_transport(&parsed, resolver_chain.as_ref()).await?;
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

#[cfg(feature = "websocket")]
async fn read_frame(
    rd: &mut tokio::io::ReadHalf<DynStream>,
    max_message_size: usize,
) -> Result<Frame> {
    use tokio::io::AsyncReadExt;

    let mut h = [0u8; 2];
    rd.read_exact(&mut h)
        .await
        .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
    let fin = (h[0] & 0x80) != 0;
    let rsv1 = (h[0] & 0x40) != 0;
    let opcode = OpCode::from_u8(h[0] & 0x0f)
        .ok_or_else(|| EngineError::Internal("unknown websocket opcode".to_owned()))?;
    let masked = (h[1] & 0x80) != 0;
    let mut len = (h[1] & 0x7f) as u64;
    if len == 126 {
        let mut b = [0u8; 2];
        rd.read_exact(&mut b)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
        len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8];
        rd.read_exact(&mut b)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
        len = u64::from_be_bytes(b);
    }

    if len as usize > max_message_size {
        return Err(EngineError::Internal(
            "websocket frame too large".to_owned(),
        ));
    }

    let mask = if masked {
        let mut m = [0u8; 4];
        rd.read_exact(&mut m)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
        Some(m)
    } else {
        None
    };

    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        rd.read_exact(&mut payload)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket read failed: {e}")))?;
    }

    if let Some(mask) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }

    Ok(Frame {
        fin,
        rsv1,
        opcode,
        payload,
    })
}

#[cfg(feature = "websocket")]
async fn write_frame(wr: &mut tokio::io::WriteHalf<DynStream>, frame: &Frame) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut header = Vec::with_capacity(14);
    let mut b0 = frame.opcode as u8;
    if frame.fin {
        b0 |= 0x80;
    }
    if frame.rsv1 {
        b0 |= 0x40;
    }
    header.push(b0);

    // Client frames must be masked.
    let mask_bit = 0x80;
    let len = frame.payload.len() as u64;
    if len <= 125 {
        header.push(mask_bit | (len as u8));
    } else if len <= u16::MAX as u64 {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&len.to_be_bytes());
    }

    let mut mask = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mask);
    header.extend_from_slice(&mask);

    wr.write_all(&header)
        .await
        .map_err(|e| EngineError::Internal(format!("websocket write failed: {e}")))?;

    if !frame.payload.is_empty() {
        let mut masked = frame.payload.clone();
        for (i, b) in masked.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        wr.write_all(&masked)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket write failed: {e}")))?;
    }

    wr.flush()
        .await
        .map_err(|e| EngineError::Internal(format!("websocket flush failed: {e}")))?;
    Ok(())
}

#[cfg(feature = "websocket")]
struct HandshakeResult {
    deflate: bool,
}

#[cfg(feature = "websocket")]
async fn handshake(
    stream: &mut DynStream,
    url: &Url,
    host: &str,
    cfg: &WsConfig,
) -> Result<HandshakeResult> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let key = generate_ws_key();
    let accept_expected = websocket_accept(&key);

    let port = url.port_or_known_default().unwrap_or(80);
    let default_port = match url.scheme().to_ascii_lowercase().as_str() {
        "ws" => 80,
        "wss" => 443,
        _ => port,
    };
    let mut path = url.path().to_owned();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    if path.is_empty() {
        path = "/".to_owned();
    }

    let mut req = String::new();
    req.push_str(&format!("GET {path} HTTP/1.1\r\n"));

    let host_override = cfg
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone());
    let mut host_header = host_override.unwrap_or_else(|| host.to_owned());
    if port != default_port && !host_header.contains(':') {
        host_header = format!("{host_header}:{port}");
    }
    req.push_str(&format!("Host: {host_header}\r\n"));

    req.push_str("Upgrade: websocket\r\n");
    req.push_str("Connection: Upgrade\r\n");
    req.push_str("Sec-WebSocket-Version: 13\r\n");
    req.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    if cfg.permessage_deflate {
        req.push_str("Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n");
    }
    for (k, v) in &cfg.headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| EngineError::Internal(format!("websocket handshake write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| EngineError::Internal(format!("websocket handshake flush failed: {e}")))?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| EngineError::Internal(format!("websocket handshake read failed: {e}")))?;
        if n == 0 {
            return Err(EngineError::Internal("websocket handshake: EOF".to_owned()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 32 * 1024 {
            return Err(EngineError::Internal(
                "websocket handshake: response too large".to_owned(),
            ));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let (head, _rest) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| EngineError::Internal("websocket handshake: bad response".to_owned()))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| EngineError::Internal("websocket handshake: missing status".to_owned()))?;
    if !status.contains(" 101 ") {
        return Err(EngineError::Internal(format!(
            "websocket handshake failed: {status}"
        )));
    }

    let mut accept = None;
    let mut extensions = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_owned();
            if k == "sec-websocket-accept" {
                accept = Some(v);
            } else if k == "sec-websocket-extensions" {
                extensions = Some(v);
            }
        }
    }

    let Some(accept) = accept else {
        return Err(EngineError::Internal(
            "websocket handshake: missing sec-websocket-accept".to_owned(),
        ));
    };
    if accept.trim() != accept_expected {
        return Err(EngineError::Internal(
            "websocket handshake: invalid sec-websocket-accept".to_owned(),
        ));
    }

    let deflate = cfg.permessage_deflate
        && extensions
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("permessage-deflate");

    Ok(HandshakeResult { deflate })
}

#[cfg(feature = "websocket")]
fn generate_ws_key() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(feature = "websocket")]
fn websocket_accept(key_b64: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut v = Vec::new();
    v.extend_from_slice(key_b64.as_bytes());
    v.extend_from_slice(GUID.as_bytes());
    let digest = sha1(&v);
    base64::engine::general_purpose::STANDARD.encode(digest)
}

#[cfg(feature = "websocket")]
fn sha1(input: &[u8]) -> [u8; 20] {
    // Minimal SHA-1 implementation for RFC6455 handshake validation.
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let mut msg = input.to_vec();
    let bit_len = (msg.len() as u64) * 8;
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, wi) in w.iter().enumerate() {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A827999)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

#[cfg(feature = "websocket")]
async fn connect_transport(
    url: &Url,
    resolver_chain: &ResolverChain,
) -> Result<(DynStream, String)> {
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url
        .host_str()
        .ok_or_else(|| EngineError::InvalidInput("missing host".to_owned()))?
        .to_owned();
    let port = url.port_or_known_default().ok_or_else(|| {
        EngineError::InvalidInput(format!("unknown default port for scheme {}", url.scheme()))
    })?;

    let addr: SocketAddr = match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => {
            let ips = resolver_chain.resolve(&host).await?;
            let ip = *ips.first().ok_or_else(|| {
                EngineError::Internal("dns resolve produced no addresses".to_owned())
            })?;
            SocketAddr::new(ip, port)
        }
    };

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| EngineError::Internal(format!("tcp connect failed: {e}")))?;
    tcp.set_nodelay(true).ok();

    match scheme.as_str() {
        "ws" => Ok((Box::new(tcp), host)),
        "wss" => {
            let tls = tls_connect(tcp, &host).await?;
            Ok((Box::new(tls), host))
        }
        _ => Err(EngineError::InvalidInput(
            "only ws:// and wss:// URLs are supported".to_owned(),
        )),
    }
}

#[cfg(feature = "websocket")]
async fn tls_connect(
    tcp: tokio::net::TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    use rustls::pki_types::ServerName;

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| EngineError::InvalidInput("invalid tls server name".to_owned()))?;
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| EngineError::Internal(format!("tls connect failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "websocket")]
    async fn read_exact_prefetched(
        sock: &mut tokio::net::TcpStream,
        prefetched: &mut Vec<u8>,
        dst: &mut [u8],
    ) -> std::io::Result<()> {
        let take = prefetched.len().min(dst.len());
        if take > 0 {
            dst[..take].copy_from_slice(&prefetched[..take]);
            prefetched.drain(..take);
        }
        if take < dst.len() {
            tokio::io::AsyncReadExt::read_exact(sock, &mut dst[take..]).await?;
        }
        Ok(())
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    #[cfg_attr(
        windows,
        ignore = "flaky on Windows under parallel test load (sporadic reconnect race)"
    )]
    async fn websocket_handshake_and_echo_frames_over_tcp() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let cfg = crate::config::EngineConfig::default();
        let resolver = std::sync::Arc::new(
            crate::anticensorship::ResolverChain::from_config(&cfg.anticensorship)
                .expect("build resolver chain"),
        );

        // Minimal RFC6455 server: does handshake, echoes single-frame masked client messages back unmasked.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut req_buf = Vec::with_capacity(4096);
            loop {
                let mut chunk = [0u8; 1024];
                let n = sock.read(&mut chunk).await.expect("read");
                if n == 0 {
                    panic!("unexpected EOF before websocket headers");
                }
                req_buf.extend_from_slice(&chunk[..n]);
                if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if req_buf.len() > 16 * 1024 {
                    panic!("websocket headers too large");
                }
            }
            let headers_end = req_buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("headers end")
                + 4;
            let mut prefetched = req_buf[headers_end..].to_vec();
            req_buf.truncate(headers_end);
            let req = String::from_utf8_lossy(&req_buf);
            let key_line = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
                .expect("key");
            let key = key_line.split(':').nth(1).unwrap().trim();
            let accept = websocket_accept(key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            sock.write_all(resp.as_bytes()).await.expect("write");

            // Echo loop: supports one text frame then close.
            // Read first two bytes.
            let mut h = [0u8; 2];
            read_exact_prefetched(&mut sock, &mut prefetched, &mut h)
                .await
                .expect("read h");
            let masked = (h[1] & 0x80) != 0;
            let mut len = (h[1] & 0x7f) as usize;
            assert!(masked);
            if len == 126 {
                let mut b = [0u8; 2];
                read_exact_prefetched(&mut sock, &mut prefetched, &mut b)
                    .await
                    .expect("len");
                len = u16::from_be_bytes(b) as usize;
            }
            let mut mask = [0u8; 4];
            read_exact_prefetched(&mut sock, &mut prefetched, &mut mask)
                .await
                .expect("mask");
            let mut payload = vec![0u8; len];
            read_exact_prefetched(&mut sock, &mut prefetched, &mut payload)
                .await
                .expect("payload");
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }

            // Write unmasked echo as a server.
            let mut out = Vec::new();
            out.push(0x81); // FIN + TEXT
            out.push(payload.len() as u8);
            out.extend_from_slice(&payload);
            sock.write_all(&out).await.expect("echo");

            // Keep the socket open until the client initiates close().
            // This avoids a race where client receive() may observe close before text echo.
            let mut close_req = [0u8; 2];
            let _ =
                tokio::time::timeout(Duration::from_secs(2), sock.read_exact(&mut close_req)).await;
            let _ = sock.write_all(&[0x88, 0x00]).await;
            let _ = sock.shutdown().await;
        });

        let mut client = WebSocketClient::new(
            WsConfig {
                permessage_deflate: false,
                ..WsConfig::default()
            },
            resolver,
        );
        client
            .connect(&format!("ws://{addr}/echo"))
            .await
            .expect("connect");
        client
            .send(WsMessage::Text("hello".to_owned()))
            .await
            .expect("send");
        let msg = client.receive().await.expect("receive");
        match msg {
            WsMessage::Text(v) => assert_eq!(v, "hello"),
            other => panic!("unexpected: {other:?}"),
        }

        let _ = client.close().await;
        let _ = server.await;
    }
}
