use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use reqwest::header::HOST;
use reqwest::header::RANGE;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::io::StreamReader;
use url::Url;

use rand::seq::SliceRandom;
use rand::thread_rng;
use rustls::SupportedProtocolVersion;

use crate::anticensorship::{
    CdnProvider, DomainFrontingProxy, FrontConfig, PrimeReqwestDnsResolver, ResolverChain,
    TlsFingerprintRandomizer,
};
use crate::config::{
    DomainFrontingRule, EchMode, EngineConfig, EvasionStrategy, FrontingProvider,
    TrackerBlockAction,
};
use crate::core::chunk_manager::{ChunkManager, DownloadStrategy, ProgressHook};
use crate::core::connection_pool::ConnectionPoolConfig;
use crate::core::{DownloadOutcome, RequestData, ResponseData, ResponseStream};
use crate::error::{EngineError, Result};
use crate::evasion::{FragmentConfig, FragmentingIo};
use crate::privacy::dnt::apply_signals;
use crate::privacy::record_blocked_domain;
use crate::privacy::referer_policy::{apply_referer_policy, RefererDecision};
use crate::privacy::tracker_blocker::TrackerBlocker;
use crate::telemetry::connection_tracker::{
    global_connection_tracker, ConnectionStatus, ConnectionTracker, DnsInfo, DownloadInfo, TlsInfo,
};
use crate::tls::{Ja3Fingerprint, TlsVersion};
use crate::websocket::{WebSocketClient, WsConfig};

mod http3;

trait AsyncIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncIo for T {}

#[derive(Debug)]
/// Primary HTTP client used by the engine.
///
/// This wraps an underlying `reqwest::Client` and applies engine configuration such as:
/// TLS (including optional ECH), anti-censorship DNS, domain fronting, and adaptive chunked downloads.
pub struct PrimeHttpClient {
    client_plain: reqwest::Client,
    client_ech_grease: Option<reqwest::Client>,
    client_ech_real_cache: parking_lot::Mutex<std::collections::HashMap<String, reqwest::Client>>,
    config: EngineConfig,
    chunk_manager: ChunkManager,
    resolver_chain: std::sync::Arc<ResolverChain>,
    dns_resolver: std::sync::Arc<PrimeReqwestDnsResolver>,
    fronting: DomainFrontingProxy,
    fronting_v2: FrontingV2,
    h2_reset_limiter: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    tls_randomizer: TlsFingerprintRandomizer,
    connection_tracker: Option<ConnectionTracker>,
    tracker_blocker: Option<TrackerBlocker>,
}

#[derive(Debug, Clone)]
struct FrontingRuleV2 {
    candidates: Vec<String>,
    real_host: String,
}

#[derive(Debug)]
struct FrontingCacheEntry {
    front_domain: String,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct FrontingV2 {
    rules: HashMap<String, FrontingRuleV2>,
    cache: parking_lot::Mutex<HashMap<String, FrontingCacheEntry>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivacyInterception {
    None,
    Empty200,
}

fn build_fronting_maps(rules: &[DomainFrontingRule]) -> (DomainFrontingProxy, FrontingV2) {
    let mut v1 = DomainFrontingProxy::new();
    let mut v2 = FrontingV2 {
        rules: HashMap::new(),
        cache: parking_lot::Mutex::new(HashMap::new()),
    };

    for rule in rules {
        let target = rule.target_host.to_ascii_lowercase();

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

        if candidates.is_empty() {
            continue;
        }

        // v1 proxy map uses the first candidate for compatibility (used by WebSocketClient today).
        let first = candidates[0].clone();
        v1.upsert_mapping(
            target.clone(),
            FrontConfig {
                front_domain: first.clone(),
                real_host: rule.real_host.clone(),
                sni_domain: rule.sni_domain.clone().unwrap_or_else(|| first.clone()),
                provider: map_fronting_provider(&rule.provider),
            },
        );

        v2.rules.insert(
            target,
            FrontingRuleV2 {
                candidates,
                real_host: rule.real_host.clone(),
            },
        );
    }

    (v1, v2)
}

impl PrimeHttpClient {
    /// Creates a new client from the given engine configuration.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the configuration is invalid or if the underlying HTTP client cannot be built.
    pub fn new(config: EngineConfig) -> Result<Self> {
        config.validate()?;
        let strategy = DownloadStrategy {
            initial_concurrency: config.download.initial_concurrency,
            max_concurrency: config.download.max_concurrency,
            chunk_size_bytes: config.download.chunk_size_mb * 1024 * 1024,
            adaptive_threshold_mbps: config.download.adaptive_threshold_mbps,
        };

        let pool = ConnectionPoolConfig {
            max_idle_per_host: config.download.max_idle_per_host,
            idle_timeout_secs: config.download.pool_idle_timeout_secs,
        };

        let resolver_chain =
            std::sync::Arc::new(ResolverChain::from_config(&config.anticensorship)?);
        let dns_resolver =
            std::sync::Arc::new(PrimeReqwestDnsResolver::new(resolver_chain.clone()));

        // Always build a plain client (no ECH) so we can fall back if ECH fails.
        let tls_plain = build_rustls_client_config(&config, None)?;
        let client_plain = build_reqwest_client(&config, &pool, dns_resolver.clone(), tls_plain)?;

        // Optional ECH GREASE client (used for ech_mode=grease, and as fallback for auto).
        let ech_mode = config.anticensorship.effective_ech_mode();
        let client_ech_grease = match ech_mode {
            Some(EchMode::Grease) | Some(EchMode::Auto) => {
                let tls = build_rustls_client_config(&config, Some(build_ech_grease_mode()?))?;
                Some(build_reqwest_client(
                    &config,
                    &pool,
                    dns_resolver.clone(),
                    tls,
                )?)
            }
            _ => None,
        };

        let (fronting, fronting_v2) =
            build_fronting_maps(&config.anticensorship.domain_fronting_rules);
        let tracker_blocker = TrackerBlocker::from_config(&config.privacy.tracker_blocker)?;

        Ok(Self {
            client_plain,
            client_ech_grease,
            client_ech_real_cache: parking_lot::Mutex::new(std::collections::HashMap::new()),
            chunk_manager: ChunkManager::new(strategy, config.download.adaptive_enabled),
            fronting,
            fronting_v2,
            h2_reset_limiter: config
                .download
                .http2_max_concurrent_reset_streams
                .map(|v| std::sync::Arc::new(tokio::sync::Semaphore::new(v.max(1)))),
            tls_randomizer: TlsFingerprintRandomizer::default(),
            connection_tracker: Some(global_connection_tracker()),
            tracker_blocker,
            resolver_chain,
            dns_resolver,
            config,
        })
    }

    /// Creates a `WebSocketClient` wired to the same DNS resolver chain and domain fronting rules as this HTTP client.
    pub fn websocket_client(&self, ws_config: WsConfig) -> WebSocketClient {
        WebSocketClient::new(ws_config, self.resolver_chain.clone())
            .with_domain_fronting(
                self.config.anticensorship.domain_fronting_enabled,
                self.fronting.clone(),
            )
            .with_domain_fronting_v2(
                self.config.anticensorship.domain_fronting_enabled,
                &self.config.anticensorship.domain_fronting_rules,
                self.config.anticensorship.fronting_probe_ttl_secs,
                self.config.anticensorship.fronting_probe_timeout_secs,
            )
    }

    async fn apply_fronting_v2_if_enabled(&self, req: &mut RequestData) -> Result<()> {
        if !self.config.anticensorship.domain_fronting_enabled {
            return Ok(());
        }

        let parsed = Url::parse(&req.url)?;
        let Some(host) = parsed.host_str() else {
            return Ok(());
        };
        let key = host.to_ascii_lowercase();

        let Some(rule) = self.fronting_v2.rules.get(&key) else {
            // Backward-compatible fallback: if a rule exists only in the legacy proxy map.
            return self.fronting.apply_fronting(req);
        };

        let selected = self.select_working_front_domain(&key, rule).await;
        let front_domain = selected
            .or_else(|| rule.candidates.first().cloned())
            .unwrap_or_else(|| host.to_owned());

        let mut new_url = parsed.clone();
        new_url.set_host(Some(&front_domain))?;
        req.url = new_url.to_string();

        // Override Host header to the real host (domain-fronting).
        req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
        req.headers
            .push(("Host".to_owned(), rule.real_host.clone()));
        Ok(())
    }

    async fn select_working_front_domain(
        &self,
        target_host: &str,
        rule: &FrontingRuleV2,
    ) -> Option<String> {
        let now = Instant::now();
        if let Some(entry) = self
            .fronting_v2
            .cache
            .lock()
            .get(target_host)
            .filter(|e| e.expires_at > now)
        {
            return Some(entry.front_domain.clone());
        }

        for cand in &rule.candidates {
            if self.probe_front_domain(cand, &rule.real_host).await {
                let ttl =
                    Duration::from_secs(self.config.anticensorship.fronting_probe_ttl_secs.max(1));
                self.fronting_v2.cache.lock().insert(
                    target_host.to_owned(),
                    FrontingCacheEntry {
                        front_domain: cand.clone(),
                        expires_at: now + ttl,
                    },
                );
                return Some(cand.clone());
            }
        }
        None
    }

    async fn probe_front_domain(&self, front_domain: &str, real_host: &str) -> bool {
        let Ok(host_header) = HeaderValue::from_str(real_host) else {
            return false;
        };
        let url = format!("https://{front_domain}/");
        let req = self.client_plain.head(url).header(HOST, host_header);

        let timeout = Duration::from_secs(
            self.config
                .anticensorship
                .fronting_probe_timeout_secs
                .max(1),
        );
        match tokio::time::timeout(timeout, req.send()).await {
            Ok(Ok(resp)) => resp.status().as_u16() < 500,
            _ => false,
        }
    }

    #[cfg_attr(feature = "observability", tracing::instrument(skip_all, fields(url = %request.url, method = ?request.method)))]
    /// Executes an HTTP request and returns the full response in memory.
    ///
    /// If `progress` is provided, it is called with progress updates (best-effort).
    ///
    /// # Errors
    ///
    /// Returns `Err` on invalid input, HTTP/TLS errors, or when chunked mode is selected but required
    /// response metadata is missing.
    pub async fn fetch(
        &self,
        mut request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        let started_total = Instant::now();
        self.validate_request(&request)?;
        #[cfg(feature = "observability")]
        tracing::debug!(url = %request.url, method = ?request.method, "http fetch start");
        self.inject_default_headers(&mut request);
        match self.apply_privacy_middleware(&mut request)? {
            PrivacyInterception::None => {}
            PrivacyInterception::Empty200 => {
                #[cfg(feature = "observability")]
                record_http_metrics(started_total, true);
                return Ok(Self::empty_response_data());
            }
        }
        self.apply_fronting_v2_if_enabled(&mut request).await?;

        let parsed = Url::parse(&request.url)?;
        let host = parsed.host_str().map(|v| v.to_ascii_lowercase());

        // Explicit DNS resolve via configured chain (best-effort): this avoids leaking to system DNS
        // when DoH is available, and provides a controlled fallback order.
        if let Some(h) = host.as_deref() {
            let _ = self.resolver_chain.resolve(h).await;
        }

        let evasion = self.effective_evasion_strategy();
        match evasion {
            Some(EvasionStrategy::Desync)
                if parsed.scheme() == "https" || parsed.scheme() == "http" =>
            {
                let res = self
                    .fetch_desync_http1(&parsed, request.clone(), progress.clone())
                    .await;
                match res {
                    Ok(v) => {
                        #[cfg(feature = "observability")]
                        record_http_metrics(started_total, true);
                        return Ok(v);
                    }
                    Err(e) => {
                        if matches!(&e, EngineError::Config(msg) if msg.contains("fragment/desync path only supports proxy.kind=socks5"))
                        {
                            tracing::warn!("desync path not applicable for current proxy settings; falling back to standard HTTP client: {e}");
                        } else {
                            #[cfg(feature = "observability")]
                            record_http_metrics(started_total, false);
                            return Err(e);
                        }
                    }
                }
            }
            Some(EvasionStrategy::Fragment)
                if parsed.scheme() == "https" || parsed.scheme() == "http" =>
            {
                let res = self
                    .fetch_fragmented_http1(&parsed, request.clone(), progress.clone())
                    .await;
                match res {
                    Ok(v) => {
                        #[cfg(feature = "observability")]
                        record_http_metrics(started_total, true);
                        return Ok(v);
                    }
                    Err(e) => {
                        if matches!(&e, EngineError::Config(msg) if msg.contains("fragment/desync path only supports proxy.kind=socks5"))
                        {
                            tracing::warn!("fragment path not applicable for current proxy settings; falling back to standard HTTP client: {e}");
                        } else {
                            #[cfg(feature = "observability")]
                            record_http_metrics(started_total, false);
                            return Err(e);
                        }
                    }
                }
            }
            _ => {}
        }

        if self.config.transport.prefer_http3
            && !matches!(
                evasion,
                Some(EvasionStrategy::Fragment | EvasionStrategy::Desync)
            )
            && parsed.scheme() == "https"
            && self.config.proxy.is_none()
        {
            // Best-effort: try HTTP/3 first, then fall back to the existing stack.
            match self.fetch_http3(request.clone(), progress.clone()).await {
                Ok(v) => {
                    #[cfg(feature = "observability")]
                    record_http_metrics(started_total, true);
                    return Ok(v);
                }
                Err(e) if self.config.transport.http3_only => {
                    #[cfg(feature = "observability")]
                    record_http_metrics(started_total, false);
                    return Err(e);
                }
                Err(_) => {}
            }
        }

        let (primary_client, used_ech) = self.select_client_for_host(host.as_deref()).await;
        let request_for_fragment = request.clone();
        let res = if used_ech {
            let request_plain = request.clone();
            match self
                .fetch_with_client(&primary_client, request, progress.clone())
                .await
            {
                Ok(v) => Ok(v),
                Err(e) if should_fallback_from_ech(&e) => {
                    self.fetch_with_client(&self.client_plain, request_plain, progress.clone())
                        .await
                }
                Err(e) => Err(e),
            }
        } else {
            self.fetch_with_client(&primary_client, request, progress.clone())
                .await
        };

        // Circuit-breaker: if the connection was reset (common DPI behavior), retry once using the
        // fragment strategy (userspace) even if evasion was not explicitly enabled.
        let res = match res {
            Ok(v) => Ok(v),
            Err(e) => {
                if self.should_try_fragment_fallback(&parsed, &e) {
                    self.fetch_fragment_fallback(&parsed, request_for_fragment, progress)
                        .await
                } else {
                    Err(e)
                }
            }
        };

        #[cfg(feature = "observability")]
        record_http_metrics(started_total, res.is_ok());
        res
    }

    #[cfg_attr(feature = "observability", tracing::instrument(skip_all, fields(url = %req.url, method = ?req.method)))]
    /// Executes an HTTP request and returns a streaming response body.
    ///
    /// This avoids buffering the whole payload in memory and is suitable for large downloads.
    pub async fn fetch_stream(&self, mut req: RequestData) -> Result<ResponseStream> {
        let conn = self.connection_tracker.as_ref().map(|tracker| {
            let id = tracker.next_connection_id();
            tracker.begin(id, req.url.clone());
            (tracker, id)
        });
        if let Some((tracker, id)) = conn.as_ref() {
            tracker.update_status(*id, ConnectionStatus::Connecting);
        }

        self.validate_request(&req)?;
        self.inject_default_headers(&mut req);
        match self.apply_privacy_middleware(&mut req) {
            Ok(PrivacyInterception::None) => {
                if self.privacy_filter_active() {
                    if let Some((tracker, id)) = conn.as_ref() {
                        tracker.mark_privacy(*id, false);
                    }
                }
            }
            Ok(PrivacyInterception::Empty200) => {
                if let Some((tracker, id)) = conn.as_ref() {
                    tracker.mark_privacy(*id, true);
                    tracker.update_status(*id, ConnectionStatus::Completed);
                }
                return Ok(Self::empty_response_stream());
            }
            Err(e) => {
                if let Some((tracker, id)) = conn.as_ref() {
                    tracker.mark_privacy(*id, true);
                    tracker.fail(*id, e.to_string());
                }
                return Err(e);
            }
        }
        self.apply_fronting_v2_if_enabled(&mut req).await?;

        let parsed = Url::parse(&req.url)?;
        let host = parsed.host_str().map(|v| v.to_ascii_lowercase());

        // Best-effort DNS resolve via configured chain to avoid leaking to system DNS.
        if let Some(h) = host.as_deref() {
            if let Some((tracker, id)) = conn.as_ref() {
                tracker.update_status(*id, ConnectionStatus::Resolving);
            }
            let dns_started = Instant::now();
            if let Ok(ips) = self.resolver_chain.resolve(h).await {
                if let Some((tracker, id)) = conn.as_ref() {
                    tracker.update_dns(
                        *id,
                        DnsInfo {
                            resolver_used: "Configured chain".to_owned(),
                            resolved_ip: ips
                                .first()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| "n/a".to_owned()),
                            resolution_time_ms: dns_started.elapsed().as_millis() as u64,
                            chain: vec!["resolve".to_owned(), "success".to_owned()],
                        },
                    );
                }
            }
        }

        if let Some((tracker, id)) = conn.as_ref() {
            tracker.update_status(*id, ConnectionStatus::TlsHandshake);
            tracker.update_tls(
                *id,
                TlsInfo {
                    version: "TLS 1.3/1.2".to_owned(),
                    cipher_suite: "negotiated".to_owned(),
                    ech_status: format!("{:?}", self.config.anticensorship.effective_ech_mode()),
                    handshake_time_ms: 0,
                },
            );
        }

        let evasion = self.effective_evasion_strategy();
        match evasion {
            Some(EvasionStrategy::Desync)
                if parsed.scheme() == "https" || parsed.scheme() == "http" =>
            {
                match self.fetch_desync_http1_stream(&parsed, req.clone()).await {
                    Ok(v) => {
                        if let Some((tracker, id)) = conn.as_ref() {
                            tracker.update_status(*id, ConnectionStatus::Completed);
                        }
                        return Ok(v);
                    }
                    Err(e) => {
                        if matches!(&e, EngineError::Config(msg) if msg.contains("fragment/desync path only supports proxy.kind=socks5"))
                        {
                            tracing::warn!("desync stream path not applicable for current proxy settings; falling back to standard HTTP client: {e}");
                        } else {
                            if let Some((tracker, id)) = conn.as_ref() {
                                tracker.fail(*id, e.to_string());
                            }
                            return Err(e);
                        }
                    }
                }
            }
            Some(EvasionStrategy::Fragment)
                if parsed.scheme() == "https" || parsed.scheme() == "http" =>
            {
                match self
                    .fetch_fragmented_http1_stream(&parsed, req.clone())
                    .await
                {
                    Ok(v) => {
                        if let Some((tracker, id)) = conn.as_ref() {
                            tracker.update_status(*id, ConnectionStatus::Completed);
                        }
                        return Ok(v);
                    }
                    Err(e) => {
                        if matches!(&e, EngineError::Config(msg) if msg.contains("fragment/desync path only supports proxy.kind=socks5"))
                        {
                            tracing::warn!("fragment stream path not applicable for current proxy settings; falling back to standard HTTP client: {e}");
                        } else {
                            if let Some((tracker, id)) = conn.as_ref() {
                                tracker.fail(*id, e.to_string());
                            }
                            return Err(e);
                        }
                    }
                }
            }
            _ => {}
        }

        if self.config.transport.prefer_http3
            && !matches!(
                evasion,
                Some(EvasionStrategy::Fragment | EvasionStrategy::Desync)
            )
            && parsed.scheme() == "https"
            && self.config.proxy.is_none()
        {
            match self.fetch_http3_stream(req.clone()).await {
                Ok(v) => {
                    if let Some((tracker, id)) = conn.as_ref() {
                        tracker.update_status(*id, ConnectionStatus::Completed);
                    }
                    return Ok(v);
                }
                Err(e) if self.config.transport.http3_only => {
                    if let Some((tracker, id)) = conn.as_ref() {
                        tracker.fail(*id, e.to_string());
                    }
                    return Err(e);
                }
                Err(_) => {}
            }
        }

        if let Some((tracker, id)) = conn.as_ref() {
            tracker.update_status(*id, ConnectionStatus::Sending);
        }
        let (primary_client, used_ech) = self.select_client_for_host(host.as_deref()).await;
        let req_for_fragment = req.clone();
        let res = if used_ech {
            let req_plain = req.clone();
            match self.fetch_stream_with_client(&primary_client, req).await {
                Ok(v) => Ok(v),
                Err(e) if should_fallback_from_ech(&e) => {
                    self.fetch_stream_with_client(&self.client_plain, req_plain)
                        .await
                }
                Err(e) => Err(e),
            }
        } else {
            self.fetch_stream_with_client(&primary_client, req).await
        };

        let out = match res {
            Ok(v) => Ok(v),
            Err(e) => {
                if self.should_try_fragment_fallback(&parsed, &e) {
                    self.fetch_fragment_fallback_stream(&parsed, req_for_fragment)
                        .await
                } else {
                    Err(e)
                }
            }
        };

        match (&out, conn.as_ref()) {
            (Ok(v), Some((tracker, id))) => {
                tracker.update_status(*id, ConnectionStatus::Receiving);
                let total_bytes = v
                    .headers
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                tracker.update_download(
                    *id,
                    DownloadInfo {
                        bytes_downloaded: 0,
                        total_bytes,
                        speed_bytes_per_sec: 0.0,
                        avg_speed_bytes_per_sec: 0.0,
                    },
                );
                tracker.update_status(*id, ConnectionStatus::Completed);
            }
            (Err(e), Some((tracker, id))) => tracker.fail(*id, e.to_string()),
            _ => {}
        }

        out
    }

    fn should_try_fragment_fallback(&self, parsed: &Url, err: &EngineError) -> bool {
        if parsed.scheme() != "https" {
            return false;
        }
        if self.config.proxy.is_some() {
            return false;
        }
        if matches!(
            self.effective_evasion_strategy(),
            Some(EvasionStrategy::Fragment)
        ) {
            return false;
        }
        is_tcp_connection_reset(err)
    }

    async fn fetch_fragment_fallback(
        &self,
        _parsed: &Url,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        let mut last: Option<EngineError> = None;
        let max = self.config.evasion.rst_retry_max;
        for attempt in 0..=max {
            if attempt > 0 {
                tokio::time::sleep(retry_delay(attempt - 1)).await;
            }

            let parsed = Url::parse(&request.url)?;
            match self
                .fetch_fragmented_http1(&parsed, request.clone(), progress.clone())
                .await
            {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if !is_tcp_connection_reset(&e) {
                        return Err(e);
                    }
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| EngineError::Internal("fragment fallback failed".to_owned())))
    }

    async fn fetch_fragment_fallback_stream(
        &self,
        _parsed: &Url,
        request: RequestData,
    ) -> Result<ResponseStream> {
        let mut last: Option<EngineError> = None;
        let max = self.config.evasion.rst_retry_max;
        for attempt in 0..=max {
            if attempt > 0 {
                tokio::time::sleep(retry_delay(attempt - 1)).await;
            }

            let parsed = Url::parse(&request.url)?;
            match self
                .fetch_fragmented_http1_stream(&parsed, request.clone())
                .await
            {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if !is_tcp_connection_reset(&e) {
                        return Err(e);
                    }
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| EngineError::Internal("fragment fallback failed".to_owned())))
    }

    async fn fetch_stream_with_client(
        &self,
        client: &reqwest::Client,
        request: RequestData,
    ) -> Result<ResponseStream> {
        use std::io;

        let RequestData {
            url,
            method,
            headers,
            body,
        } = request;
        let headers_map = build_headers(&headers)?;

        let max_retries = self.config.download.max_retries;
        let should_retry = method == Method::GET && body.is_empty();

        let response = if should_retry {
            self.send_with_retry(max_retries, || {
                client
                    .request(method.clone(), &url)
                    .headers(headers_map.clone())
            })
            .await?
        } else {
            client
                .request(method.clone(), &url)
                .headers(headers_map.clone())
                .body(body)
                .send()
                .await?
        };

        let response = response.error_for_status()?;
        let status = response.status();
        let headers = response.headers().clone();
        let body_stream = response.bytes_stream().map_err(io::Error::other);
        let reader = StreamReader::new(body_stream);
        Ok(ResponseStream {
            status,
            headers,
            stream: Box::new(reader),
        })
    }

    async fn fetch_with_client(
        &self,
        client: &reqwest::Client,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        if self.can_use_chunked(client, &request).await? {
            return self.fetch_chunked(client, request, progress).await;
        }
        self.fetch_single(client, request, progress).await
    }

    async fn select_client_for_host(&self, host: Option<&str>) -> (reqwest::Client, bool) {
        let Some(mode) = self.config.anticensorship.effective_ech_mode() else {
            return (self.client_plain.clone(), false);
        };

        let Some(host) = host else {
            return match (mode, &self.client_ech_grease) {
                (EchMode::Grease, Some(c)) | (EchMode::Auto, Some(c)) => (c.clone(), true),
                _ => (self.client_plain.clone(), false),
            };
        };

        match mode {
            EchMode::Grease => {
                if let Some(c) = &self.client_ech_grease {
                    return (c.clone(), true);
                }
                (self.client_plain.clone(), false)
            }
            EchMode::Real => {
                if let Some(c) = self.get_or_build_ech_real_client(host).await {
                    return (c, true);
                }
                (self.client_plain.clone(), false)
            }
            EchMode::Auto => {
                if let Some(c) = self.get_or_build_ech_real_client(host).await {
                    return (c, true);
                }
                if let Some(c) = &self.client_ech_grease {
                    return (c.clone(), true);
                }
                (self.client_plain.clone(), false)
            }
        }
    }

    async fn get_or_build_ech_real_client(&self, host: &str) -> Option<reqwest::Client> {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        if let Some(existing) = self.client_ech_real_cache.lock().get(&host).cloned() {
            return Some(existing);
        }

        // Best-effort: no panic, and allow fallback to plain if anything fails.
        let ech_list: Option<Vec<u8>> = self
            .resolver_chain
            .lookup_ech_config_list(&host)
            .await
            .unwrap_or_default();
        let ech_list = ech_list?;

        let ech_config = match build_rustls_ech_config(&ech_list) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let tls = match build_rustls_client_config(
            &self.config,
            Some(rustls::client::EchMode::Enable(ech_config)),
        ) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let pool = ConnectionPoolConfig {
            max_idle_per_host: self.config.download.max_idle_per_host,
            idle_timeout_secs: self.config.download.pool_idle_timeout_secs,
        };
        let client = match build_reqwest_client(&self.config, &pool, self.dns_resolver.clone(), tls)
        {
            Ok(v) => v,
            Err(_) => return None,
        };

        self.client_ech_real_cache
            .lock()
            .insert(host, client.clone());
        Some(client)
    }

    fn effective_evasion_strategy(&self) -> Option<EvasionStrategy> {
        match self.config.evasion.strategy.clone() {
            Some(EvasionStrategy::Auto) => {
                if !self.config.evasion.client_hello_split_offsets.is_empty() {
                    Some(EvasionStrategy::Desync)
                } else {
                    Some(EvasionStrategy::Fragment)
                }
            }
            other => other,
        }
    }

    fn apply_traffic_shaping_to_fragment_cfg(&self, cfg: &mut FragmentConfig) {
        if !self.config.evasion.traffic_shaping_enabled {
            return;
        }
        cfg.jitter_ms = Some((
            self.config.evasion.timing_jitter_ms_min,
            self.config.evasion.timing_jitter_ms_max,
        ));
        cfg.randomize_fragment_size = true;
    }

    fn fragment_cfg_fragment(&self) -> FragmentConfig {
        let mut cfg = FragmentConfig {
            first_write_max: 64,
            first_write_plan: None,
            fragment_size: self.config.evasion.fragment_size.max(1),
            sleep_ms: self.config.evasion.fragment_sleep_ms,
            jitter_ms: None,
            randomize_fragment_size: false,
            split_at_sni: false,
        };
        self.apply_traffic_shaping_to_fragment_cfg(&mut cfg);
        cfg
    }

    fn fragment_cfg_desync(&self) -> FragmentConfig {
        let mut sizes: Vec<usize> = Vec::new();
        let mut prev = 0usize;
        for &off in &self.config.evasion.client_hello_split_offsets {
            if off > prev {
                sizes.push(off - prev);
                prev = off;
            }
        }
        if sizes.len() < 3 {
            sizes = vec![1, 1, 1];
        }

        let mut cfg = FragmentConfig {
            first_write_max: 64,
            first_write_plan: Some(sizes),
            fragment_size: self.config.evasion.fragment_size.max(1),
            sleep_ms: self.config.evasion.fragment_sleep_ms,
            jitter_ms: None,
            randomize_fragment_size: false,
            split_at_sni: self.config.evasion.split_at_sni,
        };
        self.apply_traffic_shaping_to_fragment_cfg(&mut cfg);
        cfg
    }

    async fn build_rustls_client_config_fragmented(
        &self,
        host: &str,
    ) -> Result<rustls::ClientConfig> {
        // Fragment path uses a dedicated rustls ClientConfig so we can keep ECH behavior consistent
        // while allowing ALPN to negotiate h2 vs http/1.1 (we support both now).
        let cfg = self.config.clone();

        let Some(mode) = cfg.anticensorship.effective_ech_mode() else {
            let mut tls = build_rustls_client_config(&cfg, None)?;
            if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                tls.max_fragment_size = Some(v);
            }
            return Ok(tls);
        };

        match mode {
            EchMode::Grease => {
                let mut tls = build_rustls_client_config(&cfg, Some(build_ech_grease_mode()?))?;
                if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                    tls.max_fragment_size = Some(v);
                }
                Ok(tls)
            }
            EchMode::Real => {
                if host.parse::<std::net::IpAddr>().is_ok() {
                    let mut tls = build_rustls_client_config(&cfg, None)?;
                    if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                        tls.max_fragment_size = Some(v);
                    }
                    return Ok(tls);
                }
                let ech_list = self.resolver_chain.lookup_ech_config_list(host).await?;
                let Some(ech_list) = ech_list else {
                    let mut tls = build_rustls_client_config(&cfg, None)?;
                    if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                        tls.max_fragment_size = Some(v);
                    }
                    return Ok(tls);
                };
                let ech = build_rustls_ech_config(&ech_list)
                    .map_err(|e| EngineError::Internal(format!("ECH config parse failed: {e}")))?;
                let mut tls =
                    build_rustls_client_config(&cfg, Some(rustls::client::EchMode::Enable(ech)))?;
                if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                    tls.max_fragment_size = Some(v);
                }
                Ok(tls)
            }
            EchMode::Auto => {
                if host.parse::<std::net::IpAddr>().is_ok() {
                    let mut tls = build_rustls_client_config(&cfg, Some(build_ech_grease_mode()?))?;
                    if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                        tls.max_fragment_size = Some(v);
                    }
                    return Ok(tls);
                }
                if let Some(ech_list) = self.resolver_chain.lookup_ech_config_list(host).await? {
                    if let Ok(ech) = build_rustls_ech_config(&ech_list) {
                        if let Ok(tls) = build_rustls_client_config(
                            &cfg,
                            Some(rustls::client::EchMode::Enable(ech)),
                        ) {
                            let mut tls = tls;
                            if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                                tls.max_fragment_size = Some(v);
                            }
                            return Ok(tls);
                        }
                    }
                }
                let mut tls = build_rustls_client_config(&cfg, Some(build_ech_grease_mode()?))?;
                if let Some(v) = self.config.evasion.tls_record_max_fragment_size {
                    tls.max_fragment_size = Some(v);
                }
                Ok(tls)
            }
        }
    }

    fn url_path_and_query(parsed: &Url) -> String {
        let mut path = parsed.path().to_owned();
        if path.is_empty() {
            path = "/".to_owned();
        }
        if let Some(q) = parsed.query() {
            path.push('?');
            path.push_str(q);
        }
        path
    }

    async fn fragmented_send(
        &self,
        parsed: &Url,
        request: &RequestData,
        fragment_cfg: FragmentConfig,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        use hyper_util::rt::TokioExecutor;

        let host = parsed
            .host_str()
            .ok_or_else(|| EngineError::InvalidInput("url host is missing".to_owned()))?
            .to_owned();
        let scheme = parsed.scheme().to_ascii_lowercase();
        let port = parsed.port_or_known_default().ok_or_else(|| {
            EngineError::InvalidInput(format!(
                "unknown default port for scheme {}",
                parsed.scheme()
            ))
        })?;

        let addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            std::net::SocketAddr::new(ip, port)
        } else {
            let ips = self.resolver_chain.resolve(&host).await?;
            let ip = *ips.first().ok_or_else(|| {
                EngineError::Internal(format!("dns resolver returned no IPs for '{host}'"))
            })?;
            std::net::SocketAddr::new(ip, port)
        };

        let tcp = if let Some(proxy) = &self.config.proxy {
            match proxy.kind {
                crate::config::ProxyKind::Socks5 => {
                    Self::connect_via_socks5(&proxy.address, &host, port).await?
                }
                _ => {
                    return Err(EngineError::Config(
                        "fragment/desync path only supports proxy.kind=socks5".to_owned(),
                    ));
                }
            }
        } else {
            TcpStream::connect(addr).await?
        };
        let _ = tcp.set_nodelay(true);

        let (io, handle) = FragmentingIo::new(tcp, fragment_cfg);
        type BoxedIo = Pin<Box<dyn AsyncIo + Send>>;
        let (io, alpn) = match scheme.as_str() {
            "https" => {
                let tls_cfg = self.build_rustls_client_config_fragmented(&host).await?;
                let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_cfg));

                let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                    .map_err(|_| EngineError::InvalidInput(format!("invalid SNI host '{host}'")))?;

                let tls = connector.connect(server_name, io).await?;
                let alpn = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|p| p.to_vec())
                    .unwrap_or_default();
                handle.disable(); // avoid fragmenting application data; keep it during handshake only.
                (TokioIo::new(Box::pin(tls) as BoxedIo), alpn)
            }
            "http" => (TokioIo::new(Box::pin(io) as BoxedIo), Vec::new()),
            _ => {
                return Err(EngineError::InvalidInput(
                    "fragment/desync path only supports http:// and https://".to_owned(),
                ));
            }
        };
        let path = Self::url_path_and_query(parsed);

        let mut headers_map = build_headers(&request.headers)?;
        if !headers_map.contains_key(HOST) {
            headers_map.insert(HOST, HeaderValue::from_str(&host)?);
        }

        let uri = if alpn.as_slice() == b"h2" {
            let scheme = "https";
            let authority = match (host.parse::<std::net::IpAddr>(), port) {
                (Ok(std::net::IpAddr::V6(_)), 443) => format!("[{host}]"),
                (Ok(std::net::IpAddr::V6(_)), _) => format!("[{host}]:{port}"),
                (_, 443) => host.clone(),
                _ => format!("{host}:{port}"),
            };
            http::Uri::builder()
                .scheme(scheme)
                .authority(authority.as_str())
                .path_and_query(path.as_str())
                .build()
                .map_err(|e| {
                    EngineError::InvalidInput(format!("invalid url for h2 request: {e}"))
                })?
        } else {
            path.parse::<http::Uri>().map_err(|e| {
                EngineError::InvalidInput(format!("invalid path for h1 request: {e}"))
            })?
        };

        let mut builder = hyper::Request::builder()
            .method(request.method.clone())
            .uri(uri);
        for (k, v) in headers_map.iter() {
            builder = builder.header(k, v);
        }

        let body = Full::new(Bytes::from(request.body.clone()));
        let req = builder
            .body(body)
            .map_err(|e| EngineError::Internal(format!("failed to build request: {e}")))?;

        if scheme == "https" && alpn.as_slice() == b"h2" {
            let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(io)
                .await
                .map_err(|e| EngineError::Internal(format!("hyper h2 handshake failed: {e}")))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender
                .send_request(req)
                .await
                .map_err(|e| EngineError::Internal(format!("request failed: {e}")))
        } else {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| EngineError::Internal(format!("hyper h1 handshake failed: {e}")))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let res = sender
                .send_request(req)
                .await
                .map_err(|e| EngineError::Internal(format!("request failed: {e}")))?;
            // Best-effort: disable further write fragmentation after the request is sent.
            if scheme == "http" {
                handle.disable();
            }
            Ok(res)
        }
    }

    async fn connect_via_socks5(proxy_addr: &str, host: &str, port: u16) -> Result<TcpStream> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        fn normalize_proxy_host_port(
            s: &str,
        ) -> Result<(String, u16, Option<String>, Option<String>)> {
            let s = s.trim();
            if s.is_empty() {
                return Err(EngineError::Config("proxy.address is empty".to_owned()));
            }

            if s.contains("://") {
                let url = Url::parse(s)?;
                let user = if !url.username().is_empty() {
                    Some(url.username().to_owned())
                } else {
                    None
                };
                let pass = url.password().map(|v| v.to_owned());
                let host = url.host_str().ok_or_else(|| {
                    EngineError::Config("proxy.address URL missing host".to_owned())
                })?;
                let port = url.port_or_known_default().ok_or_else(|| {
                    EngineError::Config("proxy.address URL missing port".to_owned())
                })?;
                return Ok((host.to_owned(), port, user, pass));
            }

            if let Some((h, p)) = s.rsplit_once(':') {
                let mut host = h.trim().to_owned();
                if host.starts_with('[') {
                    if !host.ends_with(']') {
                        return Err(EngineError::Config(
                            "proxy.address IPv6 must be in the form '[::1]:port'".to_owned(),
                        ));
                    }
                    host = host[1..host.len() - 1].to_owned();
                } else if host.contains(':') {
                    // Likely an IPv6 literal without brackets.
                    return Err(EngineError::Config(
                        "proxy.address IPv6 must be in the form '[::1]:port'".to_owned(),
                    ));
                }
                if host.is_empty() {
                    return Err(EngineError::Config("proxy.address missing host".to_owned()));
                }

                // Support "user:pass@host:port" without a URL scheme (common in config files).
                let (user, pass, host) = if let Some((ui, h2)) = host.rsplit_once('@') {
                    let ui = ui.trim();
                    let h2 = h2.trim();
                    if ui.is_empty() || h2.is_empty() {
                        return Err(EngineError::Config(
                            "proxy.address has invalid credentials syntax".to_owned(),
                        ));
                    }
                    let (u, p) = ui.split_once(':').unwrap_or((ui, ""));
                    (Some(u.to_owned()), Some(p.to_owned()), h2.to_owned())
                } else {
                    (None, None, host)
                };

                let p = p.parse::<u16>().map_err(|_| {
                    EngineError::Config("proxy.address has invalid port".to_owned())
                })?;
                return Ok((host, p, user, pass));
            }

            Err(EngineError::Config(
                "proxy.address must be 'host:port' (or a URL)".to_owned(),
            ))
        }

        let (proxy_host, proxy_port, proxy_user, proxy_pass) =
            normalize_proxy_host_port(proxy_addr)?;
        let mut tcp = TcpStream::connect((proxy_host.as_str(), proxy_port)).await?;
        let _ = tcp.set_nodelay(true);

        let has_creds = proxy_user.is_some();

        // Greeting: VER=5, NMETHODS, METHODS=[USERPASS?, NOAUTH]
        if has_creds {
            tcp.write_all(&[0x05, 0x02, 0x02, 0x00]).await?;
        } else {
            tcp.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut resp = [0u8; 2];
        tcp.read_exact(&mut resp).await?;
        if resp[0] != 0x05 {
            return Err(EngineError::Internal(
                "SOCKS5 invalid reply version".to_owned(),
            ));
        }
        match resp[1] {
            0x00 => {} // NOAUTH
            0x02 => {
                // RFC1929 username/password auth.
                let user = proxy_user.unwrap_or_default();
                let pass = proxy_pass.unwrap_or_default();
                let ub = user.as_bytes();
                let pb = pass.as_bytes();
                if ub.len() > 255 || pb.len() > 255 {
                    return Err(EngineError::InvalidInput(
                        "SOCKS5 username/password is too long".to_owned(),
                    ));
                }
                let mut auth = Vec::with_capacity(3 + ub.len() + pb.len());
                auth.push(0x01); // auth version
                auth.push(ub.len() as u8);
                auth.extend_from_slice(ub);
                auth.push(pb.len() as u8);
                auth.extend_from_slice(pb);
                tcp.write_all(&auth).await?;

                let mut aresp = [0u8; 2];
                tcp.read_exact(&mut aresp).await?;
                if aresp[0] != 0x01 || aresp[1] != 0x00 {
                    return Err(EngineError::Internal(
                        "SOCKS5 username/password auth failed".to_owned(),
                    ));
                }
            }
            0xFF => {
                return Err(EngineError::Internal(
                    "SOCKS5 proxy has no acceptable auth methods".to_owned(),
                ));
            }
            other => {
                return Err(EngineError::Internal(format!(
                    "SOCKS5 proxy selected unsupported auth method 0x{other:02x}"
                )));
            }
        }

        // CONNECT request.
        let mut req = Vec::with_capacity(4 + 1 + host.len() + 2);
        req.push(0x05); // VER
        req.push(0x01); // CMD=CONNECT
        req.push(0x00); // RSV

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    req.push(0x01);
                    req.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    req.push(0x04);
                    req.extend_from_slice(&v6.octets());
                }
            }
        } else {
            let hb = host.as_bytes();
            if hb.len() > 255 {
                return Err(EngineError::InvalidInput(
                    "SOCKS5 host is too long".to_owned(),
                ));
            }
            req.push(0x03);
            req.push(hb.len() as u8);
            req.extend_from_slice(hb);
        }
        req.extend_from_slice(&port.to_be_bytes());

        tcp.write_all(&req).await?;

        // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
        let mut hdr = [0u8; 4];
        tcp.read_exact(&mut hdr).await?;
        if hdr[0] != 0x05 {
            return Err(EngineError::Internal(
                "SOCKS5 invalid reply version".to_owned(),
            ));
        }
        if hdr[1] != 0x00 {
            return Err(EngineError::Internal(format!(
                "SOCKS5 connect failed (REP=0x{:02x})",
                hdr[1]
            )));
        }

        match hdr[3] {
            0x01 => {
                let mut b = [0u8; 4 + 2];
                tcp.read_exact(&mut b).await?;
            }
            0x03 => {
                let mut lenb = [0u8; 1];
                tcp.read_exact(&mut lenb).await?;
                let len = lenb[0] as usize;
                let mut b = vec![0u8; len + 2];
                tcp.read_exact(&mut b).await?;
            }
            0x04 => {
                let mut b = [0u8; 16 + 2];
                tcp.read_exact(&mut b).await?;
            }
            other => {
                return Err(EngineError::Internal(format!(
                    "SOCKS5 invalid reply address type 0x{other:02x}"
                )));
            }
        }

        Ok(tcp)
    }

    async fn fetch_fragmented_http1(
        &self,
        parsed: &Url,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        self.fetch_fragmented_http1_with_cfg(
            parsed,
            request,
            progress,
            self.fragment_cfg_fragment(),
        )
        .await
    }

    async fn fetch_desync_http1(
        &self,
        parsed: &Url,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        self.fetch_fragmented_http1_with_cfg(parsed, request, progress, self.fragment_cfg_desync())
            .await
    }

    async fn fetch_fragmented_http1_with_cfg(
        &self,
        parsed: &Url,
        request: RequestData,
        progress: Option<ProgressHook>,
        fragment_cfg: FragmentConfig,
    ) -> Result<ResponseData> {
        let started = Instant::now();
        let resp = self.fragmented_send(parsed, &request, fragment_cfg).await?;

        let status_code = resp.status().as_u16();
        if !(200..400).contains(&status_code) {
            return Err(EngineError::Internal(format!(
                "http error status {status_code} (url='{}')",
                request.url
            )));
        }

        let headers = collect_headers(resp.headers());
        let total_opt = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame =
                frame.map_err(|e| EngineError::Internal(format!("body read failed: {e}")))?;
            if let Ok(data) = frame.into_data() {
                out.extend_from_slice(&data);
                if let Some(cb) = &progress {
                    let downloaded = out.len() as u64;
                    let total = total_opt.unwrap_or(0);
                    let elapsed = started.elapsed().as_secs_f64().max(0.001);
                    let speed_mbps = (downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                    cb(downloaded, total, speed_mbps);
                }
            }
        }

        if let Some(cb) = progress {
            let downloaded = out.len() as u64;
            let total = total_opt.unwrap_or(downloaded);
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            let speed_mbps = (downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
            cb(downloaded, total, speed_mbps);
        }

        Ok(ResponseData {
            status_code,
            headers,
            body: out,
        })
    }

    async fn fetch_fragmented_http1_stream(
        &self,
        parsed: &Url,
        request: RequestData,
    ) -> Result<ResponseStream> {
        self.fetch_fragmented_http1_stream_with_cfg(parsed, request, self.fragment_cfg_fragment())
            .await
    }

    async fn fetch_desync_http1_stream(
        &self,
        parsed: &Url,
        request: RequestData,
    ) -> Result<ResponseStream> {
        self.fetch_fragmented_http1_stream_with_cfg(parsed, request, self.fragment_cfg_desync())
            .await
    }

    async fn fetch_fragmented_http1_stream_with_cfg(
        &self,
        parsed: &Url,
        request: RequestData,
        fragment_cfg: FragmentConfig,
    ) -> Result<ResponseStream> {
        use std::io;

        let resp = self.fragmented_send(parsed, &request, fragment_cfg).await?;
        let status = resp.status();
        let status_u16 = status.as_u16();
        if !(200..400).contains(&status_u16) {
            return Err(EngineError::Internal(format!(
                "http error status {status_u16} (url='{}')",
                request.url
            )));
        }

        let headers = resp.headers().clone();
        let body_stream = resp
            .into_body()
            .into_data_stream()
            .map_err(io::Error::other);
        let reader = StreamReader::new(body_stream);
        Ok(ResponseStream {
            status,
            headers,
            stream: Box::new(reader),
        })
    }

    /// Downloads the response body to `path` without buffering the whole payload in memory.
    ///
    /// If the server supports ranged requests, the engine will attempt an adaptive chunked download and
    /// will also resume from existing partial data (best-effort).
    pub async fn download_to_path(
        &self,
        mut request: RequestData,
        path: impl AsRef<Path>,
        progress: Option<ProgressHook>,
    ) -> Result<DownloadOutcome> {
        self.validate_request(&request)?;
        if request.method != Method::GET {
            return Err(EngineError::InvalidInput(
                "download_to_path only supports GET requests".to_owned(),
            ));
        }
        if !request.body.is_empty() {
            return Err(EngineError::InvalidInput(
                "download_to_path does not support non-empty request bodies".to_owned(),
            ));
        }

        self.inject_default_headers(&mut request);
        match self.apply_privacy_middleware(&mut request)? {
            PrivacyInterception::None => {}
            PrivacyInterception::Empty200 => {
                return self.empty_download_outcome(path.as_ref()).await;
            }
        }
        self.apply_fronting_v2_if_enabled(&mut request).await?;

        let parsed = Url::parse(&request.url)?;
        let host = parsed.host_str().map(|v| v.to_ascii_lowercase());
        if let Some(h) = host.as_deref() {
            let _ = self.resolver_chain.resolve(h).await;
        }

        let path = path.as_ref().to_path_buf();
        let request_for_fragment = request.clone();
        let res = self
            .download_to_path_inner(request, &path, host.as_deref(), progress.clone())
            .await;

        match res {
            Ok(v) => Ok(v),
            Err(e) => {
                if self.should_try_fragment_fallback(&parsed, &e) {
                    self.download_to_path_fragment_fallback(request_for_fragment, &path, progress)
                        .await
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn download_to_path_inner(
        &self,
        request: RequestData,
        path: &Path,
        host: Option<&str>,
        progress: Option<ProgressHook>,
    ) -> Result<DownloadOutcome> {
        let (primary_client, used_ech) = self.select_client_for_host(host).await;
        let mut client: &reqwest::Client = &primary_client;

        let path = path.to_path_buf();
        let headers_map = build_headers(&request.headers)?;

        // Probe server metadata: prefer HEAD but fall back to a tiny Range GET if needed.
        let max_retries = self.config.download.max_retries;
        let head_res = self
            .send_with_retry(max_retries, || {
                client.head(&request.url).headers(headers_map.clone())
            })
            .await;

        let probe = match head_res {
            Ok(r) => r,
            Err(e) if used_ech && should_fallback_from_ech(&e) => {
                client = &self.client_plain;
                // Retry probe on plain transport.
                let head_res = self
                    .send_with_retry(max_retries, || {
                        client.head(&request.url).headers(headers_map.clone())
                    })
                    .await;
                match head_res {
                    Ok(r) => r,
                    Err(_) => {
                        let mut h = headers_map.clone();
                        h.insert(RANGE, HeaderValue::from_static("bytes=0-0"));
                        self.send_with_retry(max_retries, || {
                            client.get(&request.url).headers(h.clone())
                        })
                        .await?
                    }
                }
            }
            Err(_) => {
                let mut h = headers_map.clone();
                h.insert(RANGE, HeaderValue::from_static("bytes=0-0"));
                self.send_with_retry(max_retries, || client.get(&request.url).headers(h.clone()))
                    .await?
            }
        };

        // Extract content length and range support.
        let status_code = probe.status().as_u16();
        let probe_headers = collect_headers(probe.headers());
        let mut content_length = probe
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        // If we probed using Range GET, Content-Length is "1", so prefer parsing Content-Range.
        if let Some(total) = parse_total_length_from_content_range(probe.headers()) {
            content_length = Some(total);
        }

        let _supports_ranges_header = probe
            .headers()
            .get(reqwest::header::ACCEPT_RANGES)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("bytes"))
            .unwrap_or(false);

        // If we used a range GET probe and the server honored it, consuming the tiny body avoids an
        // HTTP/2 RST_STREAM on drop.
        if status_code == 206 && probe.content_length().unwrap_or(0) <= 1024 {
            let _permit =
                match &self.h2_reset_limiter {
                    Some(s) => Some(s.clone().acquire_owned().await.map_err(|_| {
                        EngineError::Internal("h2 reset limiter closed".to_owned())
                    })?),
                    None => None,
                };
            let _ = probe.bytes().await;
        }

        // Confirm the server actually honors Range requests (HEAD can lie).
        let supports_ranges = self
            .probe_range_support(client, &request, &headers_map)
            .await
            .unwrap_or(false);

        // Fast-path: if we know the expected size and the target already exists and matches, skip.
        if let (Some(expected), Ok(meta)) = (content_length, std::fs::metadata(&path)) {
            if meta.is_file() && meta.len() == expected {
                self.verify_download_integrity_if_configured(&path).await?;
                return Ok(DownloadOutcome {
                    status_code,
                    headers: probe_headers,
                    bytes_written: expected,
                    resumed: true,
                    chunked: false,
                    path,
                });
            }
        }

        let chunk_threshold = (self.config.download.chunk_size_mb as u64) * 1024 * 1024;
        let can_chunk = supports_ranges
            && content_length.is_some()
            && content_length.unwrap_or(0) >= chunk_threshold;

        let (bytes_written, resumed, chunked) = if can_chunk {
            let total = content_length.unwrap_or(0);
            let (written, resumed) = self
                .download_chunked_to_parts(
                    client,
                    &request,
                    &headers_map,
                    total,
                    &path,
                    progress.clone(),
                )
                .await?;
            (written, resumed, true)
        } else {
            let (written, resumed) = self
                .download_single_to_file(
                    client,
                    &request,
                    &headers_map,
                    content_length,
                    &path,
                    supports_ranges,
                    progress.clone(),
                )
                .await?;
            (written, resumed, false)
        };

        self.verify_download_integrity_if_configured(&path).await?;
        Ok(DownloadOutcome {
            status_code,
            headers: probe_headers,
            bytes_written,
            resumed,
            chunked,
            path,
        })
    }

    async fn download_to_path_fragment_fallback(
        &self,
        request: RequestData,
        path: &Path,
        progress: Option<ProgressHook>,
    ) -> Result<DownloadOutcome> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let parsed = Url::parse(&request.url)?;
        if parsed.scheme() != "https" {
            return Err(EngineError::InvalidInput(
                "fragment fallback download only supports https://".to_owned(),
            ));
        }

        let started = Instant::now();
        let resp = self
            .fetch_fragment_fallback_stream(&parsed, request.clone())
            .await?;
        let ResponseStream {
            status,
            headers,
            mut stream,
        } = resp;

        let status_code = status.as_u16();
        if !(200..400).contains(&status_code) {
            return Err(EngineError::Internal(format!(
                "http error status {status_code} (url='{}')",
                request.url
            )));
        }

        let total_opt = headers
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let tmp_path: PathBuf = PathBuf::from(format!("{}.prime.tmp", path.to_string_lossy()));
        let mut out = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .await?;

        let mut buf = vec![0u8; 64 * 1024];
        let mut written: u64 = 0;
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).await?;
            written += n as u64;
            if let Some(cb) = &progress {
                let total = total_opt.unwrap_or(0);
                let elapsed = started.elapsed().as_secs_f64().max(0.001);
                let speed_mbps = (written as f64 * 8.0 / 1_000_000.0) / elapsed;
                cb(written, total, speed_mbps);
            }
        }
        out.flush().await?;
        drop(out);

        if let Ok(meta) = tokio::fs::metadata(path).await {
            if meta.is_file() {
                let _ = tokio::fs::remove_file(path).await;
            }
        }
        tokio::fs::rename(&tmp_path, path).await?;
        self.verify_download_integrity_if_configured(path).await?;

        Ok(DownloadOutcome {
            status_code,
            headers: collect_headers(&headers),
            bytes_written: written,
            resumed: false,
            chunked: false,
            path: path.to_path_buf(),
        })
    }

    fn validate_request(&self, request: &RequestData) -> Result<()> {
        if request.url.trim().is_empty() {
            return Err(EngineError::InvalidInput("url is empty".to_owned()));
        }
        let parsed = Url::parse(&request.url)?;
        match parsed.scheme() {
            "http" | "https" => Ok(()),
            _ => Err(EngineError::InvalidInput(
                "only HTTP/HTTPS schemes are supported".to_owned(),
            )),
        }
    }

    fn apply_privacy_middleware(&self, request: &mut RequestData) -> Result<PrivacyInterception> {
        let parsed = Url::parse(&request.url)?;
        let mut interception = PrivacyInterception::None;

        let referer_decision =
            apply_referer_policy(&parsed, &mut request.headers, &self.config.privacy.referer);
        if !matches!(referer_decision, RefererDecision::Kept) {
            tracing::info!(
                target: "privacy.referer",
                "[PRIVACY] referer policy applied: {:?} for {}",
                referer_decision,
                request.url
            );
        }

        if apply_signals(&mut request.headers, &self.config.privacy.signals) {
            tracing::debug!(
                target: "privacy.signals",
                "[PRIVACY] privacy signals injected (DNT={}, GPC={})",
                self.config.privacy.signals.send_dnt,
                self.config.privacy.signals.send_gpc
            );
        }

        if let Some(blocker) = &self.tracker_blocker {
            if let Some(hit) = blocker.matches(&parsed) {
                record_blocked_domain(&hit.host);
                tracing::info!(
                    target: "privacy.tracker",
                    "[BLOCKED][TRACKER] host={} rule={} url={}",
                    hit.host,
                    hit.matched_rule,
                    request.url
                );

                if blocker.is_log_only() {
                    tracing::info!(
                        target: "privacy.tracker",
                        "[PRIVACY][TRACKER] log_only mode, request allowed: {}",
                        request.url
                    );
                } else {
                    match self.config.privacy.tracker_blocker.on_block {
                        TrackerBlockAction::Error => {
                            return Err(EngineError::BlockedByPrivacyPolicy(format!(
                                "tracker request blocked: host={} rule={}",
                                hit.host, hit.matched_rule
                            )));
                        }
                        TrackerBlockAction::Empty200 => {
                            interception = PrivacyInterception::Empty200;
                        }
                    }
                }
            }
        }

        // Privacy Headers: User-Agent override.
        if self.config.privacy.user_agent.enabled {
            let ua_value = self
                .config
                .privacy
                .user_agent
                .preset
                .ua_string()
                .map(str::to_owned)
                .unwrap_or_else(|| self.config.privacy.user_agent.custom_value.clone());
            request
                .headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("user-agent"));
            if !ua_value.is_empty() {
                request.headers.push(("User-Agent".to_owned(), ua_value));
            }
        }

        // Privacy Headers: Referer override.
        if self.config.privacy.referer_override.enabled
            && !self.config.privacy.referer_override.value.is_empty()
        {
            request
                .headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("referer"));
            request.headers.push((
                "Referer".to_owned(),
                self.config.privacy.referer_override.value.clone(),
            ));
        }

        // Privacy Headers: IP spoofing.
        if self.config.privacy.ip_spoof.enabled
            && !self.config.privacy.ip_spoof.spoofed_ip.is_empty()
        {
            let ip = self.config.privacy.ip_spoof.spoofed_ip.clone();
            request.headers.retain(|(k, _)| {
                !k.eq_ignore_ascii_case("x-forwarded-for") && !k.eq_ignore_ascii_case("x-real-ip")
            });
            request
                .headers
                .push(("X-Forwarded-For".to_owned(), ip.clone()));
            request.headers.push(("X-Real-IP".to_owned(), ip));
        }

        // Privacy Headers: WebRTC/Location best-effort permission policy.
        if self.config.privacy.webrtc.block_enabled
            || self.config.privacy.location_api.block_enabled
        {
            request
                .headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("permissions-policy"));
            let policy = if self.config.privacy.webrtc.block_enabled {
                "camera=(), microphone=(), geolocation=()"
            } else {
                "geolocation=()"
            };
            request
                .headers
                .push(("Permissions-Policy".to_owned(), policy.to_owned()));
        }

        Ok(interception)
    }

    fn empty_response_data() -> ResponseData {
        ResponseData {
            status_code: 200,
            headers: vec![
                (
                    "Content-Type".to_owned(),
                    "text/plain; charset=utf-8".to_owned(),
                ),
                ("X-Prime-Privacy".to_owned(), "tracker_blocked".to_owned()),
            ],
            body: Vec::new(),
        }
    }

    fn empty_response_stream() -> ResponseStream {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-prime-privacy"),
            HeaderValue::from_static("tracker_blocked"),
        );
        ResponseStream {
            status: reqwest::StatusCode::OK,
            headers,
            stream: Box::new(tokio::io::empty()),
        }
    }

    async fn empty_download_outcome(&self, path: &Path) -> Result<DownloadOutcome> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(path, []).await?;
        Ok(DownloadOutcome {
            status_code: 200,
            headers: vec![("X-Prime-Privacy".to_owned(), "tracker_blocked".to_owned())],
            bytes_written: 0,
            resumed: false,
            chunked: false,
            path: path.to_path_buf(),
        })
    }

    fn privacy_filter_active(&self) -> bool {
        self.config.privacy.tracker_blocker.enabled
            || self.config.privacy.referer.enabled
            || self.config.privacy.signals.send_dnt
            || self.config.privacy.signals.send_gpc
            || self.config.privacy.user_agent.enabled
            || self.config.privacy.referer_override.enabled
            || self.config.privacy.ip_spoof.enabled
            || self.config.privacy.webrtc.block_enabled
            || self.config.privacy.location_api.block_enabled
    }

    fn inject_default_headers(&self, request: &mut RequestData) {
        if self.config.anticensorship.tls_randomization_enabled
            && !request
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        {
            request.headers.push((
                "User-Agent".to_owned(),
                self.tls_randomizer.random_user_agent().to_owned(),
            ));
        }
    }

    async fn can_use_chunked(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
    ) -> Result<bool> {
        if !self.config.download.adaptive_enabled || request.method != Method::GET {
            return Ok(false);
        }

        let headers = build_headers(&request.headers)?;
        let response = match self
            .send_with_retry(self.config.download.max_retries, || {
                client.head(&request.url).headers(headers.clone())
            })
            .await
        {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        let len = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_default();
        if len == 0 {
            return Ok(false);
        }
        if len < (self.config.download.chunk_size_mb as u64 * 1024 * 1024) {
            return Ok(false);
        }
        let supports_ranges = response
            .headers()
            .get(reqwest::header::ACCEPT_RANGES)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("bytes"))
            .unwrap_or(false);
        if !supports_ranges {
            return Ok(false);
        }

        // HEAD can lie. Confirm Range is actually honored (tiny 1-byte request).
        Ok(self
            .probe_range_support(client, request, &headers)
            .await
            .unwrap_or(false))
    }

    async fn fetch_chunked(
        &self,
        client: &reqwest::Client,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        let headers = build_headers(&request.headers)?;
        let head = self
            .send_with_retry(self.config.download.max_retries, || {
                client.head(&request.url).headers(headers.clone())
            })
            .await?
            .error_for_status()?;
        let content_length = head
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| {
                EngineError::Internal(format!(
                    "missing content-length for chunked mode (url='{}')",
                    request.url
                ))
            })?;

        let body = self
            .chunk_manager
            .download_chunked(
                client,
                &request,
                content_length,
                self.config.download.max_retries,
                progress,
            )
            .await?;
        let headers = collect_headers(head.headers());
        Ok(ResponseData {
            status_code: 200,
            headers,
            body,
        })
    }

    async fn fetch_single(
        &self,
        client: &reqwest::Client,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        let started = Instant::now();
        let RequestData {
            url,
            method,
            headers,
            body,
        } = request;
        let headers_map = build_headers(&headers)?;

        let max_retries = self.config.download.max_retries;
        let should_retry = method == Method::GET && body.is_empty();

        let response = if should_retry {
            self.send_with_retry(max_retries, || {
                client
                    .request(method.clone(), &url)
                    .headers(headers_map.clone())
            })
            .await?
        } else {
            client
                .request(method.clone(), &url)
                .headers(headers_map.clone())
                .body(body)
                .send()
                .await?
        };

        let mut response = response.error_for_status()?;
        let status_code = response.status().as_u16();
        let headers = collect_headers(response.headers());
        let total_opt = response.content_length();

        let mut out = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            out.extend_from_slice(&chunk);
            if let Some(cb) = &progress {
                let downloaded = out.len() as u64;
                let total = total_opt.unwrap_or(0);
                let elapsed = started.elapsed().as_secs_f64().max(0.001);
                let speed_mbps = (downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                cb(downloaded, total, speed_mbps);
            }
        }

        if let Some(cb) = progress {
            let downloaded = out.len() as u64;
            let total = total_opt.unwrap_or(downloaded);
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            let speed_mbps = (downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
            cb(downloaded, total, speed_mbps);
        }

        Ok(ResponseData {
            status_code,
            headers,
            body: out,
        })
    }

    async fn probe_range_support(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
        headers: &HeaderMap,
    ) -> Result<bool> {
        if request.method != Method::GET {
            return Ok(false);
        }
        let _permit = match &self.h2_reset_limiter {
            Some(s) => Some(
                s.clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| EngineError::Internal("h2 reset limiter closed".to_owned()))?,
            ),
            None => None,
        };

        let mut h = headers.clone();
        h.insert(RANGE, HeaderValue::from_static("bytes=0-0"));
        let resp = self
            .send_with_retry(self.config.download.max_retries, || {
                client.get(&request.url).headers(h.clone())
            })
            .await?;
        let ok = resp.status().as_u16() == 206
            && parse_total_length_from_content_range(resp.headers()).is_some();
        // If the server honored the 1-byte range, consuming the body avoids an HTTP/2 RST_STREAM on drop.
        if ok {
            let _ = resp.bytes().await;
        }
        Ok(ok)
    }

    async fn send_with_retry(
        &self,
        max_retries: usize,
        mut make: impl FnMut() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let mut last_err: Option<EngineError> = None;
        for attempt in 0..=max_retries {
            let res = make().send().await;
            match res {
                Ok(resp) => {
                    let code = resp.status().as_u16();
                    let retryable_status = code == 408 || code == 429 || (500..600).contains(&code);
                    if retryable_status && attempt < max_retries {
                        tokio::time::sleep(retry_delay(attempt)).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    let retryable = e.is_timeout() || e.is_connect() || e.is_request();
                    last_err = Some(EngineError::Http(e));
                    if retryable && attempt < max_retries {
                        tokio::time::sleep(retry_delay(attempt)).await;
                        continue;
                    }
                    return Err(last_err
                        .unwrap_or_else(|| EngineError::Internal("request failed".to_owned())));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("request failed".to_owned())))
    }

    async fn download_chunked_to_parts(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
        headers: &HeaderMap,
        content_length: u64,
        path: &Path,
        progress: Option<ProgressHook>,
    ) -> Result<(u64, bool)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio::io::AsyncWriteExt;

        let mut resumed = false;
        let parts_dir: PathBuf = PathBuf::from(format!("{}.prime.parts", path.to_string_lossy()));
        std::fs::create_dir_all(&parts_dir)?;

        let chunks = self.chunk_manager.calculate_chunks(content_length);
        if chunks.is_empty() {
            // Create an empty file.
            tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .await?;
            return Ok((0, false));
        }

        let concurrency = self
            .config
            .download
            .initial_concurrency
            .min(self.config.download.max_concurrency)
            .max(1);

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
        let downloaded = std::sync::Arc::new(AtomicU64::new(0));
        let started_at = Instant::now();

        let mut join_set = tokio::task::JoinSet::new();
        for (index, chunk) in chunks.iter().copied().enumerate() {
            let part_path = parts_dir.join(format!("{index:08}.part"));
            let expected_len = (chunk.end - chunk.start) + 1;

            if let Ok(meta) = std::fs::metadata(&part_path) {
                if meta.is_file() && meta.len() == expected_len {
                    resumed = true;
                    downloaded.fetch_add(expected_len, Ordering::Relaxed);
                    continue;
                }
            }

            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| EngineError::Internal("semaphore closed".to_owned()))?;

            let client = client.clone();
            let url = request.url.clone();
            let base_headers = headers.clone();
            let downloaded = downloaded.clone();
            let progress = progress.clone();
            let max_retries = self.config.download.max_retries;
            join_set.spawn(async move {
                let _permit = permit;

                // (Re)download this part into its own file.
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&part_path)
                    .await?;

                let range_value = format!("bytes={}-{}", chunk.start, chunk.end);
                let mut h = base_headers.clone();
                h.insert(RANGE, HeaderValue::from_str(&range_value)?);

                // Retry the whole part download on transient failures.
                let mut last_err: Option<EngineError> = None;
                for attempt in 0..=max_retries {
                    let mut attempt_written: u64 = 0;
                    let resp = client.get(&url).headers(h.clone()).send().await;
                    match resp {
                        Ok(r) => {
                            if r.status().as_u16() != 206 {
                                last_err = Some(EngineError::Internal(format!(
                                    "server did not return Partial Content (expected 206, got {})",
                                    r.status().as_u16()
                                )));
                            } else {
                                let mut r = r;
                                let mut ok = true;
                                loop {
                                    match r.chunk().await {
                                        Ok(Some(buf)) => {
                                            file.write_all(&buf).await?;
                                            attempt_written += buf.len() as u64;
                                            let total_downloaded = downloaded
                                                .fetch_add(buf.len() as u64, Ordering::Relaxed)
                                                + (buf.len() as u64);
                                            if let Some(cb) = &progress {
                                                let elapsed =
                                                    started_at.elapsed().as_secs_f64().max(0.001);
                                                let speed_mbps = (total_downloaded as f64 * 8.0
                                                    / 1_000_000.0)
                                                    / elapsed;
                                                cb(total_downloaded, content_length, speed_mbps);
                                            }
                                        }
                                        Ok(None) => break,
                                        Err(e) => {
                                            last_err = Some(EngineError::Http(e));
                                            ok = false;
                                            break;
                                        }
                                    }
                                }

                                if ok {
                                    file.flush().await?;
                                    let size = file.metadata().await?.len();
                                    if size == expected_len {
                                        return Ok::<(), EngineError>(());
                                    }
                                    last_err = Some(EngineError::Internal(format!(
                                        "downloaded part size mismatch (expected {expected_len}, got {size})"
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            last_err = Some(EngineError::Http(e));
                        }
                    }

                    if attempt < max_retries {
                        // Roll back progress for bytes written during this attempt since we will re-download it.
                        if attempt_written > 0 {
                            downloaded.fetch_sub(attempt_written, Ordering::Relaxed);
                        }
                        tokio::time::sleep(retry_delay(attempt)).await;
                        // Reset file to overwrite from scratch.
                        file = tokio::fs::OpenOptions::new()
                            .create(true)
                            .truncate(true)
                            .write(true)
                            .open(&part_path)
                            .await?;
                        continue;
                    }
                }

                Err(last_err.unwrap_or_else(|| EngineError::Internal("part download failed".to_owned())))
            });
        }

        while let Some(result) = join_set.join_next().await {
            result??;
        }

        // Merge parts sequentially into a temp file, then rename into place.
        let tmp_path: PathBuf = PathBuf::from(format!("{}.prime.tmp", path.to_string_lossy()));
        let mut out = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .await?;

        for index in 0..chunks.len() {
            let part_path = parts_dir.join(format!("{index:08}.part"));
            let mut input = tokio::fs::File::open(&part_path).await?;
            tokio::io::copy(&mut input, &mut out).await?;
        }
        out.flush().await?;
        drop(out);

        if let Ok(meta) = tokio::fs::metadata(path).await {
            if meta.is_file() {
                let _ = tokio::fs::remove_file(path).await;
            }
        }
        tokio::fs::rename(&tmp_path, path).await?;

        // Best-effort cleanup of parts.
        let _ = tokio::fs::remove_dir_all(&parts_dir).await;

        Ok((content_length, resumed))
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_single_to_file(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
        headers: &HeaderMap,
        content_length: Option<u64>,
        path: &Path,
        supports_ranges: bool,
        progress: Option<ProgressHook>,
    ) -> Result<(u64, bool)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use tokio::io::AsyncWriteExt;

        let mut resumed = false;
        let mut offset: u64 = 0;
        if supports_ranges {
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.is_file() && meta.len() > 0 {
                    offset = meta.len();
                    resumed = true;
                }
            }
        }

        let mut h = headers.clone();
        if offset > 0 {
            h.insert(RANGE, HeaderValue::from_str(&format!("bytes={offset}-"))?);
        }

        let max_retries = self.config.download.max_retries;
        let resp = self
            .send_with_retry(max_retries, || client.get(&request.url).headers(h.clone()))
            .await?;

        // If we attempted a resume but the server ignored Range and returned 200, restart from scratch.
        let (resp, offset) = if offset > 0 && resp.status().as_u16() == 200 {
            resumed = false;
            offset = 0;
            let resp = self
                .send_with_retry(max_retries, || {
                    client.get(&request.url).headers(headers.clone())
                })
                .await?;
            (resp, offset)
        } else {
            (resp, offset)
        };

        // Validate status before writing any bytes to disk.
        let status = resp.status();
        if offset > 0 {
            match status.as_u16() {
                206 => {}
                416 => {
                    // Range Not Satisfiable. Only treat as "already complete" if local size exactly
                    // matches server's total size. If local is larger, it is corrupted/stale and must
                    // be restarted to avoid silent on-disk corruption.
                    let total = resp
                        .headers()
                        .get(reqwest::header::CONTENT_RANGE)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.rsplit('/').next())
                        .and_then(|s| s.parse::<u64>().ok())
                        .or(content_length);

                    if let Some(total) = total {
                        if offset == total {
                            return Ok((total, true));
                        }
                        // Local file size doesn't match server total (smaller or larger) but server rejected
                        // the range; restart full download (truncate and re-download).
                        let resp = self
                            .send_with_retry(max_retries, || {
                                client.get(&request.url).headers(headers.clone())
                            })
                            .await?;
                        let status = resp.status();
                        if !status.is_success() {
                            return Err(EngineError::Internal(format!(
                                "download failed: server returned HTTP {} on restart",
                                status.as_u16()
                            )));
                        }
                        // Continue below with fresh response.
                        // NOTE: shadowing keeps the rest of the function unchanged.
                        let resp = resp;

                        let mut file = tokio::fs::OpenOptions::new()
                            .create(true)
                            .truncate(true)
                            .write(true)
                            .open(path)
                            .await?;

                        let downloaded = AtomicU64::new(0);
                        let started_at = Instant::now();
                        let mut stream = resp.bytes_stream();
                        while let Some(buf) = stream.try_next().await.map_err(EngineError::Http)? {
                            file.write_all(&buf).await?;
                            let total_downloaded = downloaded
                                .fetch_add(buf.len() as u64, Ordering::Relaxed)
                                + (buf.len() as u64);
                            if let Some(cb) = &progress {
                                let total = content_length.unwrap_or(0);
                                let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                                let speed_mbps =
                                    (total_downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                                cb(total_downloaded, total, speed_mbps);
                            }
                        }
                        file.flush().await?;
                        let final_len = file.metadata().await?.len();
                        return Ok((final_len, false));
                    }

                    return Err(EngineError::Internal(
                        "download failed: server returned HTTP 416 (Range Not Satisfiable) and total size is unknown"
                            .to_owned(),
                    ));
                }
                _ => {
                    return Err(EngineError::Internal(format!(
                        "download failed: server returned HTTP {} for a ranged request",
                        status.as_u16()
                    )));
                }
            }
        } else if !status.is_success() {
            return Err(EngineError::Internal(format!(
                "download failed: server returned HTTP {}",
                status.as_u16()
            )));
        }

        let mut file = if offset > 0 {
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?
        } else {
            tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .await?
        };

        let downloaded = AtomicU64::new(offset);
        let started_at = Instant::now();
        let mut stream = resp.bytes_stream();
        while let Some(buf) = stream.try_next().await.map_err(EngineError::Http)? {
            file.write_all(&buf).await?;
            let total_downloaded =
                downloaded.fetch_add(buf.len() as u64, Ordering::Relaxed) + (buf.len() as u64);
            if let Some(cb) = &progress {
                let total = content_length.unwrap_or(0);
                let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                let speed_mbps = (total_downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                cb(total_downloaded, total, speed_mbps);
            }
        }
        file.flush().await?;
        let final_len = file.metadata().await?.len();
        Ok((final_len, resumed))
    }

    async fn verify_download_integrity_if_configured(&self, path: &Path) -> Result<()> {
        use tokio::io::AsyncReadExt;

        let Some(spec) = self.config.download.verify_hash.as_deref() else {
            return Ok(());
        };
        let spec = spec.trim();
        if spec.is_empty() {
            // Config validation should have prevented this; treat as no-op.
            return Ok(());
        }

        let expected_hex = if spec.eq_ignore_ascii_case("auto") {
            let sha_path = PathBuf::from(format!("{}.sha256", path.to_string_lossy()));
            let content = tokio::fs::read_to_string(&sha_path).await.map_err(|e| {
                EngineError::Internal(format!(
                    "download integrity failed: unable to read sha256 file '{}': {e}",
                    sha_path.to_string_lossy()
                ))
            })?;
            extract_sha256_from_text(&content).ok_or_else(|| {
                EngineError::Internal(format!(
                    "download integrity failed: sha256 file '{}' does not contain a 64-hex digest",
                    sha_path.to_string_lossy()
                ))
            })?
        } else if let Some(hex) = spec.strip_prefix("sha256:") {
            hex.trim().to_owned()
        } else {
            return Err(EngineError::Config(
                "download.verify_hash must be 'auto' or 'sha256:<64 hex>'".to_owned(),
            ));
        };

        let expected = parse_sha256_hex(&expected_hex).ok_or_else(|| {
            EngineError::Config("download.verify_hash contains invalid sha256 hex".to_owned())
        })?;

        let mut file = tokio::fs::File::open(path).await.map_err(|e| {
            EngineError::Internal(format!(
                "download integrity failed: unable to open '{}': {e}",
                path.to_string_lossy()
            ))
        })?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let got_bytes = hasher.finalize();

        if got_bytes != expected {
            return Err(EngineError::Internal(format!(
                "download integrity failed: sha256 mismatch for '{}'",
                path.to_string_lossy()
            )));
        }
        Ok(())
    }
}

// Minimal SHA-256 implementation (FIPS 180-4) to avoid adding new dependencies.
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len_bytes: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len_bytes: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total_len_bytes = self.total_len_bytes.wrapping_add(input.len() as u64);

        if self.buffer_len > 0 {
            let take = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }

        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            self.compress(&block);
            input = &input[64..];
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len_bytes.wrapping_mul(8);

        // Append the '1' bit.
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // Pad with zeros until we have room for the 64-bit length.
        if self.buffer_len > 56 {
            for b in self.buffer[self.buffer_len..].iter_mut() {
                *b = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
        }

        for b in self.buffer[self.buffer_len..56].iter_mut() {
            *b = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    fn val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = val(bytes[i * 2])?;
        let lo = val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn extract_sha256_from_text(s: &str) -> Option<String> {
    // Common formats:
    // - "<hex>  filename"
    // - "SHA256 (filename) = <hex>"
    // We look for the first 64-hex token/substr.
    for token in s.split_whitespace() {
        if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(token.to_ascii_lowercase());
        }
    }

    let bytes = s.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    for i in 0..=(bytes.len() - 64) {
        let sub = &bytes[i..i + 64];
        if sub.iter().all(|b| b.is_ascii_hexdigit()) {
            return Some(String::from_utf8_lossy(sub).to_ascii_lowercase());
        }
    }
    None
}

fn should_fallback_from_ech(err: &EngineError) -> bool {
    match err {
        EngineError::Http(e) => e.is_connect() || e.is_timeout(),
        _ => false,
    }
}

fn build_reqwest_client(
    cfg: &EngineConfig,
    pool: &ConnectionPoolConfig,
    dns_resolver: std::sync::Arc<PrimeReqwestDnsResolver>,
    tls: rustls::ClientConfig,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(cfg.download.connect_timeout_secs))
        .timeout(Duration::from_secs(cfg.download.request_timeout_secs))
        .tcp_keepalive(Duration::from_secs(30))
        .http2_adaptive_window(true)
        .http2_keep_alive_timeout(Duration::from_secs(30));

    // Use an explicit rustls ClientConfig so that tls.alpn_protocols and ECH settings are applied.
    // (Reqwest's high-level builder API doesn't expose ALPN, and ECH requires rustls config.)
    builder = builder.use_preconfigured_tls(tls);
    builder = pool.apply(builder);
    // Keep behavior deterministic across environments/CI: only use proxy when explicitly configured.
    builder = builder.no_proxy();
    if let Some(proxy_cfg) = &cfg.proxy {
        builder = builder.proxy(proxy_cfg.as_reqwest_proxy()?);
    }
    builder = builder.dns_resolver(dns_resolver);

    Ok(builder.build()?)
}

#[cfg(feature = "observability")]
fn record_http_metrics(started: Instant, ok: bool) {
    let elapsed = started.elapsed().as_secs_f64();
    if ok {
        crate::observability::prometheus::HTTP_REQUESTS_OK.inc();
        crate::observability::prometheus::HTTP_REQUEST_DURATION_OK.observe(elapsed);
    } else {
        crate::observability::prometheus::HTTP_REQUESTS_ERROR.inc();
        crate::observability::prometheus::HTTP_REQUEST_DURATION_ERROR.observe(elapsed);
    }
}

fn build_headers(headers: &[(String, String)]) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(value)?,
        );
    }
    Ok(map)
}

fn collect_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_owned())))
        .collect()
}

fn parse_total_length_from_content_range(headers: &HeaderMap) -> Option<u64> {
    // Content-Range: bytes 0-0/12345
    let v = headers.get(reqwest::header::CONTENT_RANGE)?.to_str().ok()?;
    let (_unit_and_range, total) = v.split_once('/')?;
    if total.trim() == "*" {
        return None;
    }
    total.trim().parse::<u64>().ok()
}

fn retry_delay(attempt: usize) -> Duration {
    // 200ms, 400ms, 800ms ... with a small jitter (best-effort).
    let base_ms: u64 = 200;
    let max_shift = 6usize;
    let exp = (attempt.min(max_shift)) as u32;
    let backoff = base_ms.saturating_mul(1_u64 << exp);
    let jitter = rand::random::<u64>() % 100;
    Duration::from_millis(backoff.saturating_add(jitter))
}

fn is_tcp_connection_reset(err: &EngineError) -> bool {
    use std::error::Error as _;
    use std::io;

    let mut cur: Option<&(dyn std::error::Error + 'static)> = match err {
        EngineError::Http(e) => e.source(),
        _ => None,
    };

    while let Some(e) = cur {
        if let Some(ioe) = e.downcast_ref::<io::Error>() {
            if ioe.kind() == io::ErrorKind::ConnectionReset
                || ioe.kind() == io::ErrorKind::ConnectionAborted
            {
                return true;
            }
        }
        cur = e.source();
    }

    // Best-effort fallback for wrappers that don't expose `io::Error` directly.
    let s = err.to_string().to_ascii_lowercase();
    s.contains("connection reset") || s.contains("connection was reset") || s.contains("econnreset")
}

fn map_fronting_provider(provider: &FrontingProvider) -> CdnProvider {
    match provider {
        FrontingProvider::Cloudflare => CdnProvider::Cloudflare,
        FrontingProvider::Fastly => CdnProvider::Fastly,
        FrontingProvider::GoogleCdn => CdnProvider::GoogleCdn,
        FrontingProvider::AzureCdn => CdnProvider::AzureCdn,
    }
}

fn build_rustls_ech_config(
    ech_config_list: &[u8],
) -> std::result::Result<rustls::client::EchConfig, rustls::Error> {
    let suites = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
    rustls::client::EchConfig::new(
        rustls::pki_types::EchConfigListBytes::from(ech_config_list),
        suites,
    )
}

fn build_ech_grease_mode() -> Result<rustls::client::EchMode> {
    let suite = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
        .first()
        .ok_or_else(|| EngineError::Internal("no HPKE suites available for ECH".to_owned()))?;
    let (placeholder_pub, _placeholder_priv) = suite.generate_key_pair().map_err(|e| {
        EngineError::Internal(format!("ECH placeholder key generation failed: {e}"))
    })?;
    let grease = rustls::client::EchGreaseConfig::new(*suite, placeholder_pub);
    Ok(rustls::client::EchMode::Grease(grease))
}

fn default_crypto_provider_arc() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

fn base_crypto_provider() -> rustls::crypto::CryptoProvider {
    // Clone the process default if installed, otherwise use aws-lc-rs defaults.
    // We keep this separate from `default_crypto_provider_arc()` to allow per-client tuning
    // (JA3-adjacent) without mutating the global default provider.
    rustls::crypto::CryptoProvider::get_default()
        .map(|arc| (**arc).clone())
        .unwrap_or_else(rustls::crypto::aws_lc_rs::default_provider)
}

fn select_crypto_provider(cfg: &EngineConfig) -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    match cfg.tls.ja3_fingerprint {
        Ja3Fingerprint::RustlsDefault => default_crypto_provider_arc(),
        other => std::sync::Arc::new(apply_ja3_profile(base_crypto_provider(), other)),
    }
}

fn apply_ja3_profile(
    mut provider: rustls::crypto::CryptoProvider,
    profile: Ja3Fingerprint,
) -> rustls::crypto::CryptoProvider {
    match profile {
        Ja3Fingerprint::RustlsDefault => {}
        Ja3Fingerprint::Chrome120 => {
            // Chrome generally prefers AES_128 first (then AES_256, then CHACHA20).
            reorder_cipher_suites(
                &mut provider.cipher_suites,
                &[
                    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                ],
            );
            // Keep X25519 first for compatibility; keep PQ-hybrid (if present) last.
            reorder_kx_groups(
                &mut provider.kx_groups,
                &[
                    rustls::NamedGroup::X25519,
                    rustls::NamedGroup::secp256r1,
                    rustls::NamedGroup::secp384r1,
                    rustls::NamedGroup::X25519MLKEM768,
                ],
            );
        }
        Ja3Fingerprint::Firefox121 => {
            // Firefox tends to prefer CHACHA20 earlier when available on non-AES-NI machines,
            // but from our side we can only apply a fixed preference ordering.
            reorder_cipher_suites(
                &mut provider.cipher_suites,
                &[
                    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                ],
            );
            reorder_kx_groups(
                &mut provider.kx_groups,
                &[
                    rustls::NamedGroup::X25519,
                    rustls::NamedGroup::secp256r1,
                    rustls::NamedGroup::secp384r1,
                    rustls::NamedGroup::X25519MLKEM768,
                ],
            );
        }
        Ja3Fingerprint::Random => {
            let mut rng = thread_rng();

            // Best-effort: keep a sane first ciphersuite if present, then randomize the rest.
            if let Some(pos) = provider
                .cipher_suites
                .iter()
                .position(|s| s.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
            {
                provider.cipher_suites.swap(0, pos);
            }
            if provider.cipher_suites.len() > 1 {
                provider.cipher_suites[1..].shuffle(&mut rng);
            }

            // Keep X25519 first if present, randomize the remainder.
            if let Some(pos) = provider
                .kx_groups
                .iter()
                .position(|g| g.name() == rustls::NamedGroup::X25519)
            {
                provider.kx_groups.swap(0, pos);
            }
            if provider.kx_groups.len() > 1 {
                provider.kx_groups[1..].shuffle(&mut rng);
            }
        }
    }
    provider
}

fn reorder_cipher_suites(
    suites: &mut Vec<rustls::SupportedCipherSuite>,
    preferred: &[rustls::CipherSuite],
) {
    let mut out: Vec<rustls::SupportedCipherSuite> = Vec::with_capacity(suites.len());

    for id in preferred {
        for s in suites.iter().copied() {
            if s.suite() == *id && !out.contains(&s) {
                out.push(s);
            }
        }
    }

    for s in suites.iter().copied() {
        if !out.contains(&s) {
            out.push(s);
        }
    }

    *suites = out;
}

fn reorder_kx_groups(
    groups: &mut Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    preferred: &[rustls::NamedGroup],
) {
    let mut out: Vec<&'static dyn rustls::crypto::SupportedKxGroup> =
        Vec::with_capacity(groups.len());
    let mut seen: Vec<rustls::NamedGroup> = Vec::new();

    for id in preferred {
        for g in groups.iter().copied() {
            if g.name() == *id && !seen.contains(id) {
                out.push(g);
                seen.push(*id);
            }
        }
    }

    for g in groups.iter().copied() {
        let id = g.name();
        if !seen.contains(&id) {
            out.push(g);
            seen.push(id);
        }
    }

    *groups = out;
}

fn build_rustls_client_config(
    cfg: &EngineConfig,
    ech_mode: Option<rustls::client::EchMode>,
) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let versions = select_rustls_versions_plain(cfg)?;

    let provider = select_crypto_provider(cfg);

    // NOTE: rustls' `with_ech()` typestate transition does not allow calling
    // `with_protocol_versions()` after it. Internally, `with_ech()` forces TLS 1.3.
    let builder = if let Some(mode) = ech_mode {
        validate_ech_tls_constraints(cfg)?;
        rustls::ClientConfig::builder_with_provider(provider)
            .with_ech(mode)
            .map_err(|e| EngineError::Internal(format!("failed to enable ECH: {e}")))?
    } else {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .map_err(|_| EngineError::Config("invalid TLS protocol versions".to_owned()))?
    };

    let mut tls = builder.with_root_certificates(roots).with_no_client_auth();

    // ALPN protocols (drives HTTP/2 negotiation).
    let mut alpn = Vec::new();
    for p in &cfg.tls.alpn_protocols {
        let p = p.trim();
        if !p.is_empty() {
            alpn.push(p.as_bytes().to_vec());
        }
    }
    if alpn.is_empty() {
        alpn.push(b"h2".to_vec());
        alpn.push(b"http/1.1".to_vec());
    }
    if cfg.tls.ja3_fingerprint == Ja3Fingerprint::Random && alpn.len() > 1 {
        alpn.shuffle(&mut thread_rng());
    }
    tls.alpn_protocols = alpn;
    tls.enable_sni = true;

    Ok(tls)
}

fn validate_ech_tls_constraints(cfg: &EngineConfig) -> Result<()> {
    let min = cfg.tls.min_version;
    let max = cfg.tls.max_version;
    let min_r = tls_rank(min);
    let max_r = tls_rank(max);

    if !(min_r <= tls_rank(TlsVersion::Tls1_3) && max_r >= tls_rank(TlsVersion::Tls1_3)) {
        return Err(EngineError::Config(
            "anticensorship.ech_mode requires TLS 1.3 to be allowed by tls.min_version/tls.max_version".to_owned(),
        ));
    }
    Ok(())
}

fn select_rustls_versions_plain(
    cfg: &EngineConfig,
) -> Result<Vec<&'static SupportedProtocolVersion>> {
    let min = cfg.tls.min_version;
    let max = cfg.tls.max_version;
    let min_r = tls_rank(min);
    let max_r = tls_rank(max);

    // Only TLS 1.2 and 1.3 are supported by the current rustls backend wiring.
    let mut versions: Vec<&'static SupportedProtocolVersion> = Vec::new();
    if min_r <= tls_rank(TlsVersion::Tls1_3) && max_r >= tls_rank(TlsVersion::Tls1_3) {
        versions.push(&rustls::version::TLS13);
    }
    if min_r <= tls_rank(TlsVersion::Tls1_2) && max_r >= tls_rank(TlsVersion::Tls1_2) {
        versions.push(&rustls::version::TLS12);
    }

    if versions.is_empty() {
        return Err(EngineError::Config(
            "no supported TLS versions selected (only TLS 1.2 and 1.3 are supported)".to_owned(),
        ));
    }

    Ok(versions)
}

fn tls_rank(v: TlsVersion) -> u8 {
    match v {
        TlsVersion::Tls1_0 => 10,
        TlsVersion::Tls1_1 => 11,
        TlsVersion::Tls1_2 => 12,
        TlsVersion::Tls1_3 => 13,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn read_u8(buf: &[u8], pos: &mut usize) -> Option<u8> {
        let v = *buf.get(*pos)?;
        *pos += 1;
        Some(v)
    }

    fn read_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
        let b0 = *buf.get(*pos)? as u16;
        let b1 = *buf.get(*pos + 1)? as u16;
        *pos += 2;
        Some((b0 << 8) | b1)
    }

    fn read_u24(buf: &[u8], pos: &mut usize) -> Option<usize> {
        let b0 = *buf.get(*pos)? as usize;
        let b1 = *buf.get(*pos + 1)? as usize;
        let b2 = *buf.get(*pos + 2)? as usize;
        *pos += 3;
        Some((b0 << 16) | (b1 << 8) | b2)
    }

    fn capture_client_hello(cfg: rustls::ClientConfig) -> Vec<u8> {
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("valid server name");
        let mut conn = rustls::ClientConnection::new(Arc::new(cfg), server_name)
            .expect("client connection should build");
        let mut out = Vec::new();
        conn.write_tls(&mut out).expect("write_tls should work");
        out
    }

    fn supported_versions_from_client_hello(tls_stream: &[u8]) -> Option<Vec<u16>> {
        // Reassemble handshake fragments from TLS records.
        let mut pos = 0usize;
        let mut handshake = Vec::new();
        while pos + 5 <= tls_stream.len() {
            let ct = tls_stream[pos];
            let _legacy_ver = u16::from_be_bytes([tls_stream[pos + 1], tls_stream[pos + 2]]);
            let len = u16::from_be_bytes([tls_stream[pos + 3], tls_stream[pos + 4]]) as usize;
            pos += 5;
            let frag = tls_stream.get(pos..pos + len)?;
            pos += len;
            if ct == 22 {
                handshake.extend_from_slice(frag);
            }
        }

        // First handshake message should be ClientHello (type 1).
        let mut hp = 0usize;
        let hs_type = read_u8(&handshake, &mut hp)?;
        if hs_type != 1 {
            return None;
        }
        let hs_len = read_u24(&handshake, &mut hp)?;
        let ch = handshake.get(hp..hp + hs_len)?;

        // Parse ClientHello enough to reach extensions.
        let mut cp = 0usize;
        let _legacy_client_ver = read_u16(ch, &mut cp)?;
        cp += 32; // random
        let sid_len = read_u8(ch, &mut cp)? as usize;
        cp += sid_len;
        let cs_len = read_u16(ch, &mut cp)? as usize;
        cp += cs_len;
        let comp_len = read_u8(ch, &mut cp)? as usize;
        cp += comp_len;
        let ext_len = read_u16(ch, &mut cp)? as usize;
        let exts = ch.get(cp..cp + ext_len)?;

        // Walk extensions.
        let mut ep = 0usize;
        while ep + 4 <= exts.len() {
            let ty = u16::from_be_bytes([exts[ep], exts[ep + 1]]);
            let elen = u16::from_be_bytes([exts[ep + 2], exts[ep + 3]]) as usize;
            ep += 4;
            let data = exts.get(ep..ep + elen)?;
            ep += elen;

            // supported_versions (RFC 8446) = 0x002b
            if ty == 0x002b {
                let mut dp = 0usize;
                let list_len = read_u8(data, &mut dp)? as usize;
                let list = data.get(dp..dp + list_len)?;
                let mut out = Vec::new();
                for chunk in list.chunks_exact(2) {
                    out.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                }
                return Some(out);
            }
        }
        None
    }

    fn cipher_suites_from_client_hello(tls_stream: &[u8]) -> Option<Vec<u16>> {
        // Reassemble handshake fragments from TLS records.
        let mut pos = 0usize;
        let mut handshake = Vec::new();
        while pos + 5 <= tls_stream.len() {
            let ct = tls_stream[pos];
            let len = u16::from_be_bytes([tls_stream[pos + 3], tls_stream[pos + 4]]) as usize;
            pos += 5;
            let frag = tls_stream.get(pos..pos + len)?;
            pos += len;
            if ct == 22 {
                handshake.extend_from_slice(frag);
            }
        }

        // First handshake message should be ClientHello (type 1).
        let mut hp = 0usize;
        let hs_type = read_u8(&handshake, &mut hp)?;
        if hs_type != 1 {
            return None;
        }
        let hs_len = read_u24(&handshake, &mut hp)?;
        let ch = handshake.get(hp..hp + hs_len)?;

        let mut cp = 0usize;
        let _legacy_client_ver = read_u16(ch, &mut cp)?;
        cp += 32; // random
        let sid_len = read_u8(ch, &mut cp)? as usize;
        cp += sid_len;
        let cs_len = read_u16(ch, &mut cp)? as usize;
        let cs = ch.get(cp..cp + cs_len)?;

        let mut out = Vec::new();
        for chunk in cs.chunks_exact(2) {
            out.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        Some(out)
    }

    #[test]
    fn ech_forces_tls13_only_in_client_hello() {
        let mut cfg = EngineConfig::default();
        cfg.tls.min_version = TlsVersion::Tls1_2;
        cfg.tls.max_version = TlsVersion::Tls1_3;
        cfg.anticensorship.ech_mode = Some(EchMode::Grease);

        let client_cfg =
            build_rustls_client_config(&cfg, Some(build_ech_grease_mode().expect("grease mode")))
                .expect("client config should build");
        let ch = capture_client_hello(client_cfg);
        let versions =
            supported_versions_from_client_hello(&ch).expect("supported_versions present");
        assert_eq!(versions, vec![0x0304]); // TLS 1.3 only
    }

    #[test]
    fn non_ech_offers_tls12_and_tls13_in_client_hello() {
        let mut cfg = EngineConfig::default();
        cfg.tls.min_version = TlsVersion::Tls1_2;
        cfg.tls.max_version = TlsVersion::Tls1_3;
        cfg.anticensorship.ech_enabled = false;

        let client_cfg =
            build_rustls_client_config(&cfg, None).expect("client config should build");
        let ch = capture_client_hello(client_cfg);
        let versions =
            supported_versions_from_client_hello(&ch).expect("supported_versions present");
        assert!(versions.contains(&0x0304)); // TLS 1.3
        assert!(versions.contains(&0x0303)); // TLS 1.2
    }

    #[test]
    fn ech_requires_tls13_to_be_allowed_by_config() {
        let mut cfg = EngineConfig::default();
        cfg.tls.min_version = TlsVersion::Tls1_2;
        cfg.tls.max_version = TlsVersion::Tls1_2;
        cfg.anticensorship.ech_mode = Some(EchMode::Grease);

        let err =
            build_rustls_client_config(&cfg, Some(build_ech_grease_mode().expect("grease mode")))
                .expect_err("must reject ECH when TLS1.3 is not allowed");
        match err {
            EngineError::Config(msg) => assert!(msg.contains("requires TLS 1.3")),
            other => panic!("expected config error, got: {other:?}"),
        }
    }

    #[test]
    fn chrome_profile_reorders_cipher_suites_best_effort() {
        let mut cfg = EngineConfig::default();
        cfg.tls.ja3_fingerprint = Ja3Fingerprint::Chrome120;
        let client_cfg =
            build_rustls_client_config(&cfg, None).expect("client config should build");
        let ch = capture_client_hello(client_cfg);
        let suites = cipher_suites_from_client_hello(&ch).expect("cipher suites present");

        // Ensure common TLS 1.3 suites appear in the intended order: 0x1301 < 0x1302 < 0x1303.
        let i1 = suites
            .iter()
            .position(|v| *v == 0x1301)
            .expect("TLS_AES_128_GCM_SHA256");
        let i2 = suites
            .iter()
            .position(|v| *v == 0x1302)
            .expect("TLS_AES_256_GCM_SHA384");
        let i3 = suites
            .iter()
            .position(|v| *v == 0x1303)
            .expect("TLS_CHACHA20_POLY1305_SHA256");
        assert!(i1 < i2 && i2 < i3);
    }

    #[test]
    fn firefox_profile_reorders_cipher_suites_best_effort() {
        let mut cfg = EngineConfig::default();
        cfg.tls.ja3_fingerprint = Ja3Fingerprint::Firefox121;
        let client_cfg =
            build_rustls_client_config(&cfg, None).expect("client config should build");
        let ch = capture_client_hello(client_cfg);
        let suites = cipher_suites_from_client_hello(&ch).expect("cipher suites present");

        // Intended order: 0x1301 < 0x1303 < 0x1302.
        let i1 = suites
            .iter()
            .position(|v| *v == 0x1301)
            .expect("TLS_AES_128_GCM_SHA256");
        let i2 = suites
            .iter()
            .position(|v| *v == 0x1302)
            .expect("TLS_AES_256_GCM_SHA384");
        let i3 = suites
            .iter()
            .position(|v| *v == 0x1303)
            .expect("TLS_CHACHA20_POLY1305_SHA256");
        assert!(i1 < i3 && i3 < i2);
    }
}
