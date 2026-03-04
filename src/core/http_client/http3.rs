use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use bytes::Bytes;
use futures_util::future::poll_fn;
use reqwest::StatusCode;
use url::Url;

use crate::core::{PrimeHttpClient, ProgressHook, RequestData, ResponseData, ResponseStream};
use crate::error::{EngineError, Result};

fn build_rustls_config_http3(client: &PrimeHttpClient) -> Result<rustls::ClientConfig> {
    // QUIC uses TLS 1.3 exclusively. Build a dedicated rustls config to avoid accidentally
    // including TLS 1.2 in `with_protocol_versions()`.
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = super::select_crypto_provider(&client.config);

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| EngineError::Config("invalid TLS protocol versions for HTTP/3".to_owned()))?;

    let mut cfg = builder.with_root_certificates(roots).with_no_client_auth();

    // HTTP/3 ALPNs. Keep a couple of legacy drafts for compatibility.
    cfg.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec(), b"h3-30".to_vec()];

    fn is_dev_mode() -> bool {
        std::env::var("PRIME_NET_DEV").is_ok()
    }

    if client.config.transport.http3_insecure_skip_verify {
        if is_dev_mode() {
            tracing::warn!("HTTP/3 TLS verification is DISABLED (insecure_skip_verify=true). This allows MITM attacks and should ONLY be used for local testing/debugging.");
            cfg.dangerous()
                .set_certificate_verifier(Arc::new(crate::tls::InsecureSkipVerify));
        } else {
            tracing::error!("http3_insecure_skip_verify=true ignored in production mode. Set PRIME_NET_DEV=1 to enable for local testing.");
        }
    }

    Ok(cfg)
}

fn bind_quinn_endpoint() -> Result<quinn::Endpoint> {
    // Prefer IPv6 bind when possible; fall back to IPv4 for environments without IPv6.
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    match quinn::Endpoint::client(v6) {
        Ok(ep) => Ok(ep),
        Err(_) => {
            let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            quinn::Endpoint::client(v4)
                .map_err(|e| EngineError::Internal(format!("quinn endpoint init failed: {e}")))
        }
    }
}

fn url_authority(parsed: &Url) -> Result<(String, u16)> {
    let Some(host) = parsed.host_str() else {
        return Err(EngineError::InvalidInput("URL has no host".to_owned()));
    };
    let port = parsed.port_or_known_default().unwrap_or(443);
    Ok((host.to_owned(), port))
}

fn url_to_h3_uri(parsed: &Url) -> Result<http::Uri> {
    let (host, port) = url_authority(parsed)?;
    let mut authority = host;
    if port != 443 {
        authority = format!("{authority}:{port}");
    }
    let path = match parsed[url::Position::BeforePath..].trim() {
        "" => "/",
        v => v,
    };
    http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|e| EngineError::InvalidInput(format!("invalid URI for HTTP/3: {e}")))
}

fn request_to_http_request(parsed: &Url, req: &RequestData) -> Result<http::Request<()>> {
    let uri = url_to_h3_uri(parsed)?;
    let mut b = http::Request::builder()
        .method(req.method.as_str())
        .uri(uri);
    for (k, v) in &req.headers {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(())
        .map_err(|e| EngineError::InvalidInput(format!("invalid HTTP/3 request: {e}")))
}

fn response_to_response_data(resp: &http::Response<()>, body: Vec<u8>) -> ResponseData {
    let mut headers = Vec::new();
    for (k, v) in resp.headers().iter() {
        if let Ok(v) = v.to_str() {
            headers.push((k.as_str().to_owned(), v.to_owned()));
        }
    }
    ResponseData {
        status_code: resp.status().as_u16(),
        headers,
        body,
    }
}

fn response_to_header_map(resp: &http::Response<()>) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for (k, v) in resp.headers().iter() {
        out.insert(k, v.clone());
    }
    out
}

impl PrimeHttpClient {
    pub(super) async fn fetch_http3(
        &self,
        request: RequestData,
        progress: Option<ProgressHook>,
    ) -> Result<ResponseData> {
        let parsed = Url::parse(&request.url)?;
        if parsed.scheme() != "https" {
            return Err(EngineError::InvalidInput(
                "HTTP/3 requires https:// URL".to_owned(),
            ));
        }

        let (host, port) = url_authority(&parsed)?;
        let ips = self.resolver_chain.resolve(&host).await?;
        if ips.is_empty() {
            return Err(EngineError::Internal(format!(
                "DNS returned no addresses for '{host}'"
            )));
        }

        // Lazy initialize or use shared endpoint if available
        let mut endpoint = {
            let mut guard = self.h3_endpoint.lock();
            if let Some(ep) = &*guard {
                ep.clone()
            } else {
                let ep = bind_quinn_endpoint()?;
                *guard = Some(ep.clone());
                ep
            }
        };
        let tls_cfg = build_rustls_config_http3(self)?;
        let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg)
            .map_err(|e| EngineError::Internal(format!("quic tls config failed: {e}")))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));

        let mut transport_cfg = quinn::TransportConfig::default();
        if let Ok(idle) =
            Duration::from_millis(self.config.transport.http3_idle_timeout_ms).try_into()
        {
            transport_cfg.max_idle_timeout(Some(idle));
        }
        transport_cfg.keep_alive_interval(
            self.config
                .transport
                .http3_keep_alive_interval_ms
                .map(Duration::from_millis),
        );
        client_cfg.transport_config(Arc::new(transport_cfg));
        endpoint.set_default_client_config(client_cfg);

        let connect_timeout = Duration::from_millis(self.config.transport.http3_connect_timeout_ms);

        let mut last_err: Option<EngineError> = None;
        for ip in ips {
            let addr = SocketAddr::new(ip, port);

            let connecting = endpoint
                .connect(addr, &host)
                .map_err(|e| EngineError::Internal(format!("quinn connect failed: {e}")))?;
            let conn = match tokio::time::timeout(connect_timeout, connecting).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    last_err = Some(EngineError::Internal(format!("quinn connect error: {e}")));
                    continue;
                }
                Err(_) => {
                    last_err = Some(EngineError::Internal(format!(
                        "quinn connect timeout to {addr}"
                    )));
                    continue;
                }
            };

            let conn = h3_quinn::Connection::new(conn);
            let (mut h3_conn, mut send_request) = h3::client::new(conn)
                .await
                .map_err(|e| EngineError::Internal(format!("h3 client init failed: {e}")))?;
            let driver = tokio::spawn(async move {
                let _ = poll_fn(|cx| h3_conn.poll_close(cx)).await;
            });

            let http_req = request_to_http_request(&parsed, &request)?;
            let mut stream = send_request
                .send_request(http_req)
                .await
                .map_err(|e| EngineError::Internal(format!("h3 send_request failed: {e}")))?;

            if !request.body.is_empty() {
                stream
                    .send_data(Bytes::from(request.body.clone()))
                    .await
                    .map_err(|e| EngineError::Internal(format!("h3 send_data failed: {e}")))?;
            }
            stream
                .finish()
                .await
                .map_err(|e| EngineError::Internal(format!("h3 finish failed: {e}")))?;

            let resp = stream
                .recv_response()
                .await
                .map_err(|e| EngineError::Internal(format!("h3 recv_response failed: {e}")))?;

            let mut body = Vec::new();
            let mut downloaded: u64 = 0;
            let max_bytes = (self.config.download.max_response_body_mb as u64) * 1024 * 1024;
            let request_timeout = Duration::from_millis(self.config.transport.http3_request_timeout_ms);

            loop {
                let chunk_res = tokio::time::timeout(request_timeout, stream.recv_data()).await;
                let mut chunk = match chunk_res {
                    Ok(Ok(Some(c))) => c,
                    Ok(Ok(None)) => break,
                    Ok(Err(e)) => {
                        return Err(EngineError::Internal(format!("h3 recv_data failed: {e}")));
                    }
                    Err(_) => {
                        return Err(EngineError::Internal("HTTP/3 data transfer timeout".to_owned()));
                    }
                };

                let n = chunk.remaining();
                if downloaded + (n as u64) > max_bytes {
                    driver.abort();
                    return Err(EngineError::Internal(format!(
                        "HTTP/3 response body exceeded limit of {} MB",
                        self.config.download.max_response_body_mb
                    )));
                }
                let bytes = chunk.copy_to_bytes(n);
                downloaded += bytes.len() as u64;
                if let Some(h) = &progress {
                    h(downloaded, 0, 0.0);
                }
                body.extend_from_slice(&bytes);
            }

            driver.abort();
            return Ok(response_to_response_data(&resp, body));
        }

        Err(last_err.unwrap_or_else(|| {
            EngineError::Internal(format!("HTTP/3 connect failed for '{host}:{port}'"))
        }))
    }

    pub(super) async fn fetch_http3_stream(&self, request: RequestData) -> Result<ResponseStream> {
        use tokio::io::AsyncWriteExt;

        let parsed = Url::parse(&request.url)?;
        if parsed.scheme() != "https" {
            return Err(EngineError::InvalidInput(
                "HTTP/3 requires https:// URL".to_owned(),
            ));
        }

        let (host, port) = url_authority(&parsed)?;
        let ips = self.resolver_chain.resolve(&host).await?;
        if ips.is_empty() {
            return Err(EngineError::Internal(format!(
                "DNS returned no addresses for '{host}'"
            )));
        }

        // Lazy initialize or use shared endpoint if available
        let mut endpoint = {
            let mut guard = self.h3_endpoint.lock();
            if let Some(ep) = &*guard {
                ep.clone()
            } else {
                let ep = bind_quinn_endpoint()?;
                *guard = Some(ep.clone());
                ep
            }
        };
        let tls_cfg = build_rustls_config_http3(self)?;
        let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg)
            .map_err(|e| EngineError::Internal(format!("quic tls config failed: {e}")))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));

        let mut transport_cfg = quinn::TransportConfig::default();
        if let Ok(idle) =
            Duration::from_millis(self.config.transport.http3_idle_timeout_ms).try_into()
        {
            transport_cfg.max_idle_timeout(Some(idle));
        }
        transport_cfg.keep_alive_interval(
            self.config
                .transport
                .http3_keep_alive_interval_ms
                .map(Duration::from_millis),
        );
        client_cfg.transport_config(Arc::new(transport_cfg));
        endpoint.set_default_client_config(client_cfg);

        let connect_timeout = Duration::from_millis(self.config.transport.http3_connect_timeout_ms);

        let mut last_err: Option<EngineError> = None;
        for ip in ips {
            let addr = SocketAddr::new(ip, port);

            let connecting = endpoint
                .connect(addr, &host)
                .map_err(|e| EngineError::Internal(format!("quinn connect failed: {e}")))?;
            let conn = match tokio::time::timeout(connect_timeout, connecting).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    last_err = Some(EngineError::Internal(format!("quinn connect error: {e}")));
                    continue;
                }
                Err(_) => {
                    last_err = Some(EngineError::Internal(format!(
                        "quinn connect timeout to {addr}"
                    )));
                    continue;
                }
            };

            let conn = h3_quinn::Connection::new(conn);
            let (mut h3_conn, mut send_request) = h3::client::new(conn)
                .await
                .map_err(|e| EngineError::Internal(format!("h3 client init failed: {e}")))?;
            let driver = tokio::spawn(async move {
                let _ = poll_fn(|cx| h3_conn.poll_close(cx)).await;
            });

            let http_req = request_to_http_request(&parsed, &request)?;
            let mut stream = send_request
                .send_request(http_req)
                .await
                .map_err(|e| EngineError::Internal(format!("h3 send_request failed: {e}")))?;

            if !request.body.is_empty() {
                stream
                    .send_data(Bytes::from(request.body.clone()))
                    .await
                    .map_err(|e| EngineError::Internal(format!("h3 send_data failed: {e}")))?;
            }
            stream
                .finish()
                .await
                .map_err(|e| EngineError::Internal(format!("h3 finish failed: {e}")))?;

            let resp = stream
                .recv_response()
                .await
                .map_err(|e| EngineError::Internal(format!("h3 recv_response failed: {e}")))?;

            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let headers = response_to_header_map(&resp);

            // Bridge the HTTP/3 body into an `AsyncRead` using an in-memory duplex pipe.
            // This avoids `Unpin` issues with `StreamReader` + `async` streams.
            let (mut writer, reader) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let _endpoint = endpoint; // keep UDP socket alive
                let driver = driver;
                let mut stream = stream;

                while let Ok(Some(chunk)) = stream.recv_data().await {
                    let mut chunk = chunk;
                    let n = chunk.remaining();
                    let bytes = chunk.copy_to_bytes(n);
                    if writer.write_all(&bytes).await.is_err() {
                        break;
                    }
                }

                let _ = writer.shutdown().await;
                driver.abort();
            });

            return Ok(ResponseStream {
                status,
                headers,
                stream: Box::new(reader),
            });
        }

        Err(last_err.unwrap_or_else(|| {
            EngineError::Internal(format!("HTTP/3 connect failed for '{host}:{port}'"))
        }))
    }
}
