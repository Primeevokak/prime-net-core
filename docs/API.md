# API (Rust + FFI)

## Cargo features

По умолчанию включены:

- `hickory-dns`
- `websocket`
- `observability`

Дополнительно:

- `tun` (TUN/VPN режим, требует `tun2` + `smoltcp`)
- `signature-verification` (проверка подписей обновлений через `gpgme`)
- `require-signatures` (зависит от `signature-verification`)

Примечание: для `signature-verification` в среде сборки должны быть доступны системные зависимости `gpgme/gpg-error` (обычно через `pkg-config`).

## Публичные реэкспорты (`src/lib.rs`)

- Конфиг и ошибки: `EngineConfig`, `TransportConfig`, `EngineError`, `Result`
- Ядро: `PrimeEngine`, `PrimeHttpClient`, `RequestData`, `ResponseData`, `ResponseStream`, `DownloadOutcome`
- Observability: `init_observability`, `ObservabilityConfig`, `ObservabilityGuard`
- TLS: `TlsConfig`, `TlsVersion`, `Ja3Fingerprint`
- SSE: `SseConfig`, `SseEvent`, `SseStream`
- UDP tunnel: `UdpOverTcpTunnel`, `UdpOverTcpConfig`, `UdpDatagram`, `UdpTargetAddr`
- WebSocket: `WebSocketClient`, `WsConfig`, `WsMessage`

## Ключевые Rust методы

- `PrimeEngine::new(config).await -> Result<PrimeEngine>`
- `PrimeEngine::client(&self) -> Arc<PrimeHttpClient>`
- `PrimeEngine::pt_socks5_addr(&self) -> Option<SocketAddr>`
- `PrimeHttpClient::new(config) -> Result<PrimeHttpClient>`
- `PrimeHttpClient::fetch(request, progress).await -> Result<ResponseData>`
- `PrimeHttpClient::fetch_stream(request).await -> Result<ResponseStream>`
- `PrimeHttpClient::download_to_path(request, path, progress).await -> Result<DownloadOutcome>`
- `PrimeHttpClient::websocket_client(ws_cfg) -> WebSocketClient`
- `Arc<PrimeHttpClient>::sse_connect(request, cfg) -> Result<SseStream>`

## FFI (C ABI)

Заголовок: `include/prime_net.h`.

### Lifecycle

- `prime_engine_new(const char* config_path) -> PrimeEngine*`
- `prime_engine_free(PrimeEngine*)`
- `prime_last_error_message(void) -> const char*`

`config_path == NULL` → используется `EngineConfig::default()`.

### Sync request

- `prime_engine_fetch(engine, request, callback, user_data) -> PrimeResponse*`

### Async request

- `prime_engine_fetch_async(...) -> PrimeRequestHandle*`
- `prime_request_wait(handle, timeout_ms) -> PrimeResponse*`
- `prime_request_cancel(handle) -> PrimeResult`
- `prime_request_status(handle) -> PrimeRequestStatus`
- `prime_request_free(handle)`

Статусы:

- `PRIME_REQUEST_STATUS_PENDING`
- `PRIME_REQUEST_STATUS_RUNNING`
- `PRIME_REQUEST_STATUS_COMPLETED`
- `PRIME_REQUEST_STATUS_CANCELLED`
- `PRIME_REQUEST_STATUS_FAILED`

### FFI error codes

`PrimeResponse.error_code`:

- `PRIME_OK` (`0`)
- `PRIME_ERR_NULL_PTR` (`1`)
- `PRIME_ERR_INVALID_UTF8` (`2`)
- `PRIME_ERR_INVALID_REQUEST` (`3`)
- `PRIME_ERR_RUNTIME` (`4`)

### Ownership / memory

- `PrimeResponse*` освобождается только через `prime_response_free`.
- `PrimeRequestHandle*` освобождается через `prime_request_free`.
- `prime_request_wait` не освобождает handle автоматически: после завершения запроса handle остается валиден до `prime_request_free`.
- При timeout handle остается валиден, можно ждать повторно.

## Модель выполнения FFI

- `prime_engine_new` поднимает отдельный runtime-thread (`tokio`).
- Запросы передаются в runtime через очередь.
- `cancel/status/wait` работают поверх того же async runtime.
