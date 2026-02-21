# API (Rust + FFI)

## Cargo features

Дефолтно включены:

- `hickory-dns`
- `websocket`
- `observability`

Дополнительные:

- `signature-verification` (подписи обновлений через `gpgme`)
- `require-signatures` (зависит от `signature-verification`)

## Публичные Rust экспорты

Из `src/lib.rs` реэкспортируются:

- конфиг/ошибки: `EngineConfig`, `TransportConfig`, `EngineError`, `Result`
- ядро: `PrimeEngine`, `PrimeHttpClient`, `RequestData`, `ResponseData`, `ResponseStream`, `DownloadOutcome`
- observability: `init_observability`, `ObservabilityConfig`, `ObservabilityGuard`
- TLS: `TlsConfig`, `TlsVersion`, `Ja3Fingerprint`
- SSE: `SseConfig`, `SseEvent`, `SseStream`
- UDP tunnel: `UdpOverTcpTunnel`, `UdpOverTcpConfig`, `UdpDatagram`, `UdpTargetAddr`
- WebSocket: `WebSocketClient`, `WsConfig`, `WsMessage`

## Ключевые методы

- `PrimeEngine::new(config).await -> Result<PrimeEngine>`
- `PrimeEngine::client(&self) -> Arc<PrimeHttpClient>`
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

`config_path == NULL` -> используется `EngineConfig::default()`.

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

### Ошибки FFI

Коды в `PrimeResponse.error_code`:

- `PRIME_OK` (0)
- `PRIME_ERR_NULL_PTR` (1)
- `PRIME_ERR_INVALID_UTF8` (2)
- `PRIME_ERR_INVALID_REQUEST` (3)
- `PRIME_ERR_RUNTIME` (4)

### Ownership

- `PrimeResponse*` освобождается только через `prime_response_free`.
- `prime_request_wait` при успехе освобождает handle.
- при timeout `prime_request_wait` возвращает ошибку `"timeout"`, handle остаётся валиден.

## Модель выполнения FFI

- при `prime_engine_new` запускается отдельный runtime-thread (`tokio` multi-thread);
- запросы идут через очередь в runtime;
- для async запросов поддерживаются cancel/status/wait.
