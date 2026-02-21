# Публичный API (Rust + FFI)

Документ фиксирует актуальные точки входа и контракт поведения.

## Cargo features

- `hickory-dns`: DoH/DoT/DoQ через `hickory-resolver`.
- `websocket`: WebSocket клиент.
- `observability`: tracing/metrics.

По умолчанию включены все три.

## Rust API

Основные экспортируемые типы:

- `EngineConfig`
- `PrimeEngine`
- `PrimeHttpClient`
- `RequestData`, `ResponseData`, `ResponseStream`
- `DownloadOutcome`
- `TlsConfig`, `TlsVersion`, `Ja3Fingerprint`
- `WebSocketClient`, `WsConfig`, `WsMessage` (при `websocket`)

Ключевые методы:

- `PrimeEngine::new(config).await -> Result<PrimeEngine>`
- `PrimeEngine::client(&self) -> Arc<PrimeHttpClient>`
- `PrimeHttpClient::new(config) -> Result<PrimeHttpClient>`
- `PrimeHttpClient::fetch(request, progress).await -> Result<ResponseData>`
- `PrimeHttpClient::fetch_stream(request).await -> Result<ResponseStream>`
- `PrimeHttpClient::download_to_path(request, path, progress).await -> Result<DownloadOutcome>`
- `PrimeHttpClient::websocket_client(ws_cfg) -> WebSocketClient`

## FFI API

Заголовок: `include/prime_net.h`

### Engine lifecycle

- `prime_engine_new(const char* config_path) -> PrimeEngine*`
- `prime_engine_free(PrimeEngine* engine)`
- `prime_last_error_message(void) -> const char*`

`config_path == NULL` означает `EngineConfig::default()`.

### Sync request

- `prime_engine_fetch(engine, request, callback, user_data) -> PrimeResponse*`

Блокирует вызывающий поток до завершения.

### Async request

- `prime_engine_fetch_async(engine, request, callback, user_data) -> PrimeRequestHandle*`
- `prime_request_wait(handle, timeout_ms) -> PrimeResponse*`
- `prime_request_cancel(handle) -> PrimeResult`
- `prime_request_status(handle) -> PrimeRequestStatus`
- `prime_request_free(handle)`

Статусы:

- `PENDING`
- `RUNNING`
- `COMPLETED`
- `CANCELLED`
- `FAILED`

### Ownership

- `PrimeResponse*` всегда освобождается через `prime_response_free`.
- `prime_request_wait`:
  - при успехе освобождает handle и возвращает response;
  - при timeout возвращает ошибку `"timeout"`, handle остается валиден.
- `prime_request_free` освобождает handle без ожидания (best-effort cancel).

### Error model

`PrimeResponse`:

- `error_code == 0` и `error_message == NULL` при успехе.
- иначе `error_code != 0` и заполнен `error_message`.

Коды:

- `PRIME_OK` (0)
- `PRIME_ERR_NULL_PTR` (1)
- `PRIME_ERR_INVALID_UTF8` (2)
- `PRIME_ERR_INVALID_REQUEST` (3)
- `PRIME_ERR_RUNTIME` (4)

## Execution model (FFI runtime)

- В `prime_engine_new` создается отдельный runtime thread (`tokio` multi-thread).
- Запросы кладутся в thread-safe очередь.
- Каждый запрос исполняется отдельной async task.
- Параллелизм поддерживается и для sync, и для async вызовов.
