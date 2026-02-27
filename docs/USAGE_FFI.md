# USAGE FFI (C ABI)

## Файлы и артефакты

- C header: `include/prime_net.h`
- пример: `examples/c_integration/main.c`

Сборка:

```bash
cargo build --release
```

Артефакты (`prime_net_engine_core`):

- Windows: `prime_net_engine_core.dll`, `prime_net_engine_core.lib`
- Linux: `libprime_net_engine_core.so`
- macOS: `libprime_net_engine_core.dylib`
- staticlib: `prime_net_engine_core.lib` (Windows) / `libprime_net_engine_core.a` (Unix)

## Минимальный lifecycle

1. `prime_engine_new(config_path)`
2. `prime_engine_fetch(...)` или async API
3. `prime_response_free(response)`
4. `prime_engine_free(engine)`

Если `prime_engine_new` вернул `NULL`, читайте `prime_last_error_message()`.

## Sync API

```c
PrimeResponse* prime_engine_fetch(
    PrimeEngine* engine,
    const PrimeRequest* request,
    ProgressCallback callback,
    void* user_data
);
```

## Async API

1. `prime_engine_fetch_async(...) -> PrimeRequestHandle*`
2. `prime_request_wait(handle, timeout_ms)`
3. опционально `prime_request_cancel(handle)`
4. `prime_request_status(handle)`
5. обязательно `prime_request_free(handle)`

`timeout_ms = 0` -> ждать бесконечно.

При timeout:

- `prime_request_wait` возвращает response с ошибкой `"timeout"`;
- handle остается валиден.

## Error codes

- `PRIME_OK`
- `PRIME_ERR_NULL_PTR`
- `PRIME_ERR_INVALID_UTF8`
- `PRIME_ERR_INVALID_REQUEST`
- `PRIME_ERR_RUNTIME`

## Ownership

- `PrimeResponse*` всегда освобождать через `prime_response_free`.
- `PrimeRequestHandle*` всегда освобождать через `prime_request_free`.
- `prime_request_wait` не освобождает handle автоматически.

## Progress callback

`ProgressCallback(downloaded, total, speed_mbps, user_data)` вызывается best-effort во время загрузки.

Если callback не нужен, передавайте `NULL`.
