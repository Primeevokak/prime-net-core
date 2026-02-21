# USAGE FFI (C ABI)

## Файлы и артефакты

- заголовок: `include/prime_net.h`
- пример: `examples/c_integration/main.c`

Сборка:

```bash
cargo build --release
```

Выходные артефакты (имя библиотеки = `prime_net_engine_core`):

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

## Sync запрос

```c
PrimeResponse* prime_engine_fetch(
    PrimeEngine* engine,
    const PrimeRequest* request,
    ProgressCallback callback,
    void* user_data
);
```

## Async запрос

1. `prime_engine_fetch_async(...) -> PrimeRequestHandle*`
2. `prime_request_wait(handle, timeout_ms)`
3. при необходимости `prime_request_cancel`, `prime_request_status`, `prime_request_free`

`timeout_ms = 0` означает ждать бесконечно.

При timeout:

- `prime_request_wait` возвращает response с ошибкой `"timeout"`;
- handle остаётся валиден и можно ждать повторно.

## Коды ошибок

- `PRIME_OK`
- `PRIME_ERR_NULL_PTR`
- `PRIME_ERR_INVALID_UTF8`
- `PRIME_ERR_INVALID_REQUEST`
- `PRIME_ERR_RUNTIME`

## Ownership и потокобезопасность

- `PrimeResponse*` всегда освобождать через `prime_response_free`.
- `PrimeRequestHandle*` освобождать через `prime_request_free`, если не был поглощён `prime_request_wait`.
- `PrimeEngine*` можно использовать из нескольких потоков; внутри работает runtime thread с очередью задач.

## Progress callback

`ProgressCallback(downloaded, total, speed_mbps, user_data)` вызывается best-effort во время загрузки. Если callback не нужен, передавайте `NULL`.
