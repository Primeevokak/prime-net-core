# Использование FFI (C ABI)

Подходит для C/C++/Go/Java/.NET интеграции.

## Что есть в репозитории

- заголовок: `include/prime_net.h`
- пример: `examples/c_integration/main.c`

## Сборка

```bash
cargo build --release
```

Артефакты в `target/release/`:

- Windows: `prime_net_engine.dll` (+ `prime_net_engine.lib`)
- Linux: `libprime_net_engine.so`
- macOS: `libprime_net_engine.dylib`
- также собирается `staticlib`

## Базовый lifecycle

1. `prime_engine_new(config_path)` создает engine.
2. Выполняете запросы (`prime_engine_fetch` или async API).
3. Освобождаете `PrimeResponse*` через `prime_response_free`.
4. Освобождаете engine через `prime_engine_free`.

При `prime_engine_new == NULL` читайте `prime_last_error_message()`.

## Sync API

- `prime_engine_fetch(engine, request, callback, user_data) -> PrimeResponse*`

Вызов блокирующий, подходит для простого request/response сценария.

## Async API

1. `prime_engine_fetch_async(...) -> PrimeRequestHandle*`
2. `prime_request_wait(handle, timeout_ms) -> PrimeResponse*`
3. При необходимости:
   - `prime_request_cancel(handle)`
   - `prime_request_status(handle)`
   - `prime_request_free(handle)`

Поведение `prime_request_wait`:

- `timeout_ms == 0`: ждать бесконечно;
- при timeout возвращается response с ошибкой `"timeout"`, handle остается валиден;
- при успешном завершении handle освобождается внутри `prime_request_wait`.

## Потокобезопасность

- `PrimeEngine*` допускает вызовы из нескольких потоков.
- Запросы выполняются параллельно на внутреннем `tokio` runtime thread.
- Ответственность за корректное освобождение `PrimeResponse*` и handle остается на стороне интеграции.

## Progress callback

`ProgressCallback(downloaded, total, speed_mbps, user_data)` вызывается best-effort во время загрузки.

Если callback не нужен, передавайте `NULL`.

## Коды ошибок

- `PRIME_OK` (0)
- `PRIME_ERR_NULL_PTR` (1)
- `PRIME_ERR_INVALID_UTF8` (2)
- `PRIME_ERR_INVALID_REQUEST` (3)
- `PRIME_ERR_RUNTIME` (4)
