# Архитектура

## Основные подсистемы

- `PrimeHttpClient` (`src/core/http_client.rs`) - HTTP(S) клиент и orchestration.
- `ResolverChain` (`src/anticensorship/resolver_chain.rs`) - цепочка DNS резолверов (DoH/DoT/DoQ/System).
- `PrimeReqwestDnsResolver` (`src/anticensorship/reqwest_dns.rs`) - интеграция `ResolverChain` в `reqwest`.
- Fronting:
  - v1: `src/anticensorship/fronting.rs`
  - v2: выбор front domain с probe/cache в `PrimeHttpClient`.
- Evasion:
  - `FragmentingIo` (`src/evasion/fragmenting_io.rs`)
  - traffic shaping / dpi bypass стратегии.
- PT stack: `src/pt/*` (trojan/shadowsocks/direct и SOCKS5 bridge).
- FFI runtime: `src/ffi/mod.rs`.

## HTTP pipeline (упрощенно)

1. Валидация запроса.
2. Применение default headers.
3. Применение fronting (если включено).
4. DNS через `ResolverChain`.
5. Выбор transport path:
   - обычный `reqwest`;
   - fragment/manual path (`TcpStream` + `tokio-rustls` + `hyper`) при evasion.
6. Возврат:
   - `fetch` -> `ResponseData` (body в памяти);
   - `fetch_stream` -> `ResponseStream` (streaming);
   - `download_to_path` -> streaming в файл (resume/chunk best-effort).

## Fragment path (актуально)

- Работает для `http://` и `https://`.
- Для `https://`:
  - делает TLS handshake через `tokio-rustls`;
  - ALPN определяет `h2` vs `http/1.1`;
  - затем handshakes `hyper` как HTTP/2 или HTTP/1.1.
- Для `http://`:
  - `hyper` HTTP/1.1 поверх fragmenting IO.
- Proxy ограничение:
  - поддерживается только `proxy.kind = "socks5"` для fragment path.
  - Иные proxy типы в fragment path возвращают config error.

## FFI execution model

- `prime_engine_new` запускает отдельный `tokio` runtime thread.
- Запросы приходят через thread-safe очередь.
- Каждая задача исполняется отдельным `tokio::spawn`.
- Async FFI поддерживает:
  - cancel (`prime_request_cancel`)
  - статус (`prime_request_status`)
  - неблокирующее освобождение handle (`prime_request_free`).

## Тестовый статус (важно для эксплуатации)

- Live smoke тесты по сети помечены `ignored` по умолчанию.
- `http3_local` на Windows помечен `ignored` из-за нестабильного локального QUIC loopback timeout.
