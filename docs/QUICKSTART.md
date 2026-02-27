# QUICKSTART

## 1. Сборка

```bash
cargo build --release --bin prime-net-engine --bin prime-tui
```

Бинарники:

- `target/release/prime-net-engine`
- `target/release/prime-tui`

## 2. Создание конфига

Интерактивно (рекомендуется):

```bash
prime-net-engine wizard --out prime-net-engine.toml
```

## 3. Проверка конфига

Онлайн-валидация + probes:

```bash
prime-net-engine --config prime-net-engine.toml --config-check
```

Офлайн (без сети):

```bash
prime-net-engine --config prime-net-engine.toml --config-check --offline
```

## 4. Запуск локального SOCKS5

```bash
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
```

## 5. Подключение системного прокси

```bash
prime-net-engine --config prime-net-engine.toml proxy enable --mode all
prime-net-engine --config prime-net-engine.toml proxy status
```

## 6. Тест связности

```bash
prime-net-engine --config prime-net-engine.toml test --url https://example.com
```

## 7. Запуск TUI

```bash
prime-net-engine --config prime-net-engine.toml tui
```

## 8. Минимальный preflight перед коммитом

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test -p prime-net-engine --lib --no-run
```
