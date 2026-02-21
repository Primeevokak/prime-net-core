# QUICKSTART

## 1. Сборка

```bash
cargo build --release --bin prime-net-engine --bin prime-tui
```

Бинарники:

- `target/release/prime-net-engine`
- `target/release/prime-tui`

## 2. Создать конфиг

Вариант A (рекомендуется):

```bash
prime-net-engine wizard --out prime-net-engine.toml
```

Вариант B (шаблон):

```bash
cp config.example.toml prime-net-engine.toml
```

## 3. Проверить конфиг

Онлайн-проверка (валидация + DoH/fronting probes):

```bash
prime-net-engine --config prime-net-engine.toml --config-check
```

Только локальная валидация (без сети):

```bash
prime-net-engine --config prime-net-engine.toml --config-check --offline
```

## 4. Запустить локальный SOCKS5

```bash
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
```

## 5. Включить системный прокси

```bash
prime-net-engine --config prime-net-engine.toml proxy enable --mode all
```

Проверка статуса:

```bash
prime-net-engine --config prime-net-engine.toml proxy status
```

## 6. Проверить связность

```bash
prime-net-engine --config prime-net-engine.toml test --url https://example.com
```

## 7. Запуск TUI

```bash
prime-net-engine --config prime-net-engine.toml tui
```

Горячие клавиши:

- `q` - выход
- `Tab` - следующая вкладка
- `m` - режим интерфейса (`simple`/`advanced`)
- `?` - контекстная справка

## 8. Базовый сервисный цикл

- Обновить blocklist: `prime-net-engine --config prime-net-engine.toml blocklist update`
- Проверить blocklist: `prime-net-engine --config prime-net-engine.toml blocklist status`
- Проверить обновления: `prime-net-engine --config prime-net-engine.toml update check`

Подробности: `docs/USER_GUIDE.md` и `docs/TROUBLESHOOTING.md`.
