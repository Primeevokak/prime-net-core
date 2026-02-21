# CLI `prime-net-engine`

Документ отражает текущее поведение CLI из `src/bin/prime-net-engine/main.rs`.

## Сборка

```bash
cargo build --release --bin prime-net-engine --bin prime-tui
```

## Базовый синтаксис

```bash
prime-net-engine [GLOBAL_OPTS] <command> [command_opts]
```

Глобальные опции:

- `--config <path>`: путь к конфигу (`.toml/.json/.yaml`).
- `--preset <name>`: применить пресет `strict-privacy|balanced-privacy|max-compatibility|aggressive-evasion`.
- `--config-check`: проверить конфиг и сетевые probes (DoH/fronting).
- `--offline`: отключить сетевые probes в `--config-check`.
- `--probe-domain <domain>`: домен для DoH probe (`example.com` по умолчанию).
- `--log-level <lvl>`: `error|warn|info|debug|trace`.
- `--log-format <fmt>`: `text|json`.
- `--log-file <path>`: писать логи в файл.
- `--log-rotation <rot>`: `never|daily|hourly|minutely`.

## Команды

### `fetch`

```bash
prime-net-engine --config cfg.toml fetch https://example.com/ --print-headers --out -
```

Опции:

- `--method <METHOD>` (по умолчанию `GET`)
- `-H, --header "Key: Value"` (повторяемый)
- `--body <string>`
- `--body-file <path>`
- `--out <path|->`
- `--print-headers`

### `download`

```bash
prime-net-engine --config cfg.toml download https://example.com/file.bin --out file.bin
```

Опции:

- `--out <path>` (обязательно)

### `socks`

```bash
prime-net-engine --config cfg.toml socks --bind 127.0.0.1:1080 --silent-drop
```

Опции:

- `--bind <host:port>`
- `--silent-drop`

### `wizard`

```bash
prime-net-engine wizard --out prime-net-engine.toml --force
```

Опции:

- `--out <path>` (по умолчанию `prime-net-engine.toml`)
- `--force`

### `tui`

```bash
prime-net-engine --config prime-net-engine.toml tui
```

Опции:

- `--config <path>`

Запускает отдельный бинарник `prime-tui`.

### `proxy`

```bash
prime-net-engine --config cfg.toml proxy enable --mode all
prime-net-engine --config cfg.toml proxy enable --mode pac
prime-net-engine --config cfg.toml proxy enable --mode custom --pac-url http://127.0.0.1:8888/proxy.pac
prime-net-engine --config cfg.toml proxy status
prime-net-engine --config cfg.toml proxy disable
prime-net-engine --config cfg.toml proxy generate-pac --output proxy.pac
prime-net-engine --config cfg.toml proxy serve-pac --port 8888
```

Подкоманды:

- `enable --mode <all|pac|custom> [--pac-url <url>]`
- `disable`
- `status`
- `generate-pac --output <path> [--socks-endpoint <host:port>]`
- `serve-pac --port <n> [--socks-endpoint <host:port>]`

### `blocklist`

```bash
prime-net-engine --config cfg.toml blocklist update
prime-net-engine --config cfg.toml blocklist update --source https://example.com/list.txt
prime-net-engine --config cfg.toml blocklist status
```

Подкоманды:

- `update [--source <url>]`
- `status`

### `update`

```bash
prime-net-engine --config cfg.toml update check
prime-net-engine --config cfg.toml update check --channel beta
prime-net-engine --config cfg.toml update install
prime-net-engine --config cfg.toml update install --version 0.3.0
prime-net-engine --config cfg.toml update rollback
```

Подкоманды:

- `check [--channel <stable|beta|nightly>]`
- `install [--version <semver>]`
- `rollback`

### `test`

```bash
prime-net-engine --config cfg.toml test --url https://example.com
prime-net-engine --config cfg.toml test https://example.com --check-leaks
```

Опции:

- `--url <url>` (или позиционный URL как первый аргумент)
- `--check-leaks`

## Быстрые практики

- Для первичной настройки: `wizard` -> `--config-check` -> `socks` -> `proxy enable`.
- Для консервативного запуска через пресет: `--preset max-compatibility`.
- Для максимального anti-censorship профиля: `--preset aggressive-evasion`.
- Для автоматизации/сбора: используйте `--log-format json` + `--log-file`.
