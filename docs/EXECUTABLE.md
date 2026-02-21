# CLI `prime-net-engine`

Документ соответствует `src/bin/prime-net-engine/main.rs`.

## Формат запуска

```text
prime-net-engine [GLOBAL_OPTS] <command> [command_opts]
```

`-h` / `--help` выводит встроенную справку.

## Глобальные опции

- `--config <path>`: путь к конфигу (TOML/JSON/YAML).
- `--preset <name>`: `strict-privacy|balanced-privacy|max-compatibility|aggressive-evasion`.
- `--config-check`: валидация конфига + probes (DoH/fronting).
- `--offline`: только для `--config-check`, пропустить сетевые probes.
- `--probe-domain <domain>`: домен для DoH probe (по умолчанию `example.com`).
- `--log-level <lvl>`: `error|warn|info|debug|trace`.
- `--log-format <fmt>`: `text|json`.
- `--log-file <path>`: писать логи в файл.
- `--log-rotation <rot>`: `never|daily|hourly|minutely`.

## Команды

### `fetch`

```text
prime-net-engine [GLOBAL_OPTS] fetch <url> [FETCH_OPTS]
```

`FETCH_OPTS`:

- `--method <METHOD>` (по умолчанию `GET`)
- `-H, --header "Key: Value"` (повторяемый)
- `--body <string>`
- `--body-file <path>`
- `--out <path>` или `--out -` для stdout
- `--print-headers`

### `download`

```text
prime-net-engine [GLOBAL_OPTS] download <url> --out <path>
```

### `socks`

```text
prime-net-engine [GLOBAL_OPTS] socks [SOCKS_OPTS]
```

`SOCKS_OPTS`:

- `--bind <host:port>` (по умолчанию `127.0.0.1:1080`)
- `--silent-drop`

### `wizard`

```text
prime-net-engine [GLOBAL_OPTS] wizard [--out <path>] [--force]
```

### `tui`

```text
prime-net-engine [GLOBAL_OPTS] tui [--config <path>]
```

Запускает соседний бинарник `prime-tui`.

### `proxy`

```text
prime-net-engine [GLOBAL_OPTS] proxy <subcommand> [opts]
```

Подкоманды:

- `enable --mode <all|pac|custom> [--pac-url <url>]`
- `disable`
- `status`
- `generate-pac --output <path> [--socks-endpoint <host:port>]`
- `serve-pac --port <n> [--socks-endpoint <host:port>]`

### `blocklist`

```text
prime-net-engine [GLOBAL_OPTS] blocklist <update|status>
```

- `update [--source <url>]`
- `status`

### `update`

```text
prime-net-engine [GLOBAL_OPTS] update <check|install|rollback> [opts]
```

- `check [--channel <stable|beta|nightly>]`
- `install [--version <v>]`
- `rollback`

### `test`

```text
prime-net-engine [GLOBAL_OPTS] test [--url <url>] [--check-leaks]
```

Также поддерживается позиционный URL первым аргументом: `test https://example.com`.

## Примеры

```bash
prime-net-engine --config cfg.toml --config-check
prime-net-engine --config cfg.toml fetch https://example.com --print-headers --out -
prime-net-engine --config cfg.toml download https://example.com/file.bin --out file.bin
prime-net-engine --config cfg.toml socks --bind 127.0.0.1:1080
prime-net-engine --config cfg.toml proxy enable --mode all
prime-net-engine --config cfg.toml blocklist update
prime-net-engine --config cfg.toml update check --channel beta
prime-net-engine --config cfg.toml test --url https://example.com --check-leaks
```

## Что важно знать

- Неиспользуемые/неизвестные флаги приводят к ошибке `InvalidInput`.
- `download` требует обязательный `--out`.
- В `proxy enable --mode custom` обязателен `--pac-url`.
- Отдельного флага `--version` в CLI нет.
