# CLI `prime-net-engine`

Источник истины: `src/bin/prime-net-engine/main.rs`.

## Формат запуска

```text
prime-net-engine [GLOBAL_OPTS] <command> [command_opts]
```

`-h` / `--help` выводит встроенную справку.

## Глобальные опции

- `--config <path>`
- `--preset <strict-privacy|balanced-privacy|max-compatibility|aggressive-evasion>`
- `--config-check`
- `--offline` (только вместе с `--config-check`)
- `--probe-domain <domain>` (default: `example.com`)
- `--log-level <error|warn|info|debug|trace>`
- `--log-format <text|json>`
- `--log-file <path>`
- `--log-rotation <never|daily|hourly|minutely>`

## Команды

### `fetch`

```text
prime-net-engine [GLOBAL_OPTS] fetch <url> [FETCH_OPTS]
```

`FETCH_OPTS`:

- `--method <METHOD>`
- `-H, --header "Key: Value"` (повторяемый)
- `--body <string>`
- `--body-file <path>`
- `--out <path>` (или `-` для stdout)
- `--print-headers`

### `download`

```text
prime-net-engine [GLOBAL_OPTS] download <url> --out <path>
```

Поддерживает возобновление прерванной загрузки.

### `socks`

```text
prime-net-engine [GLOBAL_OPTS] socks [SOCKS_OPTS]
```

`SOCKS_OPTS`:

- `--bind <host:port>` (default: `127.0.0.1:1080`)
- `--silent-drop`

### `wizard`

```text
prime-net-engine [GLOBAL_OPTS] wizard [--out <path>] [--force]
```

### `tui`

```text
prime-net-engine [GLOBAL_OPTS] tui [--config <path>]
```

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

Также поддерживается позиционный URL: `test https://example.com`.

### `tun`

```text
prime-net-engine [GLOBAL_OPTS] tun [TUN_OPTS]
```

Доступна только при сборке с `--features tun`. Запускает VPN/TUN режим через виртуальный сетевой интерфейс (`tun2` + `smoltcp`).

## Примеры

```bash
prime-net-engine --config cfg.toml --config-check
prime-net-engine --config cfg.toml --config-check --offline

prime-net-engine --config cfg.toml fetch https://example.com --print-headers --out -
prime-net-engine --config cfg.toml download https://example.com/file.bin --out file.bin

prime-net-engine --config cfg.toml socks --bind 127.0.0.1:1080
prime-net-engine --config cfg.toml proxy enable --mode all
prime-net-engine --config cfg.toml proxy status

prime-net-engine --config cfg.toml blocklist update
prime-net-engine --config cfg.toml update check --channel beta
prime-net-engine --config cfg.toml test --url https://example.com --check-leaks
```

## Важные замечания

- Неизвестные флаги/аргументы завершаются ошибкой `InvalidInput`.
- Для `download` параметр `--out` обязателен.
- Для `proxy enable --mode custom` параметр `--pac-url` обязателен.
- Отдельного флага `--version` в CLI нет.
- `tun` требует компиляции с `--features tun`.
