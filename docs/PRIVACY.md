# PRIVACY

Privacy layer применяется внутри HTTP pipeline и управляется секцией `[privacy]`.

## Подсистемы

### 1. Tracker blocker (`[privacy.tracker_blocker]`)

Что делает:

- сопоставляет host и URL с доменными/keyword правилами;
- поддерживает built-in list aliases: `easyprivacy`, `easylist`, `ublock`, `ublock_origin`;
- поддерживает custom lists (файлы), включая базовый парсинг host-like и adblock-style `||domain^` правил;
- учитывает `allowlist` (домен и поддомены).

Режимы:

- `mode = block|log_only`
- `on_block = error|empty_200`

Поведение:

- `error`: запрос блокируется ошибкой `BlockedByPrivacyPolicy`.
- `empty_200`: сеть не вызывается, возвращается пустой `200` с `X-Prime-Privacy: tracker_blocked`.
- `log_only`: совпадение логируется, запрос пропускается.

### 2. Referer policy (`[privacy.referer]`)

- `strip`
- `origin_only`
- `pass_through`

Дополнительно: `strip_from_search_engines`, `search_engine_domains`.

### 3. Privacy signals (`[privacy.signals]`)

- `DNT: 1`
- `Sec-GPC: 1`

### 4. Header overrides

- `[privacy.user_agent]`
- `[privacy.referer_override]`
- `[privacy.ip_spoof]`
- `[privacy.webrtc]`
- `[privacy.location_api]`

Могут менять `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`, `Permissions-Policy`.

## Логирование privacy-событий

В логах используются target/метки вида:

- `privacy.tracker`
- `privacy.referer`
- `privacy.signals`
- текстовые метки `[BLOCKED]`, `[PRIVACY]`, `[TRACKER]`

## Ограничения

- Это HTTP client middleware, а не полная системная анонимизация.
- Не покрывает browser/device fingerprinting (canvas/fonts/webgl и т.п.).
- Не защищает от глобального traffic correlation.
