# PRIVACY

Privacy layer применяется внутри HTTP pipeline и полностью управляется конфигом секции `[privacy]`.

## Что делает privacy layer

### 1. Tracker blocker

Секция: `[privacy.tracker_blocker]`.

- проверяет host и URL-паттерны до отправки запроса;
- встроенные списки (`easyprivacy`, `easylist`, `ublock`) + кастомные файлы;
- режимы:
  - `block`
  - `log_only`
- действие при блокировке:
  - `error`
  - `empty_200`
- `allowlist` исключает домены из блокировки.

### 2. Referer policy

Секция: `[privacy.referer]`.

- `strip`
- `origin_only`
- `pass_through`

Дополнительно: `strip_from_search_engines` и пользовательский список поисковых доменов.

### 3. Privacy signals

Секция: `[privacy.signals]`.

- `DNT: 1`
- `Sec-GPC: 1`

### 4. Privacy headers overrides

Дополнительные секции:

- `[privacy.user_agent]`
- `[privacy.referer_override]`
- `[privacy.ip_spoof]`
- `[privacy.webrtc]`
- `[privacy.location_api]`

Эти настройки изменяют исходящие заголовки (`User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`, `Permissions-Policy`).

## Поведение при блокировке

Если tracker blocker сработал:

- при `on_block = error` возвращается `BlockedByPrivacyPolicy`;
- при `on_block = empty_200` запрос не уходит в сеть, возвращается пустой ответ `200` с заголовком `X-Prime-Privacy: tracker_blocked`.

## Логирование

Privacy-решения маркируются тегами:

- `[BLOCKED]`
- `[PRIVACY]`
- `[TRACKER]`

Их можно фильтровать в TUI (`Logs`) или в внешнем сборщике логов.

## Ограничения

- Это уровень HTTP клиента, а не системная анонимизация.
- Не защищает от browser fingerprinting (canvas/fonts/WebGL и т.п.).
- Не предотвращает корреляцию трафика сильным противником.
