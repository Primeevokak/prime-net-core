# PRESETS

Пресеты применяются флагом `--preset <name>`.

Поддерживаемые значения:

- `strict-privacy`
- `balanced-privacy`
- `max-compatibility`
- `aggressive-evasion`

## Как применяются

В CLI применяется такая логика:

- если передан `--config`, пресет работает в `strict_conflicts` режиме;
- если некоторые поля уже вручную заданы значениями, конфликтующими и с дефолтом, и с пресетом, команда вернёт ошибку конфликта.

## Что меняет каждый пресет

### `strict-privacy`

- `anticensorship.system_dns_enabled = false`
- `anticensorship.dns_fallback_chain = [doh]`
- `anticensorship.doh_enabled = true`
- `anticensorship.dot_enabled = false`
- `anticensorship.doq_enabled = false`
- `anticensorship.ech_mode = real`
- `evasion.strategy = fragment`
- `privacy.tracker_blocker.enabled = true`
- `privacy.referer.enabled = true`
- `privacy.referer.mode = strip`
- `privacy.signals.send_dnt = true`
- `privacy.signals.send_gpc = true`

### `balanced-privacy`

- `privacy.tracker_blocker.enabled = false`
- `privacy.referer.enabled = true`
- `privacy.referer.mode = origin_only`
- `privacy.signals.send_dnt = false`
- `privacy.signals.send_gpc = true`

### `max-compatibility`

- `anticensorship.system_dns_enabled = true`
- `anticensorship.doh_enabled = true`
- `anticensorship.ech_mode = grease`
- `evasion.strategy = null`

### `aggressive-evasion`

- `anticensorship.system_dns_enabled = false`
- `anticensorship.doh_enabled = true`
- `anticensorship.dot_enabled = true`
- `anticensorship.doq_enabled = true`
- `anticensorship.dns_fallback_chain = [doh, dot, doq]`
- `anticensorship.ech_mode = auto`
- `evasion.strategy = auto`
- если `client_hello_split_offsets` пустой, ставится `[1, 5, 40, 64]`
- `evasion.split_at_sni = true`
- `evasion.fragment_sleep_ms = 0`
- `evasion.fragment_budget_bytes = 32768`
- `evasion.prime_mode = true`
- `evasion.traffic_shaping_enabled = true`
- на Windows дополнительно `first_packet_ttl = 5`

Примечание: пресеты не создают автоматически `domain_fronting_rules`.
