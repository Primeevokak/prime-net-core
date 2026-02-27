# TLS FINGERPRINTING

Настройка `tls.ja3_fingerprint` реализована как best-effort поверх `rustls`.

## Поддерживаемые профили

- `rustls_default`
- `chrome_120`
- `firefox_121`
- `random`

## Что реально настраивается

- порядок cipher suites (в пределах доступных rustls наборов);
- порядок key exchange groups;
- порядок/состав ALPN (в том числе частичная рандомизация в `random`);
- диапазон TLS версий (`tls.min_version`/`tls.max_version`).

## Что не гарантируется

- точная browser-grade impersonation;
- полное совпадение JA3/JA4 с конкретным браузером;
- полный контроль всех TLS extension-полей.

Итого: это полезный тюнинг для вариативности TLS-профиля, но не uTLS-эквивалент.

## ECH и TLS

- ECH включается через `anticensorship.ech_mode` (или legacy `ech_enabled=true`).
- Для ECH обязательно, чтобы конфиг допускал TLS 1.3.
- `ech_mode=auto` пытается `real`, затем fallback в `grease`.
