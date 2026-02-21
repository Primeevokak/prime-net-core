# Модель безопасности

## Что защищает `prime-net-engine`

Приватность DNS:
- запросы через DoH/DoT/DoQ;
- снижение риска DNS-утечек.

Снижение узнаваемости TLS:
- настройки TLS randomization;
- поддержка ECH (в зависимости от режима).

Обход DPI:
- fragment/desync-стратегии;
- опции traffic shaping.

Pluggable transports:
- поддержка Trojan и Shadowsocks;
- интеграция Tor PT (`obfs4`, `snowflake`) при соответствующей конфигурации.

## Что `prime-net-engine` не закрывает полностью

- DNS-утечки на уровне ОС/приложений, которые обходят прокси.
- Браузерный fingerprinting (canvas/fonts/WebGL и т.п.).
- Трафик-анализ сильным противником.
- Компрометацию конечного устройства.

## Модель угроз

Основная целевая угроза:
1. Цензура и фильтрация на уровне ISP/локальной сети.

Не является полным решением для:
1. Точечного преследования со стороны сильного государственного противника.
2. Требований полной анонимности.

Для high-risk сценариев используйте `prime-net-engine` совместно с Tor/VPN и операционными мерами безопасности.

## Безопасность обновлений

- Предпочитайте подписанные обновления (feature `signature-verification`).
- Используйте только официальные релизы репозитория.
- Регулярно выполняйте `prime-net-engine update check`.

## Безопасная настройка

- По возможности используйте пресет `strict-privacy`.
- Держите blocklist в актуальном состоянии.
- После смены сети/ОС перепроверяйте `proxy status` и DNS-поведение.

## Сообщение о уязвимостях

Не публикуйте уязвимости в публичных issue до исправления.

Контакт: `security@yourproject.com`

## Privacy Threat Model Extension

New privacy controls reduce passive tracking but do not eliminate fingerprinting.

Covered better now:
- Known analytics/tracker endpoints via request-time blocking.
- Referer query leakage to third-party origins.
- Explicit privacy signals (`Sec-GPC`, `DNT`).

Still not fully covered:
- Browser/device fingerprinting (canvas/fonts/WebGL, timing, behavior).
- Network-level traffic correlation by strong adversaries.
- Server-side identifier correlation when user is authenticated.
