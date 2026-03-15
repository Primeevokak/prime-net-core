# SECURITY

## Модель угроз

`prime-net-engine` ориентирован на:

- обход сетевых ограничений и DPI;
- снижение DNS-утечек;
- контроль transport path (direct/native bypass/PT).

Проект не является полной системой анонимности.

## Что покрывается

- DoH/DoT/DoQ + управляемый fallback chain;
- нативный TLS/TCP десинхрон (25+ in-process профилей);
- QUIC Initial inject (RFC 9001) для обхода QUIC-фильтрации;
- TCP disorder через WinDivert/NFQueue;
- fragment/desync/fronting/PT техники;
- privacy middleware для HTTP-запросов;
- health/diagnostic observability.

## Что не покрывается полностью

- browser/device fingerprinting;
- глобальная корреляция трафика сильным противником;
- утечки из приложений, которые не используют движок или его SOCKS endpoint;
- компрометация конечной машины.

## Нативный bypass: модель доверия

Нативный DPI bypass работает полностью in-process — нет загрузки внешних бинарей, нет зависимостей от byedpi/ciadpi. Вектор атаки через сторонний bypass-бинарь исключён.

TCP disorder через WinDivert (Windows) требует загрузки `WinDivert.dll`. Используйте только официальный WinDivert из доверенных источников или из директории поставки.

## Updater trust model

Актуально для `src/updater/*`:

- API разрешен только к `https://api.github.com`.
- Загрузка релизных артефактов разрешена только с GitHub-host allowlist.
- Redirect-цепочки отключены (`redirect=none`).
- Для `update install` обязательна detached signature verification.
- Проверка подписи изолирована от пользовательского keyring (временный `gpg` home).
- Подпись принимается только при совпадении ожидаемого fingerprint.

## Практическое ограничение по релиз-подписям

В текущем исходнике публичный ключ и fingerprint остаются плейсхолдерами (`REPLACE_WITH_REAL_RELEASE_SIGNING_*`).

Следствие:

- `update install` в таком состоянии ожидаемо завершится ошибкой проверки подписи.
- До замены плейсхолдеров поддерживайте обновление через вручную проверенный release pipeline.

## QUIC Initial inject: модель безопасности

Fake QUIC Initial пакеты отправляются с TTL, недостаточным для достижения сервера. Они достигают только DPI-точки провайдера. Реальный QUIC Initial с настоящим SNI не модифицируется.

Decoy SNI в fake пакете выбирается движком и не раскрывает настоящий целевой домен DPI-системе.

## Profile discovery: модель доверия

Автозондирование профилей обращается к трём жёстко прописанным IP-адресам (Cloudflare, rutracker.org, IANA). Эти адреса не конфигурируются пользователем и не загружаются из внешних источников. Результаты зондирования хранятся локально.

## Packet bypass bootstrap (legacy)

Если в конфиге задан внешний packet bypass (`PRIME_PACKET_BYPASS_ARGS`):

- latest-tag autodiscovery отключен по умолчанию;
- используется pinned stable tag (если не задан явный `PRIME_PACKET_BYPASS_TAG`);
- payload integrity обязателен (через локально заданный digest или явно разрешенный remote checksum trust).

## Практические рекомендации

- стартовать с `strict-privacy` или `aggressive-evasion` и проверять реальную связность через `test`;
- поддерживать blocklist в актуальном состоянии (`blocklist update`);
- вести логи в файл (`--log-file`, `--log-format json`);
- для инцидентов фиксировать точные команды, конфиг (без секретов) и фрагменты логов.
