# Руководство по диагностике

## Частые проблемы

### SOCKS5: `connection refused`

Симптомы:
- браузер показывает `connection refused`;
- в TUI видно, что SOCKS5 не запущен.

Решение:
```bash
prime-net-engine socks --bind 127.0.0.1:1080
```

Проверка, что порт реально слушается:
```bash
# Linux/macOS
netstat -an | grep 1080
lsof -i :1080

# Windows
netstat -an | findstr 1080
```

### Ошибка DNS-резолва

Симптомы:
- сайты не открываются;
- `test` падает на DNS-этапе.

Что проверить:
1. Актуальны ли DoH/DoT/DoQ endpoint-ы в конфиге.
2. Результат ручного теста:
```bash
prime-net-engine test https://example.com
```
3. Поведение на более совместимом пресете:
```bash
prime-net-engine --preset max-compatibility test https://example.com
```

### Системный прокси не применяется

Windows:
- проверьте `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`;
- убедитесь, что `ProxyEnable=1` при режиме `all/custom`.

macOS:
- проверьте `scutil --proxy`;
- после смены сети повторно включите прокси.

Linux:
- GNOME: `gsettings get org.gnome.system.proxy mode`;
- проверьте переменные окружения (`ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`).

### Низкая скорость

Возможные причины:
- включен `traffic_shaping_enabled`;
- медленные DNS endpoint-ы;
- слишком агрессивный пресет/стратегия evasion для текущей сети.

Что делать:
1. Отключить shaping в конфиге.
2. Убрать медленные DNS endpoint-ы.
3. Сравнить с `max-compatibility`.

### Логи и диагностика

Включить подробные логи:
```bash
prime-net-engine --log-format json --log-level debug test https://example.com
```

Проверить состояние подсистем:
```bash
prime-net-engine proxy status
prime-net-engine blocklist status
```

Сохранить диагностику в файл:
```bash
prime-net-engine --log-file diagnostics.log --log-level trace test https://example.com
```

## Что приложить при запросе помощи

1. ОС и её версия.
2. Версия `prime-net-engine` (`prime-net-engine --version`).
3. Используемый пресет.
4. Сообщения об ошибках и фрагмент логов.
