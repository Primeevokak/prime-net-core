pub fn show_help_overlay(context: &str) -> String {
    match context {
        "config_editor" => CONFIG_EDITOR_HELP,
        "connection_monitor" => MONITOR_HELP,
        "privacy_dashboard" => PRIVACY_HELP,
        "privacy_headers" => PRIVACY_HEADERS_HELP,
        "log_viewer" => LOG_VIEWER_HELP,
        "proxy" => PROXY_HELP,
        _ => MAIN_MENU_HELP,
    }
    .to_owned()
}

const MAIN_MENU_HELP: &str = r#"Горячие клавиши

Навигация:
  1-6       Переключить вкладку
  Tab       Следующая вкладка
  m         Сменить режим UI (простой/расширенный)
  q         Выход

Быстрые действия:
  ?         Показать контекстную справку
"#;

const CONFIG_EDITOR_HELP: &str = r#"Редактор конфигурации

  Up/Down    Выбор поля
  Left/Right Выбор раздела
  Enter/e    Редактировать поле
  s          Сохранить
  r          Перезагрузить
  Ctrl+Z/Y   Отменить/повторить
  ?          Справка по полю
"#;

const MONITOR_HELP: &str = r#"Монитор соединений

  Up/Down   Переместить выделение
  r         Обновить данные
"#;

const PRIVACY_HELP: &str = r#"Панель приватности

  v         Сменить режим Referer
  b         Переключить блокировщик трекеров
  a         Переключить блокировку рекламы
  n         Переключить сигнал DNT
  g         Переключить сигнал GPC
"#;

const PRIVACY_HEADERS_HELP: &str = r#"Заголовки приватности

  User-Agent   Space переключить  p сменить пресет  e редактировать значение
  Referer      Space переключить  e редактировать URL подмены
  Подмена IP   Space переключить  e редактировать IP (X-Forwarded-For)
  WebRTC       Space переключить (сигнал в заголовках по возможности)
  Геолокация   Space переключить (сигнал в заголовках по возможности)
"#;

const LOG_VIEWER_HELP: &str = r#"Просмотр логов

  /         Поиск
  f         Фильтр по уровню
  k         Фильтр по категории ([BLOCKED]/[PRIVACY]/[TRACKER])
  r         Режим regex-поиска
  s         Автопрокрутка вкл/выкл
  e         Экспорт отфильтрованных логов
  y         Копировать выбранную строку
"#;

const PROXY_HELP: &str = r#"Ядро/Прокси

  a         Запустить ядро и включить системный прокси
  x         Остановить ядро и выключить системный прокси
  u         Обновить диагностику
  d         Очистить кэш relay-классификатора (с подтверждением)

В окне подтверждения:
  y/Enter   Подтвердить очистку кэша
  n/Esc     Отмена
"#;
