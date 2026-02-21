# Privacy Layer

## Features

`prime-net-engine` provides an opt-in privacy layer for HTTP requests.

### 1) Tracker blocker

- Blocks known tracker hosts and URL patterns before request send.
- Supports built-in list presets (`easyprivacy`, `easylist`, `ublock`) and custom list files.
- Modes:
  - `block`: enforce blocking.
  - `log_only`: only emit logs.
- On block action:
  - `error`: return `BlockedByPrivacyPolicy`.
  - `empty_200`: return an empty `200` response.
- `allowlist` can exclude domains from blocking.

### 2) Referer policy

- Controls outgoing `Referer` leakage for cross-origin requests.
- Modes:
  - `strip`
  - `origin_only`
  - `pass_through`
- Search-engine referers can be force-stripped (`strip_from_search_engines=true`).

### 3) Privacy signals

- Adds request headers:
  - `DNT: 1`
  - `Sec-GPC: 1`

## Legal and practical notes

- `DNT` is widely ignored by many sites.
- `Sec-GPC` has stronger legal meaning in some jurisdictions (for example CCPA contexts) and is increasingly recognized.
- Privacy features reduce tracking surface, but cannot guarantee full anonymity.

## Logging and observability

The engine emits privacy actions into logs using categories:
- `[BLOCKED]`
- `[PRIVACY]`
- `[TRACKER]`

TUI log viewer can filter by these categories.
