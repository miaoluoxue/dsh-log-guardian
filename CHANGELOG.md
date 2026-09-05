# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-05

### Added
- `LogTailer`: incremental byte-offset log tailing with `fs.watch` + polling fallback,
  truncation / logrotate self-healing, and multibyte-safe offset tracking.
- Keyword scanner supporting plain substrings (case-insensitive) and `/regex/flags` literals.
- Dual-channel alerting: `ctx.logger.warn` (log-panel) + WebSocket broadcast (toast + Notification).
- Runtime env overrides: `LOG_MONITOR_KEYWORDS`, `LOG_MONITOR_FILES`, `LOG_MONITOR_POLL_MS`.
- REST/WS endpoints: `/alerts`, `/status`, `/client.js`, `/events` (loopback/same-origin only).
- Dedup window and in-memory alert ring buffer.
- Zero runtime dependencies; optional `@deepseek-ai/schemastery` peer with graceful fallback.
- Smoke test suite (`test/smoke.mjs`, 18 cases).

[0.1.0]: https://github.com/miaoluoxue/dsh-log-guardian/releases/tag/v0.1.0
