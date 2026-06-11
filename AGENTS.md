# AGENTS.md — AI Coding Agent Instructions

## Project Overview

**Vigil** — a self-hosted SSL certificate & domain expiry monitoring web application.
Tech: Flask + SQLite (WAL mode) + APScheduler + vanilla JS frontend.

## Conventions

### Python
- **Flask** app factory pattern with `app.py` as entrypoint.
- **No ORM** — raw `sqlite3` with `sqlite3.Row` dictionary access.
- **Models** in `ssl_domain_checker/models.py` — all DB logic lives here.
- **Routes** defined as decorated functions in `app.py`.
- Thread safety for WHOIS via `threading.Lock` + `ThreadPoolExecutor`.
- SMTP passwords encrypted with `cryptography.fernet.Fernet` before storage.
- Admin self-deactivation blocked at route level (`@admin_required` + `current_user.id == user_id` check).

### Frontend
- **No framework** — vanilla JS in `static/app.js` (~3600 lines), `static/login.js` (136 lines).
- **Hash-based routing** — `window.location.hash` drives view switching.
- **Dark/light theme** — toggled via `localStorage`, class on `<body>`.
- **Event delegation** — all click actions handled via single `data-action` attribute listener.
- **Domain/SSL pages** share a common rendering pattern: card + table toggling, sort bar, stats bar, filter chips, search + TLD dropdown, pagination, bulk selection with shift-click range, column visibility dropdown.
- **Logs page** has search, type filter chips, summary cards (total/check/alert/error), activity bar chart, pagination with mobile card view.
- **Kebab dropdowns** use `position: fixed` with JS viewport clamping to prevent clipping behind any parent container.
- Domain filters, view mode, pagination state, column visibility, group-by-status persisted in `_cachedDomains`, `_viewMode`, `_pagination`, `_domainFilter`, `_tldFilter`, `selectedDomains`/`selectedSsl` globals.

### Database
- SQLite with WAL mode, foreign keys ON, busy timeout 5s.
- `DB_PATH` defaults to `data_volume/ssl_checker.db`.
- Migration strategy: `ALTER TABLE ADD COLUMN` guarded by `PRAGMA table_info()`.
- First-run creates `admin` user with random password (logged to stderr at startup).
- `users` table has `is_active` column — deactivated users blocked at login with "Account is deactivated" message.

### Testing
- Run: `pytest tests/ -v` (from project root).
- Test DB uses temp directory, `DB_PATH` overridden in test.
- Environment variables for testing set in `tests/conftest.py`.

### Docker
- Multi-stage build: `builder` stage compiles deps, runtime stage copies only.
- Non-root `vigil` user (UID 1000).
- Gunicorn + APScheduler: scheduler started in `gunicorn.conf.py` `post_worker_init` and at module level in `app.py`.
- Resource limits: 1 CPU, 1GB RAM in docker-compose.yml.

## Code Style Rules
- No comments in Python unless explaining a complex edge case.
- No emojis in code or documentation.
- Mimic existing code patterns (e.g., `_` prefix for private functions, `route` suffix for Flask views).
- Type hints optional, but return types on public functions preferred.

## Common Tasks

### Adding a new API endpoint
1. Define route function in `app.py` with appropriate decorators (`@login_required`, `@admin_required`, `@csrf_required`).
2. Add any DB logic to `models.py`.
3. Use `@json_body(...)` for JSON input validation.
4. Return `jsonify(...)` responses, use `api_error(...)` for errors.
5. Add corresponding JS in `static/app.js` using the `api()` helper.

### Adding a new DB table
1. Add `CREATE TABLE IF NOT EXISTS` in `models.init_db()`.
2. Add `ALTER TABLE` column migration in the existing fallback loop.
3. Create getter/setter functions in `models.py`.

### Adding a new alert channel
1. Create a sender function in `ssl_domain_checker/webhook.py` (or a new module referenced from `alert.py`).
2. Add settings columns to the `settings` table for configuration.
3. Wire up in `alert.py:send_alerts()` and `webhook.py:send_webhook_alerts()`.

### Adding a domain/SSL page feature
1. If adding a new filter chip type, add the button in `templates/index.html` inside the appropriate `.domain-filters` block and handle the filter value in `applyDomainFilters()` in `app.js`.
2. If adding a new sort column, add the header in the `<thead>` + column in `applyDomainFilters()` render section + column visibility checkbox in the column-toggle dropdown.
3. If adding a bulk action, add the button in the `.bulk-toolbar` block and handle it in the global click delegator in `app.js`.
4. View mode toggling, stats bar, pagination, group-by-status all follow existing patterns — refer to `renderDomainCards()`, `renderDomainTable()`, `updateStats()`, `renderPagination()`, `renderSortBar()`.
