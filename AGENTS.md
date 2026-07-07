# AGENTS.md — AI Coding Agent Instructions

## Project Overview

**Vigil** — a self-hosted SSL certificate, domain expiry & web app monitoring web application.
Tech: Flask + PostgreSQL + APScheduler + vanilla JS frontend.

## Conventions

### Python
- **Flask** app factory pattern with `app.py` as entrypoint.
- **No ORM** — raw `psycopg2` with `RealDictCursor` dictionary access.
- **Models** in `ssl_domain_checker/models.py` — all DB logic lives here.
- **Routes** defined as decorated functions in `app.py`.
- Thread safety for WHOIS via `threading.Lock` + `ThreadPoolExecutor`.
- SMTP passwords encrypted with `cryptography.fernet.Fernet` before storage.
- Admin self-deactivation blocked at route level (`@admin_required` + `current_user.id == user_id` check).
- Webapp checks via `webapp_checker.py` — HTTP/HTTPS GET with status code + response time.
- URL normalization via `normalise_url()` in `models.py` — auto-prepends `https://` for DNS names, `http://` for IPs/localhost/single-word hosts.

### Frontend
- **No framework** — vanilla JS in `static/app.js` (~5864 lines), `static/login.js` (138 lines).
- **Hash-based routing** — `window.location.hash` drives view switching.
- **Dark/light theme** — toggled via `localStorage`, class on `<body>`.
- **Event delegation** — all click actions handled via single `data-action` attribute listener.
- **Domain/SSL pages** share a common rendering pattern: card + table toggling, sort bar, stats bar, filter chips, search + TLD dropdown, pagination, bulk selection with shift-click range, column visibility dropdown.
- **Webapps page** has its own rendering: cards with color-coded left border, card body opens detail modal, 40px sparklines, table sparkline column, filter badge counts replacing stats bar, skeleton loading, Actions dropdown in header, sort dropdown, status-change pulse animation, enhanced empty state.
- **Webapp detail modal** shows uptime % bars (24h/7d/30d/365d), incident list, response time chart (SVG polyline + area with Y-axis labels, X-axis time labels, hover tooltip with dashed guide line, duration selector 1h/6h/12h/24h/7d/30d/365d), current up/down duration, response time stats (avg/min/max/latest).
- **Logs page** has search, type filter chips, summary cards (total/check/alert/error), activity bar chart, pagination with mobile card view.
- **Dashboard** renders stat cards (3-column: Domains, SSL, Web Apps with Down/Slow/Paused), Scheduler Status with dynamic interval text, System Information with div-based card + icons grouped by section (System, Scheduler), Webapp Failures section (down/slow webapps), and Expiring lists (SSL + Domain) with 4px colored left-border items.
- **Kebab dropdowns** use `position: fixed` with JS viewport clamping to prevent clipping behind any parent container.
- Domain filters, view mode, pagination state, column visibility, group-by-status persisted in `_cachedDomains`, `_viewMode`, `_pagination`, `_domainFilter`, `_tldFilter`, `selectedDomains`/`selectedSsl` globals.
- Webapp globals: `_detailWebappId`, `_detailChartHours`, `_timezoneOffsetH` (default 5 for PKT).
- Chart rendering via string-based SVG in `loadWebappChart()`; all timestamps converted to local timezone via `_parseDt()` + `_toLocal()` using `_timezoneOffsetH`.
- `relativeTime()` shows "X ago" with defensive NaN checks; `formatDurationLong()` shows exact seconds/minutes.

### Database
- PostgreSQL only. Connection pooled via `psycopg2.pool.ThreadedConnectionPool` in `db.py`.
- Schema-per-deployment via `POSTGRES_SCHEMA` (`CREATE SCHEMA IF NOT EXISTS` + `SET search_path`).
- Migration strategy: `ALTER TABLE ADD COLUMN` guarded by `information_schema.columns` (`db.table_columns()`).
- First-run creates `admin` user with random password (logged to stderr at startup).
- `users` table has `is_active` boolean column — deactivated users blocked at login with "Account is deactivated" message. Note: `is_active` is a native Postgres boolean (JSON `true`/`false`), not `0`/`1` — frontend/backend code must compare with `!== false`, not `!== 0`, to catch both.

### Testing
- Run: `pytest tests/ -v` (from project root).
- Tests run against real PostgreSQL, each test file using its own fixed schema (`vigil_test_app`, `vigil_test_models`, `vigil_test_webapps`) that's dropped and recreated before every test — see `tests/pg_test_utils.py`. Never touches the app's real `POSTGRES_SCHEMA` data.

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
1. Add `CREATE TABLE IF NOT EXISTS` to `_PG_SCHEMA` in `models.py`.
2. Add `ALTER TABLE` column migration in `_run_postgres_migrations()`, guarded by `db.table_columns()`.
3. Create getter/setter functions in `models.py`.

### Adding a new alert channel
1. Create a sender function in `ssl_domain_checker/webhook.py` (or a new module referenced from `alert.py`).
2. Add settings columns to the `settings` table for configuration.
3. Wire up in `alert.py:send_alerts()` and `webhook.py:send_webhook_alerts()`.

### Adding a webapp page feature
1. For filter chips, add the button in `templates/index.html` inside `.webapp-filters` block and handle in `applyWebappFilters()` in `app.js`.
2. For sort options, add to `<select id="webapp-sort-select">` and handle in `renderWebappCards()` / `renderWebappTable()`.
3. For card actions, use `data-action` attribute on kebab dropdown items; the global click delegator handles it.
4. For detail modal additions, add elements to `#webapp-detail-modal` in the template and wire in `loadWebappDetail()` / `loadWebappChart()` in `app.js`.
5. Chart features: SVG built via string concatenation in `loadWebappChart()`; add `<rect class="chart-hover-overlay">` for mouse tracking; use `_parseDt()` / `_toLocal()` for timezone-aware timestamps; format X-axis labels with `fmtAxisLabel()`.

### Adding a domain/SSL page feature
1. If adding a new filter chip type, add the button in `templates/index.html` inside the appropriate `.domain-filters` block and handle the filter value in `applyDomainFilters()` in `app.js`.
2. If adding a new sort column, add the header in the `<thead>` + column in `applyDomainFilters()` render section + column visibility checkbox in the column-toggle dropdown.
3. If adding a bulk action, add the button in the `.bulk-toolbar` block and handle it in the global click delegator in `app.js`.
4. View mode toggling, stats bar, pagination, group-by-status all follow existing patterns — refer to `renderDomainCards()`, `renderDomainTable()`, `updateStats()`, `renderPagination()`, `renderSortBar()`.

### Known Bug Patterns
- (none currently — `_send_smtp()` in `alert.py` correctly checks for `ssl_days_left=None and domain_days_left=None` and uses `"webapp_alert"` template.)
