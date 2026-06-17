# CODEXC — Architecture & Design Decisions

## Technology Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Runtime | Python 3.12+ | Wide ecosystem, SSL libs built-in |
| Web framework | Flask 3.x | Lightweight, zero-ORM, great for tooling UIs |
| Database | SQLite (WAL) | Single-file, no external DB server, WAL for concurrency |
| Scheduler | APScheduler 3.x | In-process cron replacement, survives gunicorn workers |
| WSGI | Gunicorn | Production-grade, paired with APScheduler init hook |
| Encryption | `cryptography` (Fernet) | AES-128-CBC + HMAC-SHA256 for SMTP password at rest |
| Rate limiting | Flask-Limiter (in-memory) | Per-IP rate limiting for login and general API |
| Frontend | Vanilla JS + CSS | Zero build tooling, single-page with hash routing |
| Container | Docker multi-stage | Minimal final image (~130MB), non-root user |

## Architecture

### Data Flow
```
User Browser  ←→  Flask API  ←→  SQLite (DB)
                        ↑
            APScheduler (configurable interval)
                        ↓
   +-------------+-------+--------+
   |             |                |
SSL Check ()  WHOIS Check ()  Webapp HTTP Check ()
   |             |                |
   +------ Alert System (SMTP / Slack / Zulip) ------+
```

### Project Layout
```
ssl_checker/
├── ssl_domain_checker/       # Python package
│   ├── app.py                # Flask app, routes, startup
│   ├── models.py             # DB schema, CRUD, settings
│   ├── checker.py            # SSL + WHOIS domain checking
│   ├── webapp_checker.py     # HTTP/HTTPS webapp checking
│   ├── scheduler.py          # APScheduler wrapper
│   ├── alert.py              # SMTP alert dispatch
│   ├── webhook.py            # Slack / Zulip webhook dispatch
│   ├── email_templates.py    # HTML/text email template rendering
│   ├── crypto.py             # Fernet encrypt/decrypt with key fallback
│   ├── backup.py             # Gzipped SQLite backup + rotation
│   ├── db.py                 # SQLite / PostgreSQL abstraction
│   ├── status_utils.py       # Day-based status classification
│   ├── static/               # Frontend assets (JS, CSS, SVG)
│   └── templates/            # HTML templates (login.html, index.html)
├── tests/                    # pytest test suite (62 tests)
├── data_volume/              # SQLite DB (gitignored)
├── backups/                  # Gzipped backups (gitignored)
├── Dockerfile                # Multi-stage container build
├── docker-compose.yml        # Healthcheck, volumes, env
├── gunicorn.conf.py          # Scheduler init in post_worker_init
├── ssl_checker.service       # systemd unit for bare-metal deploy
└── .env.sample               # All config keys documented
```

## Key Design Decisions

### 1. Scheduler Lifecycle
APScheduler starts at **module import time** in `app.py` AND in `gunicorn.conf.py:post_worker_init`. This ensures it runs under both `python app.py` (dev) and `gunicorn app:app` (prod). The `post_worker_init` hook is the primary path under gunicorn; the module-level start is a fallback.

### 2. SMTP Password Encryption
Passwords are encrypted with `Fernet` before storage in SQLite. The encryption key is derived via `SHA256(ENCRYPTION_KEY)` -> `urlsafe_b64encode`. Legacy passwords encrypted with `SECRET_KEY` can still be decrypted (fallback chain: ENCRYPTION_KEY -> SECRET_KEY -> raise).

### 3. WHOIS Architecture
- Cached with TTL (default 300s) to avoid hammering WHOIS servers.
- Known WHOIS servers hardcoded for 40+ TLDs to skip IANA bootstrap.
- IANA lookup fallback for unknown TLDs.
- Threaded with `ThreadPoolExecutor` and `Future.timeout` to prevent hangs.
- Private IP resolution blocked at both SSL and WHOIS layers.

### 4. Status Classification
Two independent systems: SSL (certificate) and Domain (WHOIS expiry). Each uses a day-based bucket system:
- **SSL**: expired(<0) / critical(0-4) / warning(5-14) / caution(15-19) / watch(20-29) / healthy(30+)
- **Domain**: expired(<0) / critical(0-29) / warning(30-59) / caution(60-89) / healthy(90+)
- "Full" domains get domain status as primary; "SSL-only" domains use SSL status.
- **Webapp**: up / down / slow / unknown — determined by HTTP status code + response time threshold.

### 5. Alert Throttling
Alerts are rate-limited per-domain to once per 24 hours (`last_alerted` column). Webapp alerts have their own cooldown. Check complete summary email also limited to once per day.

### 6. Security Model
- Three roles: `admin` (full access), `user`, `viewer` (read-only dashboard).
- Account lockout after N failed logins (configurable via security settings).
- Session timeout (configurable, default 60 minutes).
- CSRF protection via `X-CSRF-Token` header (deterministic SHA256).
- API key authentication as alternative to session auth (Bearer token).
- Security headers: HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy.

### 7. Backup System
Daily cron at 03:00 via APScheduler. Gzip-compressed SQLite copies with metadata JSON sidecar. Verification step validates SQLite header. Automatic cleanup keeps MAX_BACKUPS (default 30). Pre-restore snapshot created automatically.

### 8. Frontend Architecture
- Single HTML page (`templates/index.html`) with hash-routed views.
- All state managed in global JS variables (no framework).
- `data-action` attribute pattern for event delegation.
- Cards view (default) + table view toggle per domain type.
- Column visibility, pagination, TLD filtering, status grouping all persisted to `localStorage`.
- Keyboard shortcuts: `j/k` navigate, `x` select, `a` select all, `/` or `f` search, `c` check selected.
- Dashboard auto-refresh on configurable interval.

### 9. Domain / SSL Page Rendering Pattern
Both "Domains" (full) and "SSL Certificates" pages share identical rendering infrastructure:
- **View toggling** via `toggleViewMode()` — cards (`.domain-list`) vs table (`.domain-table`).
- **Sort bar** (`renderSortBar()`) — sort by url/status/days/checked, group-by-status checkbox, column visibility dropdown.
- **Stats bar** (`updateStats()`) — live counts for Total / Healthy / Watch (SSL: ≤30d) / Expired / Error.
- **Filter chips** — per-page filter, cleared via `clearDomainFilters()`. Full: All/Healthy/Watch/Expired/Error. SSL: All/Healthy/Watch/Caution/Warning/Critical/Expired/Error.
- **Bulk selection** — shift-click range via `_lastChecked`, select-all, per-type sets (`selectedDomains`/`selectedSsl`).
- **Pagination** (`renderPagination()`) — configurable page size (25/50/100), first/prev/next/last.

### 10. Kebab Dropdown Positioning
Kebab dropdowns changed from `position: absolute` to `position: fixed` with JS viewport clamping. This prevents clipping behind any parent container (e.g., pagination wrapper, stat bars) that has `overflow: hidden` or `transform`.

### 11. User Deactivation
- `users` table has `is_active` column (default 1), migrated via `ALTER TABLE ADD COLUMN`.
- Deactivated users receive "Account is deactivated. Contact an administrator." at login.
- Admin self-deactivation blocked at route level (`@admin_required` + `current_user.id == user_id` → 403).
- UI shows Deact/React toggle in user management kebab menu.

### 12. Webapp Monitoring Design
- Webapps stored in separate `webapps` table (not `domains`).
- HTTP/HTTPS GET check via `requests` library — status code + response time.
- Statuses: `up` (2xx/3xx, response time < threshold), `slow` (2xx/3xx but slow), `down` (non-2xx/3xx, timeout, or connection error).
- Response time threshold configurable per webapp (default 5000ms).
- Per-webapp check interval (separate from domain interval).
- Results stored in `webapp_results` table; health logs in `webapp_health_log`.
- History retention configurable via `DATA_RETENTION_DAYS`.
- Sparklines in webapp card/table show last 20 check statuses.

### 13. URL Normalization
`normalise_url()` auto-prepends scheme based on hostname heuristics:
- If hostname has dots and no IP pattern → `https://`
- If hostname is IP address, `localhost`, or single-word → `http://`
- Applied at add time (not retroactive). Avoids DNS resolution — purely lexical.

### 14. Dashboard Design
- Stat cards: 3-column grid — Domains, SSL, Web Apps.
- Each card shows Down/Slow/Paused counts for webapps, healthy/warning/expired for domains.
- System Information sidebar card with grouped sections (System, Scheduler), hover highlight.
- Webapp Failures section lists down/slow webapps with duration.
- Expiring lists show SSL + Domain entries with 4px colored left-border items.
- Scheduler status shows next run time and interval text.
- Auto-refresh every 30s.

### 15. Alert Templates
Three built-in email templates: `ssl_alert`, `domain_alert`, `webapp_alert`, plus `check_complete` summary. Webapp alerts must use `webapp_alert` template — using `domain_alert` incorrectly would show "Domain Expiring Soon" for webapp status changes.
