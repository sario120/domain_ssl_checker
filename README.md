# Vigil — Self-Hosted SSL & Domain Expiry Monitor

Monitor SSL certificate and domain registration expiry for all your domains from a single dashboard. Get alerts via email, Slack, or Zulip before things expire.

## Features

- **SSL Certificate Checking** — TLS handshake to port 443, parses issuer, subject, SANs, validity period
- **WHOIS Domain Checking** — Queries WHOIS servers for 40+ TLDs with IANA lookup fallback
- **Dual Domain Types** — "Full" (SSL + WHOIS) or "SSL-only" per domain
- **Manual Expiry Dates** — Enter dates manually when WHOIS is unreliable
- **Scheduled Checks** — Configurable interval via APScheduler (default 24h)
- **Alert System** — Email (SMTP with STARTTLS/SSL), Slack, Zulip
- **Summary Emails** — Daily health summary after scheduled checks
- **Custom Email Templates** — Subject, HTML body, text body per alert type
- **User Management** — Role-based (admin/user/viewer), account lockout, password policy
- **API Key Auth** — Bearer token authentication for headless access
- **Database Backups** — Automatic daily gzipped backups with restore via UI
- **Health Snapshots** — Daily trend data with dashboard sparklines
- **Import/Export** — Bulk domain management (JSON/CSV)
- **Dashboard** — Stats bar, expiry buckets, expiring lists, activity chart
- **Dark/Light Theme** — Persistent preference
- **Keyboard Shortcuts** — Full keyboard navigation on domain lists
- **Card/Table Views** — Toggle between grid cards and sortable table
- **Bulk Actions** — Multi-select, shift-click range, bulk check/delete/export
- **Audit Logging** — 13 critical actions tracked with type filtering and search

## Architecture

```
Browser  ←→  Flask API  ←→  SQLite / PostgreSQL
                   ↑
       APScheduler (configurable interval)
                   ↓
         SSL Check + WHOIS Check
                   ↓
         Alerts (SMTP / Slack / Zulip)
```

### Tech Stack

| Layer | Choice |
|-------|--------|
| Runtime | Python 3.12+ |
| Framework | Flask 3.x |
| Database | SQLite (WAL mode) or PostgreSQL |
| Scheduler | APScheduler 3.x |
| WSGI | Gunicorn |
| Encryption | cryptography (Fernet) |
| Frontend | Vanilla JS + CSS (no build step) |
| Container | Docker multi-stage (~130MB) |

### Project Layout

```
ssl_checker/
├── ssl_domain_checker/       # Python package
│   ├── app.py                # Flask app, routes, middleware, startup
│   ├── models.py             # DB schema, CRUD, queries
│   ├── checker.py            # SSL + WHOIS checking logic
│   ├── scheduler.py          # APScheduler wrapper
│   ├── alert.py              # SMTP alert dispatch
│   ├── webhook.py            # Slack / Zulip dispatch
│   ├── email_templates.py    # Email template rendering
│   ├── crypto.py             # Fernet encrypt/decrypt
│   ├── backup.py             # Backup + rotation
│   ├── db.py                 # SQLite / PostgreSQL abstraction
│   ├── status_utils.py       # Day-based status classification
│   ├── static/               # JS, CSS, assets
│   └── templates/            # HTML templates
├── tests/                    # pytest test suite (48 passing)
├── data_volume/              # SQLite DB (gitignored)
├── backups/                  # Gzipped backups (gitignored)
├── Dockerfile                # Multi-stage build
├── docker-compose.yml        # Service definition
├── gunicorn.conf.py          # Scheduler init hook
├── ssl_checker.service       # systemd unit
└── .env.sample               # Configuration template
```

## Quick Start

### Docker (recommended)

```bash
git clone <repo-url> && cd ssl_checker
cp .env.sample .env
# Edit .env — at minimum set SECRET_KEY and ENCRYPTION_KEY
docker compose up -d
# Open http://localhost:8010
# Retrieve admin password:
docker exec vigil cat /app/data_volume/admin_credentials.txt
```

### Bare Metal

```bash
# Prerequisites: Python 3.12+, pip, venv
git clone <repo-url> && cd ssl_checker
python3 -m venv venv
source venv/bin/activate
pip install -r ssl_domain_checker/requirements.txt
cp .env.sample .env
# Edit .env — set SECRET_KEY, ENCRYPTION_KEY, DB_PATH
gunicorn --workers 1 --threads 4 --bind 0.0.0.0:5000 \
  --chdir ssl_domain_checker app:app
```

### systemd (production bare-metal)

```bash
sudo useradd -r -s /bin/false vigil
sudo mkdir -p /opt/ssl_checker
sudo chown vigil:vigil /opt/ssl_checker

git clone <repo-url> /opt/ssl_checker

cd /opt/ssl_checker
python3 -m venv venv
source venv/bin/activate
pip install -r ssl_domain_checker/requirements.txt
cp .env.sample .env
# Edit .env — set SECRET_KEY, ENCRYPTION_KEY, etc.

sudo cp ssl_checker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssl_checker
```

## Setup from Scratch (Detailed)

### 1. Prerequisites

- **Python 3.12+** (check with `python3 --version`)
- **pip** and **venv** (`apt install python3-pip python3-venv` on Debian/Ubuntu)
- **Docker + Docker Compose** (optional, for containerized deployment)
- **PostgreSQL 15+** (optional, for PG backend instead of SQLite)
- **Reverse proxy** (nginx/caddy) recommended for production HTTPS termination

### 2. Get the Code

```bash
git clone <repo-url> vigil
cd vigil
```

### 3. Configure Environment

```bash
cp .env.sample .env
```

Minimum required variables in `.env`:

| Variable | How to generate |
|----------|----------------|
| `SECRET_KEY` | `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `ENCRYPTION_KEY` | `python3 -c "import secrets; import base64,hashlib; print(base64.urlsafe_b64encode(hashlib.sha256(secrets.token_bytes(32)).digest()).decode())"` |
| `ADMIN_PASSWORD` | Set a strong password, or leave empty for auto-generated |

Other common settings:

- `TIMEZONE` — Set to your IANA timezone (default: `Asia/Karachi`)
- `DB_TYPE` — `sqlite` (default) or `postgresql`
- `SCHEDULER_INTERVAL_HOURS` — How often to auto-check domains (default: `24`)
- `HTTPS=1` — Enable Secure cookies when behind HTTPS reverse proxy

### 4. Run

**Docker:**
```bash
docker compose up -d
docker logs vigil -f  # watch for the admin password
```

**Bare-metal (development):**
```bash
source venv/bin/activate
python ssl_domain_checker/app.py
```

**Bare-metal (production):**
```bash
source venv/bin/activate
gunicorn --workers 1 --threads 4 --bind 127.0.0.1:5000 \
  --timeout 120 --chdir ssl_domain_checker app:app
```

### 5. First Login

1. Open `http://your-host:5000` (or `http://localhost:8010` with Docker)
2. Username: `admin`
3. Password:
   - If `ADMIN_PASSWORD` was set in `.env`, use that
   - Otherwise, check `data_volume/admin_credentials.txt` (or `docker exec vigil cat /app/data_volume/admin_credentials.txt`)
4. Go to Settings to configure SMTP, webhooks, alert thresholds

### 6. PostgreSQL Setup (Optional)

Create the database and schema manually, then set `DB_TYPE=postgresql` in `.env`:

```sql
CREATE DATABASE vigil;
CREATE SCHEMA IF NOT EXISTS vigil;
CREATE USER vigil_user WITH PASSWORD 'strong_password';
GRANT ALL PRIVILEGES ON DATABASE vigil TO vigil_user;
GRANT ALL ON SCHEMA vigil TO vigil_user;
```

## API Reference

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/login` | None | Session login (rate-limited) |
| POST | `/api/logout` | Session | End session |
| GET | `/api/me` | None | Check auth status |
| GET | `/api/csrf-token` | None | Get CSRF token |

### Domains

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/domains` | Login | List domains |
| GET | `/api/domains/all` | Login | All domains grouped by type |
| POST | `/api/domains` | Admin+CSRF | Add domain |
| PUT | `/api/domains/<id>` | Admin+CSRF | Update domain |
| DELETE | `/api/domains/<id>` | Admin+CSRF | Delete domain |
| GET | `/api/domains/export` | Admin | Export as JSON |
| POST | `/api/domains/import` | Admin+CSRF | Import from JSON |
| POST | `/api/domains/<id>/check` | Admin+CSRF | Check single domain |
| POST | `/api/check-all` | Admin+CSRF | Check all domains |
| GET | `/api/domains/<id>/cert` | Login | Certificate details |

### Dashboard & Health

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/dashboard/summary` | Login | Dashboard stats, expiring lists, snapshots |
| GET | `/api/scheduler/status` | Login | Next scheduled run |
| GET | `/api/health` | None | Health check |

### Settings & Users

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/settings` | Admin | Get settings |
| PUT | `/api/settings` | Admin+CSRF | Update settings |
| POST | `/api/settings/test-smtp` | Admin+CSRF | Test SMTP |
| POST | `/api/settings/test-webhook` | Admin+CSRF | Test webhook |
| GET | `/api/email-templates` | Admin | Get templates |
| PUT | `/api/email-templates/<name>` | Admin+CSRF | Update template |
| GET | `/api/users` | Admin | List users |
| POST | `/api/users` | Admin+CSRF | Create user |
| PUT | `/api/users/<id>` | Admin+CSRF | Update user |
| DELETE | `/api/users/<id>` | Admin+CSRF | Delete user |
| GET | `/api/security-settings` | Admin | Get security settings |
| PUT | `/api/security-settings` | Admin+CSRF | Update security |
| GET | `/api/api-keys` | Admin | List API keys |
| POST | `/api/api-keys` | Admin+CSRF | Create API key |
| DELETE | `/api/api-keys/<id>` | Admin+CSRF | Revoke API key |

### Logs & Backups

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/logs` | Admin | List audit logs |
| GET | `/api/backups` | Admin | List backups |
| POST | `/api/backups` | Admin+CSRF | Create backup |
| POST | `/api/backups/restore` | Admin+CSRF | Restore from backup |
| GET | `/api/backups/download/<file>` | Admin | Download backup |
| DELETE | `/api/backups/<file>` | Admin+CSRF | Delete backup |

### Prometheus Metrics

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/metrics` | None | Domain status counts + last check timestamp |

## Configuration Reference

See `.env.sample` for all variables with documentation. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | — | Flask session signing key (required) |
| `ENCRYPTION_KEY` | — | Fernet key for SMTP password encryption (required) |
| `ADMIN_PASSWORD` | — | First-run admin password (auto-generated if empty) |
| `DB_TYPE` | `sqlite` | Database backend: `sqlite` or `postgresql` |
| `DB_PATH` | `data_volume/ssl_checker.db` | SQLite file path |
| `HTTPS` | `1` | Enable Secure cookies + HSTS |
| `TIMEZONE` | `Asia/Karachi` | IANA timezone for timestamps |
| `SESSION_LIFETIME_HOURS` | `4` | Max session lifetime (max 4) |
| `SCHEDULER_INTERVAL_HOURS` | `24` | Auto-check interval |
| `CHECK_WORKERS` | `20` | ThreadPoolExecutor size |
| `DATA_RETENTION_DAYS` | `90` | Old data retention period |
| `RATE_LIMIT_DEFAULT` | `200 per day,50 per hour` | API rate limit |
| `RATE_LIMIT_LOGIN` | `10 per minute` | Login rate limit |

## User Management

### Roles

- **admin** — Full access: manage domains, settings, users, API keys, backups
- **user** — Can manage domains and view settings
- **viewer** — Read-only dashboard access

### First-Run Admin

On first startup (empty `users` table), Vigil creates an admin user:
1. Username: `admin`
2. Password: `ADMIN_PASSWORD` env var, or auto-generated 32-char random password
3. Auto-generated password written to `data_volume/admin_credentials.txt`

See `create_admin_user.info` for password reset and API key workflows.

### Security Settings

Configured via Settings > Security in the UI:

- Password policy (min length, uppercase, lowercase, digit, special char)
- Account lockout (max failed attempts, lockout duration)
- Session timeout

## Monitoring

### Status Classification

**SSL Certificates:**
| Bucket | Days Left |
|--------|-----------|
| Expired | < 0 |
| Critical | 0–4 |
| Warning | 5–14 |
| Caution | 15–19 |
| Watch | 20–29 |
| Healthy | 30+ |

**Domain Registration:**
| Bucket | Days Left |
|--------|-----------|
| Expired | < 0 |
| Critical | 0–29 |
| Warning | 30–59 |
| Caution | 60–89 |
| Healthy | 90+ |

### Alert Thresholds

Configure per-domain or globally:
- **SSL alert threshold** — Days before SSL expiry to trigger alert (default: 30)
- **Domain alert threshold** — Days before domain expiry to trigger alert (default: 60)

Alerts are rate-limited to once per 24 hours per domain. Summary email is sent at most once per day.

## Database

### SQLite (default)

- WAL mode for concurrent reads
- Foreign keys enabled
- Busy timeout: 5s
- File location: `data_volume/ssl_checker.db`

### PostgreSQL

- Connection pooling (min 2, max 10)
- Schema-based isolation
- `RETURNING` clause for INSERT/UPDATE
- Timezone-aware timestamps converted to naive UTC internally

### Schema Versioning

`schema_version` table tracks the schema version (`SCHEMA_VERSION = 1`). Migrations use `ALTER TABLE ADD COLUMN IF NOT EXISTS` pattern.

## Testing

```bash
pytest tests/ -v
# Specific test file
pytest tests/test_models.py -v
# With coverage
pytest tests/ --cov=ssl_domain_checker -v
```

Test config is in `tests/conftest.py` — uses temp DB, sets required env vars.

## Docker

### Build

```bash
docker compose build
# Or manually:
docker build -t vigil:latest .
```

### Multi-stage Build

- **Builder stage** — Installs Python dependencies
- **Runtime stage** — Slim `python:3.12-slim`, copies only site-packages and app code
- Non-root `vigil` user (UID 1000)

### Resource Limits (docker-compose.yml)

- CPU: 1 core
- Memory: 1 GB

## systemd Service

The provided `ssl_checker.service` expects:
- Working directory: `/opt/ssl_checker`
- Virtual env: `/opt/ssl_checker/venv/`
- Environment file: `/opt/ssl_checker/.env`
- Gunicorn listening on `127.0.0.1:5000`

Setup:
```bash
sudo cp ssl_checker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssl_checker
sudo journalctl -u ssl_checker -f  # watch logs
```

## Backups

- Automatic daily at 03:00 (APScheduler)
- Gzip-compressed SQLite copy with metadata JSON sidecar
- Verification checks SQLite header validity
- Pre-restore snapshot created automatically
- Retention: 30 backups (configurable via `MAX_BACKUPS`)
- Manual backup/restore available via UI

## Prometheus Metrics

`GET /api/metrics` returns:
```
# HELP vigil_domain_status_count Domain status counts
# TYPE vigil_domain_status_count gauge
vigil_domain_status_count{status="healthy"} 42
vigil_domain_status_count{status="watch"} 3
# HELP vigil_last_check_timestamp Unix timestamp of last check run
# TYPE vigil_last_check_timestamp gauge
vigil_last_check_timestamp 1.712345e+09
```

## License

Internal use. Contact the maintainer for licensing inquiries.
