# PROJECT_INFO.md — Vigil SSL/Domain Monitor

## What It Does

Vigil is a self-hosted web application that monitors SSL certificate expiry and domain registration expiry for a list of domains. It checks certificates (TLS handshake) and WHOIS records on a configurable schedule, sends alerts via email/Slack/Zulip when things are about to expire, and provides a dashboard for at-a-glance health status.

## Core Features

- **SSL Certificate Checking** — Connects to port 443, retrieves the certificate, parses notBefore/notAfter, issuer, subject, SANs.
- **WHOIS Domain Checking** — Queries WHOIS servers for domain expiry dates. Supports 40+ TLDs directly with IANA lookup fallback.
- **Dual Domain Types** — "Full" domains get both SSL + WHOIS checks; "SSL-only" domains get cert checks only.
- **Manual Expiry Dates** — Domains can have manual expiry dates entered when WHOIS is unreliable.
- **Scheduled Checks** — APScheduler runs checks at configurable intervals (default 24h).
- **Alert System** — Sends email (SMTP with STARTTLS/SSL), Slack webhook, and/or Zulip webhook notifications when certs/domains are expiring.
- **Customizable Email Templates** — Subject, HTML body, and text body configurable per alert type.
- **Check Summary Emails** — Daily summary of all-domain health sent after scheduled check.
- **User Management** — Role-based access (admin/user/viewer), account lockout, password policy, user deactivation/reactivation (admin cannot self-deactivate).
- **API Key Authentication** — Bearer token API keys for headless/automated access.
- **Database Backups** — Automatic daily gzipped SQLite backups with metadata, manual backup/restore via UI.
- **Health Snapshots** — Daily health data stored for trend sparkline on dashboard.
- **Import/Export** — Bulk domain import/export (JSON/CSV), settings export/import.
- **Dark/Light Theme** — Persistent theme preference.
- **Keyboard Shortcuts** — Full keyboard navigation on domain lists.
- **Card/Table View Toggle** — Switch between grid cards and sortable table on Domains and SSL pages.
- **Sort Bar** — Sort by Name, Status, Days Left, Last Checked; column visibility dropdown.
- **Stats Bar** — Live counts for Total, Healthy, Watch, Expired, Error.
- **Filter Chips** — Domain status filter chips, search input, TLD dropdown on both domain and SSL views.
- **Pagination** — Configurable page size (25/50/100), first/prev/next/last navigation.
- **Bulk Actions** — Select-all, shift-click range selection, bulk check/delete/export/notes/tags/compare/print.
- **Logs Page** — Search, type filter chips, summary cards (total/check/alert/error), activity bar chart, pagination with mobile card view.

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
| GET | `/api/domains` | Login | List domains (?type=full/ssl_only, ?page, ?limit) |
| GET | `/api/domains/all` | Login | List all domains grouped by type |
| POST | `/api/domains` | Admin+CSRF | Add domain |
| PUT | `/api/domains/<id>` | Admin+CSRF | Update domain |
| DELETE | `/api/domains/<id>` | Admin+CSRF | Delete domain |
| GET | `/api/domains/export` | Admin | Export domains as JSON |
| POST | `/api/domains/import` | Admin+CSRF | Import domains from JSON |
| POST | `/api/domains/<id>/check` | Admin+CSRF | Manual check single domain |
| POST | `/api/check-all` | Admin+CSRF | Check all domains |
| GET | `/api/domains/<id>/cert` | Login | Get cert details |

### Dashboard & Status
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/dashboard/summary` | Login | Dashboard statistics, expiring lists, health snapshots |
| GET | `/api/scheduler/status` | Login | Next scheduled run |
| GET | `/api/health` | None | Health check |

### Settings
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/settings` | Admin | Get settings (password masked) |
| PUT | `/api/settings` | Admin+CSRF | Update settings |
| GET | `/api/settings/export` | Admin | Export settings as JSON |
| POST | `/api/settings/import` | Admin+CSRF | Import settings from JSON |
| POST | `/api/settings/test-smtp` | Admin+CSRF | Test SMTP configuration |
| POST | `/api/settings/test-webhook` | Admin+CSRF | Test webhook |
| GET | `/api/email-templates` | Admin | Get all email templates |
| PUT | `/api/email-templates/<name>` | Admin+CSRF | Update template |
| PUT | `/api/email-templates/reset` | Admin+CSRF | Reset templates to defaults |

### Users
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/users` | Admin | List users |
| POST | `/api/users` | Admin+CSRF | Create user |
| PUT | `/api/users/<id>` | Admin+CSRF | Update user (password/role/is_active) |
| DELETE | `/api/users/<id>` | Admin+CSRF | Delete user |

### Security Settings
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/security-settings` | Admin | Get security settings |
| PUT | `/api/security-settings` | Admin+CSRF | Update security settings |

### API Keys
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/api-keys` | Admin | List API keys |
| POST | `/api/api-keys` | Admin+CSRF | Create API key |
| DELETE | `/api/api-keys/<id>` | Admin+CSRF | Revoke API key |
| POST | `/api/api-keys/bulk-revoke` | Admin+CSRF | Bulk revoke API keys |

### Logs & Backups
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/logs` | Admin | List audit logs (?limit, ?offset, ?type, ?search) |
| POST | `/api/logs` | Admin+CSRF | Create log entry |
| GET | `/api/backups` | Admin | List backups |
| POST | `/api/backups` | Admin+CSRF | Create backup |
| POST | `/api/backups/restore` | Admin+CSRF | Restore from backup |
| GET | `/api/backups/download/<file>` | Admin | Download backup file |
| DELETE | `/api/backups/<file>` | Admin+CSRF | Delete backup |

## Database Schema

### `domains`
`id`, `url`, `type` (full/ssl_only), `ssl_expiry`, `ssl_days_left`, `ssl_status`, `ssl_issuer`, `ssl_subject`, `ssl_sans`, `ssl_valid_from`, `ssl_valid_until`, `domain_expiry`, `domain_days_left`, `domain_status`, `domain_registrar`, `status`, `last_checked`, `notes`, `ssl_alert_threshold`, `domain_alert_threshold`, `created_at`, `last_alerted`, `manual_expiry_date`, `manual_registrar`, `tags`, `ssl_fingerprint`, `check_interval`

### `settings`
`id`, `smtp_server`, `smtp_port`, `smtp_email`, `smtp_password` (encrypted), `smtp_enabled`, `ssl_alert_threshold`, `domain_alert_threshold`, `alert_emails`, `slack_webhook_url`, `slack_enabled`, `zulip_webhook_url`, `zulip_enabled`, `last_summary_sent`

### `users`
`id`, `username`, `password` (werkzeug hash), `role` (admin/user/viewer), `is_active` (1/0), `login_fails`, `last_fail`, `last_login`, `created_at`

### `security_settings`
`id`, `session_timeout`, `max_login_attempts`, `lockout_duration`, `min_password_length`, `require_uppercase`, `require_lowercase`, `require_number`, `require_special`

### `api_keys`
`id`, `name`, `key_hash` (SHA256), `key_masked`, `revoked`, `created_at`, `last_used`

### `logs`
`id`, `type` (info/check/alert/error/alert_error), `message`, `domain_id`, `username`, `created_at`

### `health_snapshots`
`id`, `snapshot_date`, `ssl_healthy`, `ssl_total`, `domain_healthy`, `domain_total`, `created_at`

### `check_runs`
`id`, `run_type` (manual/scheduled), `status` (running/completed), `domains_checked`, `domains_total`, `started_at`, `completed_at`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | (required) | Flask session signing key |
| `ENCRYPTION_KEY` | (required) | Fernet key for SMTP password encryption |
| `FLASK_DEBUG` | `0` | Enable Flask debug mode |
| `PORT` | `5000` | App listen port |
| `DB_PATH` | `data_volume/ssl_checker.db` | SQLite database path |
| `BACKUP_DIR` | `backups/` | Backup storage directory |
| `MAX_BACKUPS` | `30` | Max backup files to retain |
| `HTTPS` | `1` | Enable Secure cookie flag and HSTS |
| `SESSION_LIFETIME_HOURS` | `24` | Max session lifetime |
| `RATE_LIMIT_DEFAULT` | `200 per day,50 per hour` | API rate limit |
| `RATE_LIMIT_LOGIN` | `10 per minute` | Login endpoint rate limit |
| `LOG_MAX_BYTES` | `5242880` | Log rotation size |
| `LOG_BACKUP_COUNT` | `3` | Log files to keep |
| `CHECK_WORKERS` | `20` | ThreadPoolExecutor workers |
| `SCHEDULER_INTERVAL_HOURS` | `24` | Auto-check interval |
| `WHOIS_TIMEOUT` | `15` | WHOIS socket timeout |
| `WHOIS_CACHE_TTL` | `300` | WHOIS cache lifetime |
| `WHOIS_RECV_TIMEOUT` | `5` | WHOIS recv chunk timeout |
| `SMTP_HOST` | — | Env override for SMTP server |
| `SMTP_PORT` | `587` | Env override for SMTP port |
| `SMTP_SECURE` | `true` | Enable STARTTLS for env SMTP |
| `SMTP_USER` | — | Env override for SMTP username |
| `SMTP_PASS` | — | Env override for SMTP password |
| `RECIPIENT_MAIL` | — | Env override for alert recipients |

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_models.py -v

# Run with coverage
pytest tests/ --cov=ssl_domain_checker -v
```

Test configuration is in `tests/conftest.py` — sets `SECRET_KEY`, `ENCRYPTION_KEY`, `WHOIS_TIMEOUT`, `WHOIS_CACHE_TTL`, and suppresses the first-run admin warning.

## Deployment

### Docker (recommended)
```bash
docker compose up -d
# App available at http://host:8010
```

### Bare-metal (systemd)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r ssl_domain_checker/requirements.txt
cp .env.sample .env  # edit as needed
# The ssl_checker.service file expects /opt/ssl_checker layout
gunicorn --workers 1 --threads 4 --bind 127.0.0.1:5000 app:app
```
