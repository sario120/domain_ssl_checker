# PROJECT_INFO.md — Vigil SSL/Domain/Webapp Monitor

## What It Does

Vigil is a self-hosted web application that monitors SSL certificate expiry, domain registration expiry, and web app uptime for a list of targets. It checks certificates (TLS handshake), WHOIS records, and HTTP endpoints on configurable schedules, sends alerts via email/Slack/Zulip when things go wrong, and provides a dashboard for at-a-glance health status.

## Core Features

- **SSL Certificate Checking** — Connects to port 443, retrieves the certificate, parses notBefore/notAfter, issuer, subject, SANs, TLS version, cipher suite, SHA-256 fingerprint, serial number, and full PEM chain.
- **WHOIS Domain Checking** — Queries WHOIS servers for domain expiry dates. Supports 40+ TLDs directly with IANA lookup fallback.
- **Web App Monitoring** — HTTP/HTTPS GET checks with status code + response time. Statuses: up, down, slow. Per-webapp check interval.
- **Certificate Details Modal** — Rich modal showing Identity, Validity (dates, days left, 30-day sparkline trend), Security (TLS version, cipher, fingerprint, serial), SANs, Metadata, PEM viewer, Check Now, and live last-checked.
- **Dual Domain Types** — "Full" domains get both SSL + WHOIS checks; "SSL-only" domains get cert checks only.
- **Manual Expiry Dates** — Domains can have manual expiry dates entered when WHOIS is unreliable.
- **Scheduled Checks** — APScheduler runs checks at configurable intervals (default 24h for domains, per-webapp interval for apps).
- **Alert System** — Sends email (SMTP with STARTTLS/SSL), Slack webhook, and/or Zulip webhook notifications when certs/domains/webapps are expiring or down.
- **Customizable Email Templates** — Subject, HTML body, and text body configurable per alert type (ssl_alert, domain_alert, webapp_alert, check_complete).
- **Check Summary Emails** — Daily summary of all-domain health sent after scheduled check.
- **User Management** — Role-based access (admin/user/viewer), account lockout, password policy, user deactivation/reactivation (admin cannot self-deactivate).
- **API Key Authentication** — Bearer token API keys for headless/automated access.
- **Database Backups** — Automatic daily gzipped SQLite backups with metadata, manual backup/restore via UI.
- **Health Snapshots** — Daily domain/SSL health data stored for dashboard display.
- **Import/Export** — Bulk domain import/export (JSON/CSV/TXT), webapp import/export (JSON/CSV/TXT), settings export/import.
- **Dark/Light Theme** — Persistent theme preference.
- **Keyboard Shortcuts** — Full keyboard navigation on domain lists.
- **Card/Table View Toggle** — Switch between grid cards and sortable table on Domains and SSL pages.
- **Sort & Filter** — Sort by Name/Status/Days Left/Last Checked, filter by status/search/TLD, group by status, column visibility.
- **Pagination** — Configurable page size (25/50/100), first/prev/next/last navigation.
- **Bulk Actions** — Select-all, shift-click range selection, bulk check/delete/export/notes/tags/compare/print.
- **Logs Page** — Search, type filter chips, summary cards (total/check/alert/error), activity bar chart, pagination with mobile card view.
- **Dashboard** — Stat cards (3-column with Domains, SSL, Web Apps), Scheduler Status, System Information, Webapp Failures section, Expiring lists (SSL + Domain).
- **Public Status Page** — `GET /api/webapps/status/public` endpoint for external uptime display.
- **Prometheus Metrics** — `GET /api/metrics` for domain status counts.

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
| GET | `/api/domains` | Login | List domains (?type, ?page, ?limit) |
| GET | `/api/domains/all` | Login | All domains grouped by type |
| POST | `/api/domains` | Admin+CSRF | Add domain |
| PUT | `/api/domains/<id>` | Admin+CSRF | Update domain |
| DELETE | `/api/domains/<id>` | Admin+CSRF | Delete domain |
| GET | `/api/domains/export` | Admin | Export as JSON/CSV/TXT |
| POST | `/api/domains/import` | Admin+CSRF | Import from JSON/CSV/TXT |
| POST | `/api/domains/<id>/check` | Admin+CSRF | Manual check single domain |
| POST | `/api/check-all` | Admin+CSRF | Check all domains |
| GET | `/api/domains/<id>/cert` | Login | Get cert details |
| GET | `/api/domains/<id>/history` | Login | Get check history |

### Web Apps
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/webapps` | Login | List webapps |
| POST | `/api/webapps` | Admin+CSRF | Add webapp |
| PUT | `/api/webapps/<id>` | Admin+CSRF | Update webapp |
| DELETE | `/api/webapps/<id>` | Admin+CSRF | Delete webapp |
| POST | `/api/webapps/bulk-delete` | Admin+CSRF | Bulk delete |
| POST | `/api/webapps/bulk-check` | Admin+CSRF | Check selected |
| POST | `/api/webapps/<id>/check` | Admin+CSRF | Check single webapp |
| POST | `/api/webapps/check-all` | Admin+CSRF | Check all webapps |
| GET | `/api/webapps/<id>/detail` | Login | Detail/downtime data |
| GET | `/api/webapps/<id>/results` | Login | Check results |
| GET | `/api/webapps/stats` | Login | Statistics |
| GET | `/api/webapps/export/csv` | Admin | Export as CSV |
| POST | `/api/webapps/import` | Admin+CSRF | Import from JSON/CSV/TXT |
| GET | `/api/webapps/status/public` | None | Public status page data |

### Dashboard & Status
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/dashboard/summary` | Login | Dashboard statistics, expiring lists, webapp failures |
| GET | `/api/scheduler/status` | Login | Next scheduled run with intervals |
| GET | `/api/health` | None | Health check |

### Settings
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/settings` | Admin | Get settings (password masked) |
| PUT | `/api/settings` | Admin+CSRF | Update settings |
| GET | `/api/settings/export` | Admin | Export settings as JSON |
| POST | `/api/settings/import` | Admin+CSRF | Import settings from JSON |
| POST | `/api/settings/test-smtp` | Admin+CSRF | Test SMTP |
| POST | `/api/settings/test-webhook` | Admin+CSRF | Test webhook |
| GET | `/api/email-templates` | Admin | Get all email templates |
| PUT | `/api/email-templates/<name>` | Admin+CSRF | Update template |
| PUT | `/api/email-templates/reset` | Admin+CSRF | Reset to defaults |

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

### Prometheus
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/metrics` | None | Prometheus-formatted metrics |

## Database Schema

### `domains`
`id`, `url`, `type` (full/ssl_only), `ssl_expiry`, `ssl_days_left`, `ssl_status`, `ssl_issuer`, `ssl_subject`, `ssl_sans`, `ssl_valid_from`, `ssl_valid_until`, `ssl_tls_version`, `ssl_cipher`, `ssl_fingerprint`, `ssl_serial`, `ssl_pem`, `domain_expiry`, `domain_days_left`, `domain_status`, `domain_registrar`, `status`, `last_checked`, `notes`, `ssl_alert_threshold`, `domain_alert_threshold`, `created_at`, `last_alerted`, `manual_expiry_date`, `manual_registrar`, `tags`, `check_interval`

### `webapps`
`id`, `name`, `url`, `method`, `expected_status`, `expected_body`, `timeout`, `headers`, `body`, `check_interval`, `status`, `response_time_ms`, `last_status_code`, `last_checked`, `last_error`, `uptime_count`, `downtime_count`, `total_checks`, `successful_checks`, `is_active`, `notify_on_down`, `notify_on_recovery`, `last_alerted`, `notes`, `status_changed_at`, `tags`, `created_at`, `updated_at`

### `webapp_results`
`id`, `webapp_id`, `status`, `status_code`, `response_time_ms`, `error`, `checked_at`

### `settings`
`id`, `smtp_server`, `smtp_port`, `smtp_email`, `smtp_password` (encrypted), `smtp_enabled`, `ssl_alert_threshold`, `domain_alert_threshold`, `alert_emails`, `slack_webhook_url`, `slack_enabled`, `zulip_webhook_url`, `zulip_enabled`, `last_summary_sent`, `backup_schedule_hour`, `backup_schedule_minute`, `max_backups`, `log_retention_days`

### `users`
`id`, `username`, `password` (werkzeug hash), `role` (admin/user/viewer), `is_active` (1/0), `login_fails`, `last_fail`, `last_login`, `created_at`

### `security_settings`
`id`, `session_timeout`, `max_login_attempts`, `lockout_duration`, `min_password_length`, `require_uppercase`, `require_lowercase`, `require_number`, `require_special`

### `api_keys`
`id`, `name`, `key_hash` (SHA256), `key_masked`, `revoked`, `created_at`, `last_used`

### `logs`
`id`, `type` (info/check/alert/error/alert_error/webapp_alert_error), `message`, `domain_id`, `username`, `client_ip`, `created_at`

### `health_snapshots`
`id`, `snapshot_date`, `ssl_healthy`, `ssl_total`, `domain_healthy`, `domain_total`, `created_at`

### `check_runs`
`id`, `run_type` (manual/scheduled), `status` (running/completed), `domains_checked`, `domains_total`, `started_at`, `completed_at`

### `check_results`
`id`, `domain_id`, `checked_at`, `status`, `result_json`, `ssl_days_left`, `domain_days_left`

### `rate_limits`
`key`, `count`, `window_start`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | (required) | Flask session signing key |
| `ENCRYPTION_KEY` | (required) | Fernet key for SMTP password encryption |
| `FLASK_DEBUG` | `0` | Enable Flask debug mode |
| `PORT` | `5000` | App listen port |
| `DB_TYPE` | `sqlite` | Database backend: sqlite or postgresql |
| `DB_PATH` | `data_volume/ssl_checker.db` | SQLite database path |
| `BACKUP_DIR` | `backups/` | Backup storage directory |
| `MAX_BACKUPS` | `30` | Max backup files to retain |
| `HTTPS` | `1` | Enable Secure cookie flag and HSTS |
| `SESSION_LIFETIME_HOURS` | `4` | Max session lifetime |
| `RATE_LIMIT_DEFAULT` | `200 per day,50 per hour` | API rate limit |
| `RATE_LIMIT_LOGIN` | `10 per minute` | Login endpoint rate limit |
| `LOG_MAX_BYTES` | `5242880` | Log rotation size |
| `LOG_BACKUP_COUNT` | `3` | Log files to keep |
| `CHECK_WORKERS` | `20` | ThreadPoolExecutor workers |
| `SCHEDULER_INTERVAL_HOURS` | `24` | Auto-check interval (domains) |
| `WEBAPP_CHECK_INTERVAL_SECONDS` | `300` | Auto-check interval (webapps) |
| `WHOIS_TIMEOUT` | `15` | WHOIS socket timeout |
| `WHOIS_CACHE_TTL` | `300` | WHOIS cache lifetime |
| `WHOIS_RECV_TIMEOUT` | `5` | WHOIS recv chunk timeout |
| `DATA_RETENTION_DAYS` | `90` | Old data retention period |
| `PG_POOL_MIN` | `2` | PostgreSQL pool min connections |
| `PG_POOL_MAX` | `10` | PostgreSQL pool max connections |

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_models.py -v

# Run with coverage
pytest tests/ --cov=ssl_domain_checker -v
```

62 test functions across 7 test files. Test configuration is in `tests/conftest.py` — sets `SECRET_KEY`, `ENCRYPTION_KEY`, `WHOIS_TIMEOUT`, `WHOIS_CACHE_TTL`, and suppresses the first-run admin warning.
