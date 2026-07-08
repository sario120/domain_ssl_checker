import datetime
import hashlib
import json
import logging
import os
import re
import secrets
import sys
import time
from zoneinfo import ZoneInfo

from flask import g
from werkzeug.security import generate_password_hash

import db
from crypto import encrypt, decrypt
from status_utils import ssl_status_from_days, domain_status_from_days, compute_manual_domain_status

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DB_PATH_ENV = os.environ.get("DB_PATH", "")
DB_PATH = os.path.abspath(_DB_PATH_ENV) if _DB_PATH_ENV else os.path.join(
    PROJECT_ROOT, "data_volume", "ssl_checker.db"
)

TIMEZONE = os.environ.get("TIMEZONE", "UTC")
_local_tz = ZoneInfo(TIMEZONE)

# Time constants (seconds)
STALE_RUN_SECONDS = 7200       # 2h before a running check is considered stale
ALERT_COOLDOWN_SECONDS = 86400  # 24h minimum between alerts for the same domain
SUMMARY_COOLDOWN_SECONDS = 86400  # 24h between summary emails
SCHEMA_VERSION = 1  # bump each time a migration is added in _run_migrations


def timezone_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def timezone_now_str():
    return timezone_now().strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(value):
    """Parse a DB timestamp — always returns a naive UTC datetime."""
    if isinstance(value, datetime.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.datetime.strptime(value, fmt)
            except ValueError:
                continue
        try:
            aware = datetime.datetime.fromisoformat(value)
            if aware.tzinfo is not None:
                return aware.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            return aware
        except (ValueError, TypeError):
            pass
    return None


def normalise_dt_str(value):
    """Return a consistent 'YYYY-MM-DD HH:MM:SS' string regardless of DB backend."""
    dt = parse_dt(value)
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else None


def to_local_time(dt_str):
    """Convert a UTC datetime string to the configured local timezone for display."""
    if not dt_str:
        return dt_str
    try:
        dt = datetime.datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(_local_tz).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return dt_str


def parse_hostname(url):
    hostname = url.strip()
    hostname = re.sub(r'^https?://', '', hostname)
    return hostname.split('/')[0].split(':')[0]


def is_valid_domain(url):
    hostname = parse_hostname(url)
    try:
        hostname.encode('idna')
    except (UnicodeError, UnicodeDecodeError):
        return False
    return bool(re.match(
        r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$',
        hostname
    )    )


_MULTI_TLD = frozenset({
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'net.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
    'co.nz', 'org.nz', 'net.nz', 'govt.nz', 'ac.nz', 'gen.nz',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'ed.jp',
    'com.br', 'org.br', 'net.br', 'gov.br', 'edu.br',
    'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in',
    'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za',
    'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il',
    'com.sg', 'org.sg', 'net.sg', 'gov.sg', 'edu.sg',
    'com.hk', 'org.hk', 'net.hk', 'gov.hk', 'edu.hk',
    'com.mx', 'org.mx', 'net.mx', 'gob.mx',
    'co.kr', 'or.kr', 'ne.kr', 'go.kr',
    'com.cn', 'org.cn', 'net.cn', 'gov.cn',
    'com.ar', 'net.ar', 'org.ar', 'gov.ar',
    'com.tr', 'org.tr', 'net.tr', 'gov.tr', 'edu.tr',
    'com.pt', 'org.pt', 'net.pt', 'gov.pt',
    'co.at', 'or.at', 'ac.at',
    'co.id', 'or.id', 'ac.id', 'net.id', 'go.id',
    'com.ua', 'org.ua', 'net.ua', 'gov.ua',
    'com.eg', 'org.eg', 'net.eg', 'gov.eg',
    'co.th', 'or.th', 'net.th', 'go.th', 'ac.th',
    'com.tw', 'org.tw', 'net.tw', 'gov.tw',
    'com.vn', 'org.vn', 'net.vn', 'gov.vn',
    'co.gg', 'net.gg', 'org.gg',
    'co.je', 'net.je', 'org.je',
})

def infer_domain_type(hostname):
    hostname = parse_hostname(hostname)
    parts = hostname.lower().split('.')
    if len(parts) < 2:
        return 'full'
    if len(parts) >= 2:
        last_two = '.'.join(parts[-2:])
        if last_two in _MULTI_TLD:
            if len(parts) == 3:
                return 'full'
            return 'ssl_only'
    if len(parts) == 2:
        return 'full'
    return 'ssl_only'


def normalise_url(url):
    url = url.strip()
    if url.startswith(('http://', 'https://')):
        return url
    host = url.split('/')[0].split(':')[0]
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) or host in ('localhost',) or '.' not in host:
        url = 'http://' + url
    else:
        url = 'https://' + url
    return url


def _connect():
    return db.connect()


def get_db():
    return db.get_db()


def close_db(e=None):
    db.close_db(e)


def check_rate_limit(key, max_requests, window_seconds):
    conn = get_db()
    now = time.time()
    row = conn.execute("SELECT count, window_start FROM rate_limits WHERE key=?", (key,)).fetchone()
    if not row or now - row["window_start"] > window_seconds:
        conn.execute(
            "INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?) "
            "ON CONFLICT(key) DO UPDATE SET count=1, window_start=?",
            (key, now, now)
        )
        conn.commit()
        return True
    if row["count"] >= max_requests:
        return False
    conn.execute("UPDATE rate_limits SET count=count+1 WHERE key=?", (key,))
    conn.commit()
    return True


_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL DEFAULT 'full',
    ssl_expiry TEXT, ssl_days_left INTEGER, ssl_status TEXT DEFAULT 'pending',
    ssl_issuer TEXT, ssl_subject TEXT, ssl_sans TEXT,
    ssl_valid_from TEXT, ssl_valid_until TEXT,
    domain_expiry TEXT, domain_days_left INTEGER,
    domain_status TEXT DEFAULT 'pending', domain_registrar TEXT,
    status TEXT DEFAULT 'pending', last_checked TEXT,
    notes TEXT, ssl_alert_threshold INTEGER, domain_alert_threshold INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(), last_alerted TIMESTAMPTZ,
    ssl_tls_version TEXT, ssl_cipher TEXT, ssl_fingerprint TEXT, ssl_serial TEXT,
    tags TEXT DEFAULT '', check_interval INTEGER DEFAULT 360,
    manual_registrar TEXT, manual_expiry_date TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    id BIGSERIAL PRIMARY KEY,
    smtp_server TEXT DEFAULT 'smtp.gmail.com', smtp_port INTEGER DEFAULT 587,
    smtp_email TEXT DEFAULT '', smtp_password TEXT DEFAULT '',
    smtp_enabled BOOLEAN DEFAULT FALSE,
    ssl_alert_threshold INTEGER DEFAULT 30, domain_alert_threshold INTEGER DEFAULT 30,
    alert_emails TEXT DEFAULT '',
    slack_webhook_url TEXT DEFAULT '', slack_enabled BOOLEAN DEFAULT FALSE,
    zulip_webhook_url TEXT DEFAULT '', zulip_enabled BOOLEAN DEFAULT FALSE,
    discord_webhook_url TEXT DEFAULT '', discord_enabled BOOLEAN DEFAULT FALSE,
    telegram_bot_token TEXT DEFAULT '', telegram_chat_id TEXT DEFAULT '',
    telegram_enabled BOOLEAN DEFAULT FALSE,
    teams_webhook_url TEXT DEFAULT '', teams_enabled BOOLEAN DEFAULT FALSE,
    last_summary_sent TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS logs (
    id BIGSERIAL PRIMARY KEY,
    type TEXT NOT NULL DEFAULT 'info', message TEXT NOT NULL,
    domain_id INTEGER REFERENCES domains(id) ON DELETE SET NULL,
    username TEXT, client_ip TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE, email TEXT, password TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    login_fails INTEGER DEFAULT 0, last_fail TIMESTAMPTZ, last_login TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS invite_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_invite_tokens_hash ON invite_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_invite_tokens_user ON invite_tokens(user_id);
CREATE TABLE IF NOT EXISTS security_settings (
    id BIGSERIAL PRIMARY KEY,
    session_timeout INTEGER DEFAULT 60, max_login_attempts INTEGER DEFAULT 5,
    lockout_duration INTEGER DEFAULT 15, min_password_length INTEGER DEFAULT 8,
    require_uppercase BOOLEAN DEFAULT TRUE, require_lowercase BOOLEAN DEFAULT TRUE,
    require_number BOOLEAN DEFAULT TRUE, require_special BOOLEAN DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE, key_masked TEXT NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(), last_used TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domains_url ON domains(url);
CREATE INDEX IF NOT EXISTS idx_domains_type ON domains(type);
CREATE INDEX IF NOT EXISTS idx_domains_ssl_status ON domains(ssl_status);
CREATE INDEX IF NOT EXISTS idx_domains_domain_status ON domains(domain_status);
CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(type);
CREATE INDEX IF NOT EXISTS idx_logs_domain_id ON logs(domain_id);
CREATE INDEX IF NOT EXISTS idx_domains_last_checked ON domains(last_checked);
CREATE INDEX IF NOT EXISTS idx_domains_created_at ON domains(created_at);
CREATE INDEX IF NOT EXISTS idx_domains_ssl_days_left ON domains(ssl_days_left);
CREATE INDEX IF NOT EXISTS idx_domains_domain_days_left ON domains(domain_days_left);
CREATE INDEX IF NOT EXISTS idx_domains_last_alerted ON domains(last_alerted);
CREATE TABLE IF NOT EXISTS health_snapshots (
    id BIGSERIAL PRIMARY KEY,
    snapshot_date TEXT NOT NULL UNIQUE,
    ssl_healthy INTEGER DEFAULT 0, ssl_total INTEGER DEFAULT 0,
    domain_healthy INTEGER DEFAULT 0, domain_total INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_health_date ON health_snapshots(snapshot_date);
CREATE TABLE IF NOT EXISTS check_runs (
    id BIGSERIAL PRIMARY KEY,
    run_type TEXT NOT NULL DEFAULT 'manual', status TEXT NOT NULL DEFAULT 'running',
    domains_checked INTEGER DEFAULT 0, domains_total INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ DEFAULT NOW(), completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_check_runs_started ON check_runs(started_at);
CREATE INDEX IF NOT EXISTS idx_check_runs_status ON check_runs(status);
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY, count INTEGER DEFAULT 0, window_start DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);
CREATE TABLE IF NOT EXISTS check_results (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT,
    result_json JSONB,
    ssl_days_left INTEGER,
    domain_days_left INTEGER
);
CREATE INDEX IF NOT EXISTS idx_check_results_domain ON check_results(domain_id, checked_at DESC);
ALTER TABLE domains ADD COLUMN IF NOT EXISTS check_details JSONB;
CREATE TABLE IF NOT EXISTS webapps (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    expected_status INTEGER DEFAULT 200,
    expected_body TEXT,
    timeout INTEGER DEFAULT 10,
    headers JSONB,
    body TEXT,
    check_interval INTEGER DEFAULT 300,
    status TEXT DEFAULT 'unknown',
    response_time_ms DOUBLE PRECISION,
    last_status_code INTEGER,
    last_checked TIMESTAMPTZ,
    last_error TEXT,
    uptime_count INTEGER DEFAULT 0,
    downtime_count INTEGER DEFAULT 0,
    total_checks INTEGER DEFAULT 0,
    successful_checks INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    notify_on_down BOOLEAN DEFAULT TRUE,
    notify_on_recovery BOOLEAN DEFAULT TRUE,
    last_alerted TIMESTAMPTZ,
    notes TEXT,
    status_changed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webapps_status ON webapps(status);
CREATE INDEX IF NOT EXISTS idx_webapps_active ON webapps(is_active);
CREATE TABLE IF NOT EXISTS webapp_results (
    id BIGSERIAL PRIMARY KEY,
    webapp_id INTEGER NOT NULL REFERENCES webapps(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    status_code INTEGER,
    response_time_ms DOUBLE PRECISION,
    error TEXT,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webapp_results_app ON webapp_results(webapp_id, checked_at DESC);
CREATE TABLE IF NOT EXISTS port_checks (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 80,
    check_interval INTEGER DEFAULT 300,
    timeout INTEGER DEFAULT 10,
    use_ipv6 BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'unknown',
    last_response_time_ms DOUBLE PRECISION,
    last_checked TIMESTAMPTZ,
    last_error TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    notify_on_down BOOLEAN DEFAULT TRUE,
    notify_on_recovery BOOLEAN DEFAULT TRUE,
    last_alerted TIMESTAMPTZ,
    status_changed_at TIMESTAMPTZ,
    notes TEXT,
    tags TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_port_checks_status ON port_checks(status);
CREATE INDEX IF NOT EXISTS idx_port_checks_active ON port_checks(is_active);
CREATE TABLE IF NOT EXISTS dns_checks (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    record_type TEXT NOT NULL DEFAULT 'A',
    expected_value TEXT,
    check_interval INTEGER DEFAULT 300,
    status TEXT DEFAULT 'unknown',
    last_result TEXT,
    last_checked TIMESTAMPTZ,
    last_error TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    notify_on_down BOOLEAN DEFAULT TRUE,
    notify_on_recovery BOOLEAN DEFAULT TRUE,
    last_alerted TIMESTAMPTZ,
    status_changed_at TIMESTAMPTZ,
    notes TEXT,
    tags TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_checks_status ON dns_checks(status);
CREATE INDEX IF NOT EXISTS idx_dns_checks_active ON dns_checks(is_active);
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    day_of_week INTEGER NOT NULL DEFAULT 7,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    timezone TEXT DEFAULT 'UTC',
    target_type TEXT DEFAULT 'all',
    target_ids TEXT DEFAULT '[]',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
""";

_MIGRATION_DOMAIN_COLS = frozenset({
    'ssl_alert_threshold', 'domain_alert_threshold', 'notes', 'manual_expiry_date',
    'check_interval', 'manual_registrar', 'last_alerted', 'tags', 'ssl_fingerprint',
    'ssl_tls_version', 'ssl_cipher', 'ssl_serial',
    'ct_monitoring_enabled', 'ct_last_known_ids', 'ct_last_checked',
})
_MIGRATION_SETTINGS_COLS = frozenset({
    'last_summary_sent', 'slack_webhook_url', 'slack_enabled',
    'zulip_webhook_url', 'zulip_enabled',
    'discord_webhook_url', 'discord_enabled',
    'telegram_bot_token', 'telegram_chat_id', 'telegram_enabled',
    'teams_webhook_url', 'teams_enabled',
    'backup_schedule_hour', 'backup_schedule_minute', 'max_backups',
    'log_retention_days',
})


def _run_postgres_migrations():
    conn = get_db()
    conn.executescript(_PG_SCHEMA)
    conn.commit()

    pg_pl = db.placeholder()

    for col, dtype, default in [
        ('manual_registrar', 'TEXT', None),
        ('manual_expiry_date', 'TEXT', None),
        ('tags', 'TEXT', "''"),
        ('ssl_fingerprint', 'TEXT', None),
        ('ssl_tls_version', 'TEXT', None),
        ('ssl_cipher', 'TEXT', None),
        ('ssl_serial', 'TEXT', None),
        ('check_interval', 'INTEGER', '360'),
        ('ssl_alert_threshold', 'INTEGER', None),
        ('domain_alert_threshold', 'INTEGER', None),
        ('notes', 'TEXT', None),
        ('last_alerted', 'TIMESTAMPTZ', None),
        ('ct_monitoring_enabled', 'BOOLEAN', 'FALSE'),
        ('ct_last_known_ids', 'TEXT', None),
        ('ct_last_checked', 'TIMESTAMPTZ', None),
    ]:
        if col not in db.table_columns('domains'):
            if col not in _MIGRATION_DOMAIN_COLS:
                raise ValueError(f"Invalid migration column: {col}")
            default_clause = f"DEFAULT {default}" if default else ""
            conn.execute(f"ALTER TABLE domains ADD COLUMN {col} {dtype} {default_clause}")

    if 'role' not in db.table_columns('users'):
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    if 'is_active' not in db.table_columns('users'):
        conn.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE")
    if 'email' not in db.table_columns('users'):
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if 'username' not in db.table_columns('logs'):
        conn.execute("ALTER TABLE logs ADD COLUMN username TEXT")
    if 'client_ip' not in db.table_columns('logs'):
        conn.execute("ALTER TABLE logs ADD COLUMN client_ip TEXT")
    if 'last_summary_sent' not in db.table_columns('settings'):
        conn.execute("ALTER TABLE settings ADD COLUMN last_summary_sent TIMESTAMPTZ")
    if 'backup_schedule_hour' not in db.table_columns('settings'):
        conn.execute("ALTER TABLE settings ADD COLUMN backup_schedule_hour INTEGER DEFAULT 3")
    if 'backup_schedule_minute' not in db.table_columns('settings'):
        conn.execute("ALTER TABLE settings ADD COLUMN backup_schedule_minute INTEGER DEFAULT 0")
    if 'max_backups' not in db.table_columns('settings'):
        conn.execute("ALTER TABLE settings ADD COLUMN max_backups INTEGER DEFAULT 30")
    if 'log_retention_days' not in db.table_columns('settings'):
        conn.execute("ALTER TABLE settings ADD COLUMN log_retention_days INTEGER DEFAULT 90")

    for col, dtype in [
        ('slack_webhook_url', 'TEXT'), ('slack_enabled', 'BOOLEAN'),
        ('zulip_webhook_url', 'TEXT'), ('zulip_enabled', 'BOOLEAN'),
        ('discord_webhook_url', 'TEXT'), ('discord_enabled', 'BOOLEAN'),
        ('telegram_bot_token', 'TEXT'), ('telegram_chat_id', 'TEXT'),
        ('telegram_enabled', 'BOOLEAN'),
        ('teams_webhook_url', 'TEXT'), ('teams_enabled', 'BOOLEAN'),
    ]:
        if col not in db.table_columns('settings'):
            if col not in _MIGRATION_SETTINGS_COLS:
                raise ValueError(f"Invalid migration column: {col}")
            conn.execute(f"ALTER TABLE settings ADD COLUMN {col} {dtype} DEFAULT FALSE")

    if 'last_alerted' not in db.table_columns('webapps'):
        conn.execute("ALTER TABLE webapps ADD COLUMN last_alerted TIMESTAMPTZ")
    if 'status_changed_at' not in db.table_columns('webapps'):
        conn.execute("ALTER TABLE webapps ADD COLUMN status_changed_at TIMESTAMPTZ")
    if 'tags' not in db.table_columns('webapps'):
        conn.execute("ALTER TABLE webapps ADD COLUMN tags TEXT DEFAULT ''")
    if 'expected_body_negate' not in db.table_columns('webapps'):
        conn.execute("ALTER TABLE webapps ADD COLUMN expected_body_negate BOOLEAN DEFAULT FALSE")

    conn.commit()


def init_db():
    logger.info("Database backend: %s", db.DB_TYPE)

    _run_postgres_migrations()

    conn = get_db()

    count = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()['cnt']
    if count == 0:
        admin_pwd = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(16)
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')",
                     ("admin", generate_password_hash(admin_pwd)))
        conn.commit()
        if os.environ.get("ADMIN_PASSWORD"):
            logger.info("Admin user created from ADMIN_PASSWORD env var")
        else:
            creds_path = os.path.join(os.path.dirname(DB_PATH), "admin_credentials.txt")
            try:
                os.makedirs(os.path.dirname(creds_path), exist_ok=True)
                with open(creds_path, "w") as f:
                    f.write(f"username=admin\npassword={admin_pwd}\nCHANGE IMMEDIATELY\n")
                os.chmod(creds_path, 0o600)
                logger.warning("Admin credentials written to %s — CHANGE IMMEDIATELY", creds_path)
            except OSError:
                logger.warning("Could not write admin credentials to %s", creds_path)

    # Schema version check
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    current_ver = row['version'] if row else 0
    if current_ver < SCHEMA_VERSION:
        logger.info("Schema version %d → %d", current_ver, SCHEMA_VERSION)
        pl = db.placeholder()
        if current_ver == 0:
            conn.execute(f"INSERT INTO schema_version (version) VALUES ({pl})", (SCHEMA_VERSION,))
        else:
            conn.execute(f"UPDATE schema_version SET version={pl}", (SCHEMA_VERSION,))
        conn.commit()


def get_domains(type_filter=None):
    conn = get_db()
    if type_filter:
        rows = conn.execute("SELECT * FROM domains WHERE type=? ORDER BY url", (type_filter,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM domains ORDER BY url").fetchall()
    domains = [dict(r) for r in rows]
    for d in domains:
        if d.get("manual_expiry_date"):
            days, status, expiry = compute_manual_domain_status(d["manual_expiry_date"])
            if status:
                d["domain_days_left"] = days
                d["domain_expiry"] = expiry
                d["domain_status"] = status
                if d.get("status") == "pending":
                    d["status"] = status
    return domains


def get_domain(domain_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("manual_expiry_date"):
        days, status, expiry = compute_manual_domain_status(d["manual_expiry_date"])
        if status:
            d["domain_days_left"] = days
            d["domain_expiry"] = expiry
            d["domain_status"] = status
            if d.get("status") == "pending":
                d["status"] = status
    return d


def update_last_alerted(domain_id):
    conn = get_db()
    conn.execute("UPDATE domains SET last_alerted=? WHERE id=?", (timezone_now_str(), domain_id))
    conn.commit()


def add_domain(url, domain_type="full", notes="", manual_expiry_date=None, manual_registrar=None):
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO domains (url, type, notes, manual_expiry_date, manual_registrar) "
            "VALUES (?, ?, ?, ?, ?) RETURNING id",
            (url, domain_type, notes, manual_expiry_date, manual_registrar)
        )
        new_id = cur.fetchone()['id']
        conn.commit()
        return {"ok": True, "id": new_id}
    except Exception as e:
        conn.rollback()
        if db.is_integrity_error(e):
            return {"ok": False, "error": "Domain already exists"}
        logger.exception("Failed to add domain %s", url)
        return {"ok": False, "error": "Internal error"}


_ALLOWED_DOMAIN_COLS = frozenset({
    'url', 'type', 'notes', 'manual_expiry_date', 'manual_registrar',
    'ct_monitoring_enabled', 'ct_last_known_ids', 'ct_last_checked',
})
_ALLOWED_SETTINGS_COLS = frozenset({
    'smtp_server', 'smtp_port', 'smtp_email', 'smtp_password', 'smtp_enabled',
    'ssl_alert_threshold', 'domain_alert_threshold', 'alert_emails',
    'slack_webhook_url', 'slack_enabled', 'zulip_webhook_url', 'zulip_enabled',
    'discord_webhook_url', 'discord_enabled',
    'telegram_bot_token', 'telegram_chat_id', 'telegram_enabled',
    'teams_webhook_url', 'teams_enabled',
    'email_templates', 'backup_schedule_hour', 'backup_schedule_minute', 'max_backups',
    'log_retention_days',
})
_ALLOWED_USER_COLS = frozenset({'password', 'role', 'email'})
_BOOLEAN_SETTINGS_COLS = frozenset({'smtp_enabled', 'slack_enabled', 'zulip_enabled',
                                     'discord_enabled', 'telegram_enabled', 'teams_enabled'})


def update_domain(domain_id, url=None, domain_type=None, notes=None, manual_expiry_date=None, manual_registrar=None, ct_monitoring_enabled=None):
    conn = get_db()
    fields = {}
    if url is not None: fields["url"] = url
    if domain_type is not None: fields["type"] = domain_type
    if notes is not None: fields["notes"] = notes
    if manual_expiry_date is not None: fields["manual_expiry_date"] = manual_expiry_date
    if manual_registrar is not None: fields["manual_registrar"] = manual_registrar
    if ct_monitoring_enabled is not None: fields["ct_monitoring_enabled"] = bool(ct_monitoring_enabled)
    fields = {k: v for k, v in fields.items() if k in _ALLOWED_DOMAIN_COLS}
    if fields:
        fields["id"] = domain_id
        sets = ", ".join(f"{k}=?" for k in fields if k != "id")
        conn.execute(f"UPDATE domains SET {sets} WHERE id=?", tuple(fields.values()))
        conn.commit()
    return {"ok": True}


def delete_domain(domain_id):
    conn = get_db()
    conn.execute("DELETE FROM domains WHERE id=?", (domain_id,))
    conn.commit()
    return {"ok": True}


def save_domain_check(domain_id, result):
    conn = get_db()
    r = result
    dom = get_domain(domain_id)
    domain_expiry = r.get("domain_expiry")
    domain_days_left = r.get("domain_days_left")
    domain_status = r.get("domain_status")
    if domain_expiry is None and dom and dom.get("manual_expiry_date"):
        days, status, expiry = compute_manual_domain_status(dom["manual_expiry_date"])
        if status:
            domain_expiry = expiry
            domain_days_left = days
            domain_status = status
    conn.execute("""UPDATE domains SET
        ssl_expiry=?, ssl_days_left=?, ssl_status=?, ssl_issuer=?, ssl_subject=?,
        ssl_sans=?, ssl_valid_from=?, ssl_valid_until=?,
        ssl_tls_version=?, ssl_cipher=?, ssl_fingerprint=?, ssl_serial=?,
        domain_expiry=?, domain_days_left=?, domain_status=?, domain_registrar=?,
        status=?, last_checked=?
        WHERE id=?""", (
        r.get("ssl_expiry"), r.get("ssl_days_left"), r.get("ssl_status"),
        r.get("ssl_issuer"), r.get("ssl_subject"), r.get("ssl_sans"),
        r.get("ssl_valid_from"), r.get("ssl_valid_until"),
        r.get("ssl_tls_version"), r.get("ssl_cipher"),
        r.get("ssl_fingerprint"), r.get("ssl_serial"),
        domain_expiry, domain_days_left, domain_status,
        r.get("domain_registrar"), r.get("status"), timezone_now_str(), domain_id
    ))
    conn.commit()


def save_domain_checks_batch(results):
    """Batch save many check results in a single transaction."""
    conn = get_db()
    now = timezone_now_str()
    manual = {}
    for r in results:
        if r.get("domain_expiry") is None:
            did = r.get("domain_id")
            if did and did not in manual:
                dom = get_domain(did)
                if dom and dom.get("manual_expiry_date"):
                    days, status, expiry = compute_manual_domain_status(dom["manual_expiry_date"])
                    if status:
                        manual[did] = (expiry, days, status)
    params_list = []
    for r in results:
        domain_id = r.get("domain_id")
        domain_expiry = r.get("domain_expiry")
        domain_days_left = r.get("domain_days_left")
        domain_status = r.get("domain_status")
        if domain_expiry is None and domain_id in manual:
            domain_expiry, domain_days_left, domain_status = manual[domain_id]
        params_list.append((
            r.get("ssl_expiry"), r.get("ssl_days_left"), r.get("ssl_status"),
            r.get("ssl_issuer"), r.get("ssl_subject"), r.get("ssl_sans"),
            r.get("ssl_valid_from"), r.get("ssl_valid_until"),
            r.get("ssl_tls_version"), r.get("ssl_cipher"),
            r.get("ssl_fingerprint"), r.get("ssl_serial"),
            domain_expiry, domain_days_left, domain_status,
            r.get("domain_registrar"), r.get("status"), now, domain_id
        ))
    try:
        conn.executemany("""UPDATE domains SET
            ssl_expiry=?, ssl_days_left=?, ssl_status=?, ssl_issuer=?, ssl_subject=?,
            ssl_sans=?, ssl_valid_from=?, ssl_valid_until=?,
            ssl_tls_version=?, ssl_cipher=?, ssl_fingerprint=?, ssl_serial=?,
            domain_expiry=?, domain_days_left=?, domain_status=?, domain_registrar=?,
            status=?, last_checked=?
            WHERE id=?""", params_list)
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        logger.exception("Batch domain check save failed — %d results rolled back", len(results))
        return False


def save_check_result_history(domain_id, result):
    """Store a check result in the history table."""
    conn = get_db()
    now = timezone_now_str()
    result_json = json.dumps({
        k: v for k, v in result.items()
        if k in ('ssl_expiry', 'ssl_days_left', 'ssl_status', 'ssl_issuer',
                 'ssl_subject', 'ssl_sans', 'ssl_valid_from', 'ssl_valid_until',
                 'ssl_tls_version', 'ssl_cipher', 'ssl_fingerprint', 'ssl_serial', 'ssl_pem',
                 'domain_expiry', 'domain_days_left', 'domain_status',
                 'domain_registrar', 'domain_error')
    }, default=str)
    conn.execute(
        "INSERT INTO check_results (domain_id, checked_at, status, result_json, "
        "ssl_days_left, domain_days_left) VALUES (?, ?, ?, ?, ?, ?)",
        (domain_id, now, result.get('status'), result_json,
         result.get('ssl_days_left'), result.get('domain_days_left'))
    )
    conn.commit()


def save_check_results_batch(results):
    """Batch store check result history."""
    conn = get_db()
    now = timezone_now_str()
    params = []
    for r in results:
        result_json = json.dumps({
            k: v for k, v in r.items()
            if k in ('ssl_expiry', 'ssl_days_left', 'ssl_status', 'ssl_issuer',
                     'ssl_subject', 'ssl_sans', 'ssl_valid_from', 'ssl_valid_until',
                     'ssl_tls_version', 'ssl_cipher', 'ssl_fingerprint', 'ssl_serial', 'ssl_pem',
                     'domain_expiry', 'domain_days_left', 'domain_status',
                     'domain_registrar', 'domain_error')
        }, default=str)
        params.append((
            r.get('domain_id'), now, r.get('status'), result_json,
            r.get('ssl_days_left'), r.get('domain_days_left')
        ))
    try:
        conn.executemany(
            "INSERT INTO check_results (domain_id, checked_at, status, result_json, "
            "ssl_days_left, domain_days_left) VALUES (?, ?, ?, ?, ?, ?)",
            params
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Batch result history save failed — %d results rolled back", len(results))


def cleanup_old_data(retention_days=90):
    """Remove check history, logs, and stale rate-limit entries older than retention_days."""
    conn = get_db()
    cutoff = timezone_now() - datetime.timedelta(days=retention_days)
    deleted = conn.execute("DELETE FROM check_results WHERE checked_at < ?", (cutoff,)).rowcount
    deleted += conn.execute("DELETE FROM logs WHERE created_at < ?", (cutoff,)).rowcount
    deleted += conn.execute(
        "DELETE FROM check_runs WHERE completed_at IS NOT NULL AND completed_at < ?",
        (cutoff,)
    ).rowcount
    deleted += conn.execute(
        "DELETE FROM webapp_results WHERE checked_at < ?",
        (cutoff,)
    ).rowcount
    deleted += conn.execute(
        "DELETE FROM rate_limits WHERE window_start < ?",
        (time.time() - 86400,)
    ).rowcount
    conn.commit()
    return deleted


def add_logs_batch(entries):
    """Batch insert log entries. Each entry is (type, message, domain_id, username, client_ip)."""
    conn = get_db()
    conn.executemany(
        "INSERT INTO logs (type, message, domain_id, username, client_ip) VALUES (?, ?, ?, ?, ?)",
        entries
    )
    conn.commit()


def get_settings():
    conn = get_db()
    row = conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
    if row:
        s = dict(row)
        try:
            s['smtp_password'] = decrypt(s.get('smtp_password', ''))
        except ValueError as e:
            logger.error("Failed to decrypt SMTP password: %s", e)
            s['smtp_password'] = ''

        env_host = os.environ.get('SMTP_HOST', '').strip()
        if env_host:
            s['smtp_server'] = env_host
            s['smtp_port'] = int(os.environ.get('SMTP_PORT', '587'))
            s['smtp_email'] = os.environ.get('SMTP_USER', '')
            env_pass = os.environ.get('SMTP_PASS', '')
            s['smtp_password'] = env_pass
            s['alert_emails'] = os.environ.get('RECIPIENT_MAIL', '')
            s['smtp_from_env'] = True
        else:
            s['smtp_from_env'] = False
        return s
    return None


def init_settings():
    conn = get_db()
    row = conn.execute("SELECT id, smtp_password FROM settings WHERE id=1").fetchone()
    if not row:
        conn.execute("INSERT INTO settings DEFAULT VALUES")
        conn.commit()
    else:
        pwd = row['smtp_password']
        if pwd:
            if not pwd.startswith('gAAAAA'):
                try:
                    encrypted = encrypt(pwd)
                    conn.execute("UPDATE settings SET smtp_password=? WHERE id=1", (encrypted,))
                    conn.commit()
                except ValueError as e:
                    logger.warning("Cannot encrypt existing plaintext SMTP password: %s", e)
            else:
                try:
                    plain = decrypt(pwd)
                    if os.environ.get('ENCRYPTION_KEY'):
                        try:
                            re_encrypted = encrypt(plain)
                            conn.execute("UPDATE settings SET smtp_password=? WHERE id=1", (re_encrypted,))
                            conn.commit()
                            logger.info("Migrated encrypted SMTP password to current ENCRYPTION_KEY")
                        except ValueError as e:
                            logger.warning("Failed to re-encrypt SMTP password with current ENCRYPTION_KEY: %s", e)
                    else:
                        logger.warning(
                            "SMTP password is encrypted with SECRET_KEY (legacy). "
                            "Set ENCRYPTION_KEY to migrate to dedicated encryption."
                        )
                except ValueError as e:
                    logger.warning("Existing encrypted SMTP password could not be decrypted: %s", e)


def update_settings(data):
    conn = get_db()
    env_managed = frozenset({'smtp_server', 'smtp_port', 'smtp_email', 'smtp_password', 'alert_emails'})
    vals = []
    set_cols = []
    for k in _ALLOWED_SETTINGS_COLS:
        if k in _ALLOWED_SETTINGS_COLS and k in data and k not in env_managed:
            v = data[k]
            if k == 'smtp_password' and v:
                v = encrypt(v)
            elif k in _BOOLEAN_SETTINGS_COLS:
                v = bool(v)
            set_cols.append(k)
            vals.append(v)
    if set_cols:
        sets = ", ".join(f"{k}=?" for k in set_cols)
        conn.execute(f"UPDATE settings SET {sets} WHERE id=1", vals)
        conn.commit()
    return {"ok": True}


def update_last_summary_sent():
    conn = get_db()
    conn.execute("UPDATE settings SET last_summary_sent=? WHERE id=1", (timezone_now_str(),))
    conn.commit()


def clear_all_logs():
    conn = get_db()
    conn.execute("DELETE FROM logs")
    conn.commit()


def prune_logs():
    conn = get_db()
    settings = get_settings()
    raw = (settings or {}).get('log_retention_days', 90)
    try:
        retention_days = int(raw)
    except (ValueError, TypeError):
        retention_days = 90
    if retention_days <= 0:
        return
    cutoff = (timezone_now() - datetime.timedelta(days=retention_days)).strftime('%Y-%m-%d %H:%M:%S')
    conn.execute("DELETE FROM logs WHERE created_at < ?", (cutoff,))
    conn.commit()


def add_log(log_type, message, domain_id=None, username=None, client_ip=None):
    conn = get_db()
    conn.execute("INSERT INTO logs (type, message, domain_id, username, client_ip) VALUES (?, ?, ?, ?, ?)",
                 (log_type, message, domain_id, username, client_ip))
    conn.commit()


def _log_filters(log_type=None, query=None, from_date=None, to_date=None, exclude_type=None):
    clauses = []
    params = []
    if log_type and log_type != 'all':
        if log_type == 'error':
            clauses.append("(l.type=? OR l.type LIKE ?)")
            params.extend(['error', '%error%'])
        else:
            clauses.append("l.type=?")
            params.append(log_type)
    if exclude_type:
        if exclude_type == 'error':
            clauses.append("(l.type<>? AND l.type NOT LIKE ?)")
            params.extend(['error', '%error%'])
        else:
            clauses.append("l.type<>?")
            params.append(exclude_type)
    if from_date:
        clauses.append("l.created_at >= ?")
        params.append(from_date + ' 00:00:00')
    if to_date:
        clauses.append("l.created_at <= ?")
        params.append(to_date + ' 23:59:59')
    if query:
        escaped = query.replace('%', '\\%').replace('_', '\\_')
        like = f"%{escaped}%"
        clauses.append("(l.message LIKE ? ESCAPE '\\' OR l.username LIKE ? ESCAPE '\\' OR d.url LIKE ? ESCAPE '\\' OR l.type LIKE ? ESCAPE '\\')")
        params.extend([like, like, like, like])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    return where, params


def get_logs(limit=100, offset=0, log_type=None, query=None, from_date=None, to_date=None, exclude_type=None):
    conn = get_db()
    where, params = _log_filters(log_type, query, from_date, to_date, exclude_type)
    rows = conn.execute(f"""
        SELECT l.*, d.url as domain_url FROM logs l
        LEFT JOIN domains d ON l.domain_id = d.id
        {where}
        ORDER BY l.created_at DESC LIMIT ? OFFSET ?
    """, params + [limit, offset]).fetchall()
    return [dict(r) for r in rows]


def get_logs_count(log_type=None, query=None, from_date=None, to_date=None, exclude_type=None):
    conn = get_db()
    where, params = _log_filters(log_type, query, from_date, to_date, exclude_type)
    row = conn.execute(f"""
        SELECT COUNT(*) as cnt FROM logs l
        LEFT JOIN domains d ON l.domain_id = d.id
        {where}
    """, params).fetchone()
    return row['cnt']


def get_logs_summary(log_type=None, query=None, from_date=None, to_date=None, exclude_type=None):
    conn = get_db()
    where, params = _log_filters(log_type=log_type, query=query, from_date=from_date, to_date=to_date, exclude_type=exclude_type)
    rows = conn.execute(f"""
        SELECT l.type, COUNT(*) as cnt FROM logs l
        LEFT JOIN domains d ON l.domain_id = d.id
        {where}
        GROUP BY l.type
    """, params).fetchall()
    summary = {r['type'] or 'info': r['cnt'] for r in rows}
    summary['total'] = sum(summary.values())
    return summary


def get_logs_activity(date_str=None):
    conn = get_db()
    if date_str:
        start = date_str + ' 00:00:00'
        end = date_str + ' 23:59:59'
    else:
        today = timezone_now().strftime('%Y-%m-%d')
        start = today + ' 00:00:00'
        end = today + ' 23:59:59'
    hour_expr = "EXTRACT(HOUR FROM created_at)::int"
    rows = conn.execute(f"""
        SELECT {hour_expr} AS hour, COUNT(*) AS cnt
        FROM logs
        WHERE created_at >= ? AND created_at <= ?
        GROUP BY hour
        ORDER BY hour
    """, (start, end)).fetchall()
    hours = {r['hour']: r['cnt'] for r in rows}
    result = []
    for h in range(24):
        result.append({'hour': h, 'count': hours.get(h, 0)})
    return result


def get_users():
    conn = get_db()
    rows = conn.execute("SELECT id, username, email, role, login_fails, last_login, created_at, is_active, password FROM users ORDER BY username").fetchall()
    users = []
    for r in rows:
        u = dict(r)
        u['has_password'] = bool(u.pop('password'))
        users.append(u)
    return users


def get_user_by_username(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None


def get_user(user_id):
    conn = get_db()
    row = conn.execute("SELECT id, username, email, role, is_active FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_email(email):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    return dict(row) if row else None


def add_user(username, password=None, role="user", email=None):
    conn = get_db()
    try:
        if password:
            cur = conn.execute(
                "INSERT INTO users (username, email, password, role, is_active) VALUES (?, ?, ?, ?, ?) RETURNING id",
                (username, email, generate_password_hash(password), role, True)
            )
        else:
            cur = conn.execute(
                "INSERT INTO users (username, email, password, role, is_active) VALUES (?, ?, ?, ?, ?) RETURNING id",
                (username, email, '', role, False)
            )
        new_id = cur.fetchone()['id']
        conn.commit()
        return {"ok": True, "id": new_id}
    except Exception as e:
        if db.is_integrity_error(e):
            conn.rollback()
            return {"ok": False, "error": "Username already exists"}
        conn.rollback()
        raise


def update_user(user_id, password=None, role=None, is_active=None, email=None):
    conn = get_db()
    filtered = []
    if password:
        filtered.append(("password=?", generate_password_hash(password)))
    if role and role in ('admin', 'user', 'viewer'):
        filtered.append(("role=?", role))
    if is_active is not None:
        filtered.append(("is_active=?", bool(is_active)))
    if email is not None:
        filtered.append(("email=?", email))
    if not filtered:
        return {"ok": True}
    sets = ", ".join(s for s, _ in filtered)
    params = [v for _, v in filtered] + [user_id]
    conn.execute(f"UPDATE users SET {sets} WHERE id=?", params)
    conn.commit()
    return {"ok": True}


def delete_user(user_id, current_user_id):
    conn = get_db()
    if int(user_id) == int(current_user_id):
        return {"ok": False, "error": "Cannot delete yourself"}
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    return {"ok": True}


INVITE_TOKEN_EXPIRY_HOURS = 48


def create_invite_token(user_id):
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    expires_at = (timezone_now() + datetime.timedelta(hours=INVITE_TOKEN_EXPIRY_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    conn.execute(
        "INSERT INTO invite_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
        (user_id, token_hash, expires_at)
    )
    conn.commit()
    return raw


def invalidate_user_invite_tokens(user_id):
    conn = get_db()
    conn.execute(
        "UPDATE invite_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL",
        (timezone_now_str(), user_id)
    )
    conn.commit()


def verify_invite_token(raw_token):
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM invite_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at > ?",
        (token_hash, timezone_now_str())
    ).fetchone()
    return dict(row) if row else None


def complete_invite(raw_token, password):
    token = verify_invite_token(raw_token)
    if not token:
        return {"ok": False, "error": "Invalid or expired invite token"}
    conn = get_db()
    conn.execute(
        "UPDATE users SET password=?, is_active=1 WHERE id=?",
        (generate_password_hash(password), token["user_id"])
    )
    conn.execute(
        "UPDATE invite_tokens SET used_at=? WHERE id=?",
        (timezone_now_str(), token["id"])
    )
    conn.commit()
    return {"ok": True}


def record_login_attempt(username, success):
    conn = get_db()
    if success:
        conn.execute("UPDATE users SET login_fails=0, last_login=? WHERE username=?", (timezone_now_str(), username))
    else:
        conn.execute("UPDATE users SET login_fails=login_fails+1 WHERE username=?", (username,))
    conn.commit()


def is_user_locked(username):
    sec = get_security_settings()
    max_attempts = sec.get('max_login_attempts', 5)
    lockout = sec.get('lockout_duration', 15)
    conn = get_db()
    row = conn.execute("SELECT login_fails, last_fail FROM users WHERE username=?", (username,)).fetchone()
    if not row or row['login_fails'] < max_attempts:
        return False
    if row['last_fail']:
        last = parse_dt(row['last_fail'])
        if last and (timezone_now() - last) < datetime.timedelta(minutes=lockout):
            return True
        conn.execute("UPDATE users SET login_fails=0 WHERE username=?", (username,))
        conn.commit()
    return False


def record_fail_time(username):
    conn = get_db()
    conn.execute("UPDATE users SET last_fail=? WHERE username=?", (timezone_now_str(), username))
    conn.commit()


def get_security_settings():
    conn = get_db()
    row = conn.execute("SELECT * FROM security_settings LIMIT 1").fetchone()
    if row:
        return dict(row)
    return {
        'session_timeout': 60, 'max_login_attempts': 5, 'lockout_duration': 15,
        'min_password_length': 8, 'require_uppercase': 1, 'require_lowercase': 1,
        'require_number': 1, 'require_special': 0
    }


def update_security_settings(data):
    conn = get_db()
    existing = conn.execute("SELECT id FROM security_settings LIMIT 1").fetchone()
    if existing:
        conn.execute("""UPDATE security_settings SET
            session_timeout=?, max_login_attempts=?, lockout_duration=?,
            min_password_length=?, require_uppercase=?, require_lowercase=?,
            require_number=?, require_special=?
            WHERE id=?""",
            (data.get('session_timeout', 60), data.get('max_login_attempts', 5),
             data.get('lockout_duration', 15), data.get('min_password_length', 8),
             bool(data.get('require_uppercase', True)), bool(data.get('require_lowercase', True)),
             bool(data.get('require_number', True)), bool(data.get('require_special', False)),
             existing['id']))
    else:
        conn.execute("""INSERT INTO security_settings
            (session_timeout, max_login_attempts, lockout_duration,
             min_password_length, require_uppercase, require_lowercase,
             require_number, require_special)
            VALUES (?,?,?,?,?,?,?,?)""",
            (data.get('session_timeout', 60), data.get('max_login_attempts', 5),
             data.get('lockout_duration', 15), data.get('min_password_length', 8),
             bool(data.get('require_uppercase', True)), bool(data.get('require_lowercase', True)),
             bool(data.get('require_number', True)), bool(data.get('require_special', False))))
    conn.commit()


def get_api_keys():
    conn = get_db()
    rows = conn.execute("SELECT id, name, key_masked, created_at, last_used FROM api_keys WHERE revoked=FALSE ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def create_api_key(name):
    raw_key = secrets.token_urlsafe(32)
    masked = raw_key[:8] + '•' * 24
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    conn = get_db()
    conn.execute("INSERT INTO api_keys (name, key_hash, key_masked) VALUES (?,?,?)",
                 (name, key_hash, masked))
    conn.commit()
    return {'key': raw_key, 'key_masked': masked}


def revoke_api_key(key_id):
    conn = get_db()
    conn.execute("UPDATE api_keys SET revoked=TRUE WHERE id=?", (key_id,))
    conn.commit()


def verify_api_key(key):
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    conn = get_db()
    row = conn.execute("SELECT id FROM api_keys WHERE key_hash=? AND revoked=FALSE", (key_hash,)).fetchone()
    if row:
        conn.execute("UPDATE api_keys SET last_used=? WHERE id=?", (timezone_now_str(), row['id']))
        conn.commit()
        return True
    return False


def save_health_snapshot():
    conn = get_db()
    today = timezone_now().strftime('%Y-%m-%d')
    full = conn.execute("SELECT * FROM domains WHERE type='full'").fetchall()
    ssl = conn.execute("SELECT * FROM domains WHERE type='ssl_only'").fetchall()

    ssl_healthy = sum(1 for d in ssl if (d['ssl_status'] or 'pending') == 'healthy')
    ssl_total = len(ssl)
    domain_healthy = sum(1 for d in full if (d['domain_status'] or 'pending') == 'healthy')
    domain_total = len(full)

    conn.execute("""INSERT INTO health_snapshots
        (snapshot_date, ssl_healthy, ssl_total, domain_healthy, domain_total)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (snapshot_date)
        DO UPDATE SET ssl_healthy=EXCLUDED.ssl_healthy,
            ssl_total=EXCLUDED.ssl_total,
            domain_healthy=EXCLUDED.domain_healthy,
            domain_total=EXCLUDED.domain_total""",
        (today, ssl_healthy, ssl_total, domain_healthy, domain_total))
    conn.commit()


def get_health_snapshots(days=7):
    conn = get_db()
    rows = conn.execute("""SELECT * FROM health_snapshots
        ORDER BY snapshot_date DESC LIMIT ?""", (days,)).fetchall()
    return [dict(r) for r in rows]


def start_check_run(run_type='manual', total=0):
    conn = get_db()
    now = timezone_now_str()
    now_dt = timezone_now()
    stale_cutoff = (now_dt - datetime.timedelta(seconds=STALE_RUN_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE check_runs SET status='failed' WHERE status='running' AND started_at < ?",
                 (stale_cutoff,))
    running = conn.execute("SELECT id FROM check_runs WHERE status='running' LIMIT 1").fetchone()
    if running:
        conn.commit()
        return None
    cur = conn.execute("INSERT INTO check_runs (run_type, status, domains_total, started_at) VALUES (?, 'running', ?, ?) RETURNING id",
                       (run_type, total, now))
    row_id = cur.fetchone()['id']
    conn.commit()
    return row_id


def update_check_run(run_id, checked, status='running'):
    conn = get_db()
    if status == 'completed':
        conn.execute("UPDATE check_runs SET domains_checked=?, status=?, completed_at=? WHERE id=?",
                     (checked, status, timezone_now_str(), run_id))
    else:
        conn.execute("UPDATE check_runs SET domains_checked=?, status=? WHERE id=?",
                     (checked, status, run_id))
    conn.commit()


def get_last_check_run():
    conn = get_db()
    row = conn.execute("SELECT * FROM check_runs ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    r = dict(row)
    r['started_at'] = normalise_dt_str(r.get('started_at'))
    r['completed_at'] = normalise_dt_str(r.get('completed_at'))
    if r.get('started_at') and r.get('completed_at'):
        sa = parse_dt(r['started_at'])
        ca = parse_dt(r['completed_at'])
        if sa and ca:
            r['duration_seconds'] = int((ca - sa).total_seconds())
        else:
            r['duration_seconds'] = None
    else:
        r['duration_seconds'] = None
    return r


def get_dashboard_summary():
    conn = get_db()
    full = conn.execute("SELECT id, url, type, domain_status, ssl_status, ssl_days_left, domain_days_left FROM domains WHERE type='full'").fetchall()
    ssl = conn.execute("SELECT id, url, type, ssl_status, ssl_days_left FROM domains WHERE type='ssl_only'").fetchall()

    f_stats = {'healthy': 0, 'caution': 0, 'warning': 0, 'critical': 0, 'expired': 0, 'error': 0, 'pending': 0}
    s_stats = {'healthy': 0, 'watch': 0, 'caution': 0, 'warning': 0, 'critical': 0, 'expired': 0, 'error': 0, 'pending': 0}
    reachable = 0
    ssl_expiring = []
    domain_expiring = []
    ssl_buckets = {'expired': 0, 'critical': 0, 'warning': 0, 'caution': 0, 'healthy': 0}
    domain_buckets = {'expired': 0, 'critical': 0, 'warning': 0, 'caution': 0, 'healthy': 0}

    def bucket_ssl(days):
        if days is None: return
        if days < 0: ssl_buckets['expired'] += 1
        elif days <= 5: ssl_buckets['critical'] += 1
        elif days <= 15: ssl_buckets['warning'] += 1
        elif days <= 30: ssl_buckets['caution'] += 1
        else: ssl_buckets['healthy'] += 1

    def bucket_domain(days):
        if days is None: return
        if days < 0: domain_buckets['expired'] += 1
        elif days <= 30: domain_buckets['critical'] += 1
        elif days <= 60: domain_buckets['warning'] += 1
        elif days <= 90: domain_buckets['caution'] += 1
        else: domain_buckets['healthy'] += 1

    for d in full:
        ds = d['domain_status'] or 'pending'
        if ds in f_stats: f_stats[ds] += 1
        if d['ssl_status'] == 'healthy': reachable += 1
        bucket_ssl(d['ssl_days_left'])
        bucket_domain(d['domain_days_left'])
        if d['ssl_days_left'] is not None and 1 <= d['ssl_days_left'] <= 30:
            ssl_expiring.append({'id': d['id'], 'url': d['url'], 'days': d['ssl_days_left'], 'status': d['ssl_status']})
        if d['domain_days_left'] is not None and 1 <= d['domain_days_left'] <= 90:
            domain_expiring.append({'id': d['id'], 'url': d['url'], 'days': d['domain_days_left'], 'status': d['domain_status']})

    for d in ssl:
        ss = d['ssl_status'] or 'pending'
        if ss in s_stats: s_stats[ss] += 1
        if d['ssl_status'] == 'healthy': reachable += 1
        bucket_ssl(d['ssl_days_left'])
        if d['ssl_days_left'] is not None and 1 <= d['ssl_days_left'] <= 30:
            ssl_expiring.append({'id': d['id'], 'url': d['url'], 'days': d['ssl_days_left'], 'status': d['ssl_status']})

    ssl_expiring.sort(key=lambda x: x['days'])
    domain_expiring.sort(key=lambda x: x['days'])

    last_check = get_last_check_run()
    snapshots = get_health_snapshots(7)

    cutoff_24h = (timezone_now() - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    hour_expr = "to_char(date_trunc('hour', checked_at), 'YYYY-MM-DD HH24:00:00')"
    wa_trend_raw = conn.execute(f"""
        SELECT {hour_expr} AS hour,
               COUNT(*) AS total,
               SUM(CASE WHEN status IN ('up','slow') THEN 1 ELSE 0 END) AS up_count
        FROM webapp_results
        WHERE checked_at >= ?
        GROUP BY {hour_expr}
        ORDER BY hour ASC
    """, (cutoff_24h,)).fetchall()
    webapp_trend = []
    for r in wa_trend_raw:
        pct = round((r['up_count'] / r['total']) * 100, 1) if r['total'] else 0
        webapp_trend.append(pct)

    wa_overall = conn.execute("""
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN status IN ('up','slow') THEN 1 ELSE 0 END) AS up_count,
               AVG(response_time_ms) AS avg_rt
        FROM webapp_results
        WHERE checked_at >= ?
    """, (cutoff_24h,)).fetchone()
    webapp_uptime_24h = round((wa_overall['up_count'] / wa_overall['total']) * 100, 1) if wa_overall and wa_overall['total'] else None
    webapp_avg_rt = round(wa_overall['avg_rt'], 1) if wa_overall and wa_overall['avg_rt'] else None

    return {
        'full_count': len(full),
        'ssl_count': len(ssl),
        'full_stats': f_stats,
        'ssl_stats': s_stats,
        'reachable': reachable,
        'total': len(full) + len(ssl),
        'ssl_expiring': ssl_expiring[:5],
        'domain_expiring': domain_expiring[:5],
        'expiry_buckets': {'ssl': ssl_buckets, 'domain': domain_buckets},
        'last_check': last_check,
        'history': [dict(r) for r in snapshots],
        'webapp_stats': get_webapp_stats(),
        'webapp_trend': webapp_trend,
        'webapp_uptime_24h': webapp_uptime_24h,
        'webapp_avg_response_time': webapp_avg_rt,
        'port_stats': get_port_check_stats(),
    }


def count_admins():
    conn = get_db()
    return conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='admin'").fetchone()['cnt']


def count_users():
    conn = get_db()
    return conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()['cnt']


def count_domains():
    conn = get_db()
    return conn.execute("SELECT COUNT(*) AS cnt FROM domains").fetchone()['cnt']


def count_domains_full():
    conn = get_db()
    return conn.execute("SELECT COUNT(*) AS cnt FROM domains WHERE type='full'").fetchone()['cnt']


def count_domains_ssl():
    conn = get_db()
    return conn.execute("SELECT COUNT(*) AS cnt FROM domains WHERE type='ssl_only'").fetchone()['cnt']


def get_domain_status_counts():
    """Return a dict of domain status → count for Prometheus metrics."""
    conn = get_db()
    rows = conn.execute(
        "SELECT COALESCE(status, 'pending') AS st, COUNT(*) AS cnt FROM domains GROUP BY st"
    ).fetchall()
    return {r['st']: r['cnt'] for r in rows}


def get_domain_check_history(domain_id, days=7):
    """Return recent ssl_days_left values for a domain (for sparkline)."""
    conn = get_db()
    cutoff = (timezone_now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    rows = conn.execute(
        "SELECT checked_at, ssl_days_left FROM check_results "
        "WHERE domain_id=? AND checked_at>=? ORDER BY checked_at ASC",
        (domain_id, cutoff)
    ).fetchall()
    return [{'date': normalise_dt_str(r['checked_at']), 'ssl_days_left': r['ssl_days_left']} for r in rows]


def get_domain_pem(domain_id):
    """Return the most recent PEM for a domain from check_results (avoids bloating the domains table)."""
    conn = get_db()
    row = conn.execute(
        "SELECT result_json FROM check_results WHERE domain_id=? AND result_json::text LIKE ? "
        "ORDER BY checked_at DESC LIMIT 1",
        (domain_id, '%ssl_pem%')
    ).fetchone()
    if row and row['result_json']:
        data = row['result_json']
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                return None
        if isinstance(data, dict):
            return data.get('ssl_pem')
    return None


# ─── Webapps ────────────────────────────────────────────────────

_ALLOWED_WEBAPP_SORT_COLS = frozenset({
    'name', 'url', 'status', 'response_time_ms', 'last_checked', 'total_checks',
    'uptime_pct',
})
_ALLOWED_SORT_DIRS = frozenset({'asc', 'desc'})


def get_webapps(search='', status='', sort_by='name', sort_dir='asc', page=1, page_size=0):
    conn = get_db()
    conditions = []
    params = []
    if search:
        conditions.append("(name LIKE ? OR url LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%'])
    if status and status != 'all':
        conditions.append("status=?")
        params.append(status)
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    if sort_by not in _ALLOWED_WEBAPP_SORT_COLS:
        sort_by = 'name'
    if sort_dir not in _ALLOWED_SORT_DIRS:
        sort_dir = 'asc'
    if sort_by == 'uptime_pct':
        order_clause = "ORDER BY (CAST(successful_checks AS REAL) / MAX(total_checks, 1)) " + sort_dir
    else:
        order_clause = f"ORDER BY {sort_by} {sort_dir}"
    query = f"SELECT * FROM webapps {where} {order_clause}, name ASC"
    if page_size > 0:
        offset = (page - 1) * page_size
        query += f" LIMIT ? OFFSET ?"
        params.extend([page_size, offset])
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def count_webapps_filtered(search='', status=''):
    conn = get_db()
    conditions = []
    params = []
    if search:
        conditions.append("(name LIKE ? OR url LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%'])
    if status and status != 'all':
        conditions.append("status=?")
        params.append(status)
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    row = conn.execute(f"SELECT COUNT(*) AS cnt FROM webapps {where}", params).fetchone()
    return row['cnt'] if row else 0


def get_webapp_by_url(url):
    conn = get_db()
    row = conn.execute("SELECT * FROM webapps WHERE url=?", (url,)).fetchone()
    return dict(row) if row else None


def get_webapp(webapp_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM webapps WHERE id=?", (webapp_id,)).fetchone()
    return dict(row) if row else None


def add_webapp(name, url, method='GET', expected_status=200, expected_body=None,
               expected_body_negate=False, timeout=10, headers=None, body=None, check_interval=300,
               notify_on_down=True, notify_on_recovery=True, notes='', tags=''):
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO webapps (name, url, method, expected_status, expected_body, expected_body_negate, "
            "timeout, headers, body, check_interval, notify_on_down, notify_on_recovery, notes, tags) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (name, url, method, expected_status, expected_body, bool(expected_body_negate),
             timeout, headers, body, check_interval,
             bool(notify_on_down), bool(notify_on_recovery), notes, tags)
        )
        new_id = cur.fetchone()['id']
        conn.commit()
        return {"ok": True, "id": new_id}
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to add webapp %s", url)
        return {"ok": False, "error": str(e)}


def update_webapp(webapp_id, **kwargs):
    allowed = frozenset({'name', 'url', 'method', 'expected_status', 'expected_body', 'expected_body_negate',
                         'timeout', 'headers', 'body', 'check_interval', 'notes', 'tags',
                         'notify_on_down', 'notify_on_recovery', 'is_active'})
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k not in allowed:
            continue
        if k in ('notify_on_down', 'notify_on_recovery', 'is_active'):
            v = bool(v)
        sets.append(f"{k}=?")
        vals.append(v)
    if not sets:
        return False
    conn = get_db()
    vals.append(timezone_now_str())
    vals.append(webapp_id)
    conn.execute(f"UPDATE webapps SET {', '.join(sets)}, updated_at={db.placeholder()} WHERE id=?",
                 vals)
    conn.commit()
    return True


def delete_webapp(webapp_id):
    conn = get_db()
    conn.execute("DELETE FROM webapps WHERE id=?", (webapp_id,))
    conn.commit()


def update_webapp_last_alerted(webapp_id):
    conn = get_db()
    conn.execute("UPDATE webapps SET last_alerted=? WHERE id=?", (timezone_now_str(), webapp_id))
    conn.commit()


def save_webapp_check(webapp_id, result):
    conn = get_db()
    now = timezone_now_str()
    row = conn.execute("SELECT status FROM webapps WHERE id=?", (webapp_id,)).fetchone()
    old_status = row['status'] if row else None
    new_status = result['status']
    status_changed = old_status is not None and old_status != new_status
    conn.execute(
        "UPDATE webapps SET status=?, response_time_ms=?, last_status_code=?, "
        "last_checked=?, last_error=?, uptime_count=?, downtime_count=?, "
        "total_checks=?, successful_checks=?, "
        "status_changed_at=CASE WHEN ? THEN ? ELSE status_changed_at END, "
        "updated_at=? WHERE id=?",
        (
            new_status, result.get('response_time_ms'),
            result.get('status_code'), now,
            result.get('error'), result.get('uptime_count', 0),
            result.get('downtime_count', 0), result.get('total_checks', 0),
            result.get('successful_checks', 0),
            status_changed, now if status_changed else None,
            now, webapp_id
        )
    )
    conn.commit()


def save_webapp_check_result(webapp_id, result):
    conn = get_db()
    conn.execute(
        "INSERT INTO webapp_results (webapp_id, status, status_code, response_time_ms, error, checked_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (webapp_id, result['status'], result.get('status_code'),
         result.get('response_time_ms'), result.get('error'), timezone_now_str())
    )
    conn.commit()


def get_webapp_check_history(webapp_id, hours=168):
    conn = get_db()
    cutoff = (timezone_now() - datetime.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    rows = conn.execute(
        "SELECT checked_at, response_time_ms, status, status_code, error FROM webapp_results "
        "WHERE webapp_id=? AND checked_at>=? ORDER BY checked_at ASC",
        (webapp_id, cutoff)
    ).fetchall()
    return [dict(r) for r in rows]


def get_webapp_detail_stats(webapp_id):
    conn = get_db()
    now = timezone_now()
    periods = {
        '24h': now - datetime.timedelta(hours=24),
        '7d': now - datetime.timedelta(days=7),
        '30d': now - datetime.timedelta(days=30),
        '365d': now - datetime.timedelta(days=365),
    }
    uptime_data = {}
    for label, cutoff in periods.items():
        rows = conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status IN ('up','slow') THEN 1 ELSE 0 END) AS up_count "
            "FROM webapp_results WHERE webapp_id=? AND checked_at>=?",
            (webapp_id, cutoff.strftime("%Y-%m-%d %H:%M:%S"))
        ).fetchone()
        total = rows['total'] or 0
        up = rows['up_count'] or 0
        pct = round((up / total) * 100, 2) if total else None
        incidents = rows2 = conn.execute(
            "SELECT COUNT(*) AS cnt FROM webapp_results WHERE webapp_id=? "
            "AND checked_at>=? AND status='down'",
            (webapp_id, cutoff.strftime("%Y-%m-%d %H:%M:%S"))
        ).fetchone()
        downtime_m = 0
        if incident_count := (rows2['cnt'] or 0):
            interval = 5
            downtime_m = incident_count * interval
        uptime_data[label] = {
            'uptime_pct': pct,
            'incidents': incident_count,
            'downtime_minutes': downtime_m,
        }

    wa = get_webapp(webapp_id)
    current_duration = None
    if wa:
        sca = parse_dt(wa.get('status_changed_at'))
        if sca:
            current_duration = int((now - sca).total_seconds())
        else:
            lc = parse_dt(wa.get('last_checked'))
            if lc:
                current_duration = int((now - lc).total_seconds())
            else:
                ca = parse_dt(wa.get('created_at'))
                if ca:
                    current_duration = int((now - ca).total_seconds())

    history = conn.execute(
        "SELECT checked_at, status FROM webapp_results WHERE webapp_id=? "
        "ORDER BY checked_at ASC", (webapp_id,)
    ).fetchall()
    incidents_list = []
    prev = None
    for r in history:
        st = r['status']
        if prev is not None and prev != st:
            incidents_list.append({
                'from': prev,
                'to': st,
                'at': normalise_dt_str(r['checked_at']),
            })
        prev = st

    rt_stats = conn.execute(
        "SELECT AVG(response_time_ms) AS avg_r, MIN(response_time_ms) AS min_r, "
        "MAX(response_time_ms) AS max_r FROM webapp_results WHERE webapp_id=? "
        "AND response_time_ms IS NOT NULL",
        (webapp_id,)
    ).fetchone()

    recent = conn.execute(
        "SELECT status FROM webapp_results WHERE webapp_id=? "
        "ORDER BY checked_at DESC LIMIT 25", (webapp_id,)
    ).fetchall()
    recent_total = len(recent)
    recent_up = sum(1 for r in recent if r['status'] in ('up', 'slow'))

    return {
        'current_duration_seconds': current_duration,
        'uptime': uptime_data,
        'incidents': incidents_list[-20:],
        'incident_count': len(incidents_list),
        'avg_response_time_ms': round(rt_stats['avg_r'], 1) if rt_stats and rt_stats['avg_r'] else None,
        'min_response_time_ms': round(rt_stats['min_r'], 1) if rt_stats and rt_stats['min_r'] else None,
        'max_response_time_ms': round(rt_stats['max_r'], 1) if rt_stats and rt_stats['max_r'] else None,
        'recent_checks_total': recent_total,
        'recent_checks_up': recent_up,
    }


def count_webapps():
    conn = get_db()
    return conn.execute("SELECT COUNT(*) AS cnt FROM webapps").fetchone()['cnt']


def get_webapp_stats():
    conn = get_db()
    rows = conn.execute(
        "SELECT COALESCE(status, 'unknown') AS st, COUNT(*) AS cnt FROM webapps GROUP BY st"
    ).fetchall()
    paused_check = "CAST(is_active AS INTEGER) = 0 OR is_active IS NULL"
    paused_row = conn.execute(f"""
        SELECT COUNT(*) AS cnt FROM webapps WHERE {paused_check}
    """).fetchone()
    stats = {'up': 0, 'down': 0, 'slow': 0, 'unknown': 0, 'paused': paused_row['cnt'] if paused_row else 0}
    total = 0
    for r in rows:
        if r['st'] in stats:
            stats[r['st']] = r['cnt']
            total += r['cnt']
    stats['total'] = total
    return stats


def get_webapp_recent_failures(limit=5):
    conn = get_db()
    order = "ORDER BY w.last_checked DESC NULLS LAST"
    active_check = "CAST(w.is_active AS INTEGER) = 1"
    rows = conn.execute(f"""
        SELECT w.id, w.name, w.url, w.status, w.last_checked,
            (SELECT status FROM webapp_results WHERE webapp_id = w.id ORDER BY checked_at DESC LIMIT 1) as last_status
        FROM webapps w
        WHERE {active_check} AND COALESCE(w.status, 'unknown') IN ('down', 'slow')
        {order} LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


# ─── Maintenance Windows ──────────────────────────────────────────

def get_maintenance_windows():
    conn = get_db()
    rows = conn.execute("SELECT * FROM maintenance_windows ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def get_maintenance_window(mw_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM maintenance_windows WHERE id=?", (mw_id,)).fetchone()
    return dict(row) if row else None


def add_maintenance_window(data):
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO maintenance_windows (name, description, day_of_week, start_time, end_time, "
            "timezone, target_type, target_ids, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (data['name'], data.get('description', ''), data.get('day_of_week', 7),
             data['start_time'], data['end_time'], data.get('timezone', 'UTC'),
             data.get('target_type', 'all'), json.dumps(data.get('target_ids', [])),
             bool(data.get('is_active', True)))
        )
        new_id = cur.fetchone()['id']
        conn.commit()
        return {"ok": True, "id": new_id}
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to add maintenance window")
        return {"ok": False, "error": str(e)}


def update_maintenance_window(mw_id, data):
    allowed = frozenset({'name', 'description', 'day_of_week', 'start_time', 'end_time',
                         'timezone', 'target_type', 'target_ids', 'is_active'})
    sets = []
    vals = []
    for k, v in data.items():
        if k not in allowed:
            continue
        if k == 'is_active':
            v = bool(v)
        if k == 'target_ids' and isinstance(v, list):
            v = json.dumps(v)
        sets.append(f"{k}=?")
        vals.append(v)
    if not sets:
        return False
    conn = get_db()
    vals.append(mw_id)
    conn.execute(f"UPDATE maintenance_windows SET {', '.join(sets)} WHERE id=?", vals)
    conn.commit()
    return True


def delete_maintenance_window(mw_id):
    conn = get_db()
    conn.execute("DELETE FROM maintenance_windows WHERE id=?", (mw_id,))
    conn.commit()


def is_in_maintenance_window(monitored_type, monitored_id=None):
    """Check if a monitored item is currently covered by an active maintenance window.
    monitored_type: 'webapp', 'domain', 'ssl', or 'all'
    Returns True if any active window covers the current time on today's day of week.
    """
    conn = get_db()
    now = timezone_now()
    weekday = now.weekday()
    current_time = now.strftime("%H:%M")
    rows = conn.execute(
        "SELECT * FROM maintenance_windows WHERE is_active=TRUE "
        "AND (day_of_week=? OR day_of_week=7) "
        "AND ((start_time <= end_time AND start_time <= ? AND end_time >= ?) "
        "OR (start_time > end_time AND (start_time <= ? OR end_time >= ?)))",
        ((weekday + 1) % 7, current_time, current_time, current_time, current_time)
    ).fetchall()
    for row in rows:
        if row['target_type'] == 'all':
            return True
        if row['target_type'] == monitored_type:
            target_ids = json.loads(row['target_ids']) if row['target_ids'] else []
            if not target_ids or (monitored_id is not None and monitored_id in target_ids):
                return True
    return False


# ─── DNS Checks ────────────────────────────────────────────────────

_ALLOWED_DNS_CHECK_COLS = frozenset({
    'name', 'hostname', 'record_type', 'expected_value', 'check_interval',
    'notify_on_down', 'notify_on_recovery', 'notes', 'tags', 'is_active',
})
_ALLOWED_PORT_CHECK_COLS = frozenset({
    'name', 'hostname', 'port', 'check_interval', 'timeout', 'use_ipv6',
    'notify_on_down', 'notify_on_recovery', 'notes', 'tags', 'is_active',
})


def get_dns_checks():
    conn = get_db()
    rows = conn.execute("SELECT * FROM dns_checks ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def get_dns_check(dns_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM dns_checks WHERE id=?", (dns_id,)).fetchone()
    return dict(row) if row else None


def add_dns_check(data):
    conn = get_db()
    tags = data.get('tags', '')
    if isinstance(tags, list):
        tags = json.dumps(tags)
    try:
        cur = conn.execute(
            "INSERT INTO dns_checks (name, hostname, record_type, expected_value, "
            "check_interval, notify_on_down, notify_on_recovery, notes, tags) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (data['name'].strip(), data['hostname'].strip(), data.get('record_type', 'A'),
             data.get('expected_value') or None, data.get('check_interval', 300),
             bool(data.get('notify_on_down', True)), bool(data.get('notify_on_recovery', True)),
             data.get('notes', ''), tags)
        )
        new_id = cur.fetchone()['id']
        conn.commit()
        return {"ok": True, "id": new_id}
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to add DNS check")
        return {"ok": False, "error": str(e)}


def update_dns_check(dns_id, **kwargs):
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k not in _ALLOWED_DNS_CHECK_COLS:
            continue
        if k in ('notify_on_down', 'notify_on_recovery', 'is_active'):
            v = bool(v)
        if k == 'tags' and isinstance(v, list):
            v = json.dumps(v)
        sets.append(f"{k}=?")
        vals.append(v)
    if not sets:
        return False
    conn = get_db()
    vals.append(dns_id)
    conn.execute(f"UPDATE dns_checks SET {', '.join(sets)}, updated_at=? WHERE id=?",
                 vals + [timezone_now_str(), dns_id])
    conn.commit()
    return True


def delete_dns_check(dns_id):
    conn = get_db()
    conn.execute("DELETE FROM dns_checks WHERE id=?", (dns_id,))
    conn.commit()


def save_dns_check(dns_id, result):
    conn = get_db()
    now = timezone_now_str()
    row = conn.execute("SELECT status FROM dns_checks WHERE id=?", (dns_id,)).fetchone()
    old_status = row['status'] if row else None
    new_status = result['status']
    status_changed = old_status is not None and old_status != new_status
    conn.execute(
        "UPDATE dns_checks SET status=?, last_result=?, last_checked=?, last_error=?, "
        "status_changed_at=CASE WHEN ? THEN ? ELSE status_changed_at END, updated_at=? WHERE id=?",
        (new_status, (result.get('values') or [None])[0] if result.get('values') else None,
         now, result.get('error'),
         status_changed, now if status_changed else None, now, dns_id)
    )
    conn.commit()


def update_dns_last_alerted(dns_id):
    conn = get_db()
    conn.execute("UPDATE dns_checks SET last_alerted=? WHERE id=?", (timezone_now_str(), dns_id))
    conn.commit()


def count_dns_checks():
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) AS cnt FROM dns_checks").fetchone()
    return row['cnt'] if row else 0


def get_dns_check_stats():
    conn = get_db()
    rows = conn.execute(
        "SELECT COALESCE(status, 'unknown') AS st, COUNT(*) AS cnt FROM dns_checks GROUP BY st"
    ).fetchall()
    stats = {'up': 0, 'down': 0, 'unknown': 0}
    total = 0
    for r in rows:
        if r['st'] in stats:
            stats[r['st']] = r['cnt']
            total += r['cnt']
    stats['total'] = total
    return stats


def get_port_checks():
    conn = get_db()
    rows = conn.execute("SELECT * FROM port_checks ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def get_port_check(check_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM port_checks WHERE id=?", (check_id,)).fetchone()
    return dict(row) if row else None


def add_port_check(data):
    conn = get_db()
    tags = data.get('tags', '')
    if isinstance(tags, list):
        tags = json.dumps(tags)
    try:
        cur = conn.execute(
            "INSERT INTO port_checks (name, hostname, port, check_interval, timeout, "
            "use_ipv6, notify_on_down, notify_on_recovery, notes, tags) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (data['name'].strip(), data['hostname'].strip(), int(data.get('port', 80)),
             data.get('check_interval', 300), data.get('timeout', 10),
             bool(data.get('use_ipv6', False)),
             bool(data.get('notify_on_down', True)), bool(data.get('notify_on_recovery', True)),
             data.get('notes', ''), tags)
        )
        new_id = cur.fetchone()['id']
        conn.commit()
        return {"ok": True, "id": new_id}
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to add port check")
        return {"ok": False, "error": str(e)}


def update_port_check(check_id, **kwargs):
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k not in _ALLOWED_PORT_CHECK_COLS:
            continue
        if k in ('notify_on_down', 'notify_on_recovery', 'is_active', 'use_ipv6'):
            v = bool(v)
        if k in ('port', 'check_interval', 'timeout'):
            v = int(v)
        if k == 'tags' and isinstance(v, list):
            v = json.dumps(v)
        sets.append(f"{k}=?")
        vals.append(v)
    if not sets:
        return False
    conn = get_db()
    vals.append(check_id)
    conn.execute(f"UPDATE port_checks SET {', '.join(sets)}, updated_at=? WHERE id=?",
                 vals + [timezone_now_str(), check_id])
    conn.commit()
    return True


def delete_port_check(check_id):
    conn = get_db()
    conn.execute("DELETE FROM port_checks WHERE id=?", (check_id,))
    conn.commit()


def save_port_check(check_id, result):
    conn = get_db()
    now = timezone_now_str()
    row = conn.execute("SELECT status FROM port_checks WHERE id=?", (check_id,)).fetchone()
    old_status = row['status'] if row else None
    new_status = result['status']
    status_changed = old_status is not None and old_status != new_status
    conn.execute(
        "UPDATE port_checks SET status=?, last_response_time_ms=?, last_checked=?, "
        "last_error=?, status_changed_at=CASE WHEN ? THEN ? ELSE status_changed_at END, "
        "updated_at=? WHERE id=?",
        (new_status, result.get('response_time_ms'), now, result.get('error'),
         status_changed, now if status_changed else None, now, check_id)
    )
    conn.commit()


def update_port_last_alerted(check_id):
    conn = get_db()
    conn.execute("UPDATE port_checks SET last_alerted=? WHERE id=?", (timezone_now_str(), check_id))
    conn.commit()


def count_port_checks():
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) AS cnt FROM port_checks").fetchone()
    return row['cnt'] if row else 0


def get_port_check_stats():
    conn = get_db()
    rows = conn.execute(
        "SELECT COALESCE(status, 'unknown') AS st, COUNT(*) AS cnt FROM port_checks GROUP BY st"
    ).fetchall()
    stats = {'up': 0, 'down': 0, 'unknown': 0}
    total = 0
    for r in rows:
        if r['st'] in stats:
            stats[r['st']] = r['cnt']
            total += r['cnt']
    stats['total'] = total
    return stats
