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
    ))


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


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL DEFAULT 'full',
    ssl_expiry TEXT, ssl_days_left INTEGER, ssl_status TEXT DEFAULT 'pending',
    ssl_issuer TEXT, ssl_subject TEXT, ssl_sans TEXT,
    ssl_valid_from TEXT, ssl_valid_until TEXT,
    domain_expiry TEXT, domain_days_left INTEGER,
    domain_status TEXT DEFAULT 'pending', domain_registrar TEXT,
    status TEXT DEFAULT 'pending', last_checked TEXT,
    notes TEXT, ssl_alert_threshold INTEGER, domain_alert_threshold INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_alerted TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    smtp_server TEXT DEFAULT 'smtp.gmail.com', smtp_port INTEGER DEFAULT 587,
    smtp_email TEXT DEFAULT '', smtp_password TEXT DEFAULT '',
    smtp_enabled INTEGER DEFAULT 0,
    ssl_alert_threshold INTEGER DEFAULT 30, domain_alert_threshold INTEGER DEFAULT 30,
    alert_emails TEXT DEFAULT '',
    slack_webhook_url TEXT DEFAULT '', slack_enabled INTEGER DEFAULT 0,
    zulip_webhook_url TEXT DEFAULT '', zulip_enabled INTEGER DEFAULT 0,
    last_summary_sent TEXT
);
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL DEFAULT 'info', message TEXT NOT NULL,
    domain_id INTEGER, username TEXT, client_ip TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    login_fails INTEGER DEFAULT 0, last_fail TEXT, last_login TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS security_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_timeout INTEGER DEFAULT 60, max_login_attempts INTEGER DEFAULT 5,
    lockout_duration INTEGER DEFAULT 15, min_password_length INTEGER DEFAULT 8,
    require_uppercase INTEGER DEFAULT 1, require_lowercase INTEGER DEFAULT 1,
    require_number INTEGER DEFAULT 1, require_special INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE, key_masked TEXT NOT NULL,
    revoked INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_used TEXT
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_date TEXT NOT NULL UNIQUE,
    ssl_healthy INTEGER DEFAULT 0, ssl_total INTEGER DEFAULT 0,
    domain_healthy INTEGER DEFAULT 0, domain_total INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_health_date ON health_snapshots(snapshot_date);
CREATE TABLE IF NOT EXISTS check_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_type TEXT NOT NULL DEFAULT 'manual', status TEXT NOT NULL DEFAULT 'running',
    domains_checked INTEGER DEFAULT 0, domains_total INTEGER DEFAULT 0,
    started_at TEXT DEFAULT CURRENT_TIMESTAMP, completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_check_runs_started ON check_runs(started_at);
CREATE INDEX IF NOT EXISTS idx_check_runs_status ON check_runs(status);
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY, count INTEGER DEFAULT 0, window_start REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);
CREATE TABLE IF NOT EXISTS check_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    checked_at TEXT NOT NULL,
    status TEXT,
    result_json TEXT,
    ssl_days_left INTEGER,
    domain_days_left INTEGER
);
CREATE INDEX IF NOT EXISTS idx_check_results_domain ON check_results(domain_id, checked_at DESC);
CREATE TABLE IF NOT EXISTS webapps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    expected_status INTEGER DEFAULT 200,
    expected_body TEXT,
    timeout INTEGER DEFAULT 10,
    headers TEXT,
    body TEXT,
    check_interval INTEGER DEFAULT 300,
    status TEXT DEFAULT 'unknown',
    response_time_ms REAL,
    last_status_code INTEGER,
    last_checked TEXT,
    last_error TEXT,
    uptime_count INTEGER DEFAULT 0,
    downtime_count INTEGER DEFAULT 0,
    total_checks INTEGER DEFAULT 0,
    successful_checks INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    notify_on_down INTEGER DEFAULT 1,
    notify_on_recovery INTEGER DEFAULT 1,
    last_alerted TEXT,
    notes TEXT,
    status_changed_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_webapps_status ON webapps(status);
CREATE INDEX IF NOT EXISTS idx_webapps_active ON webapps(is_active);
CREATE TABLE IF NOT EXISTS webapp_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    webapp_id INTEGER NOT NULL REFERENCES webapps(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    status_code INTEGER,
    response_time_ms REAL,
    error TEXT,
    checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webapp_results_app ON webapp_results(webapp_id, checked_at DESC);
"""

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
    created_at TIMESTAMPTZ DEFAULT NOW(), last_alerted TIMESTAMPTZ
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
    username TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    login_fails INTEGER DEFAULT 0, last_fail TIMESTAMPTZ, last_login TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
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
""";

_MIGRATION_DOMAIN_COLS = frozenset({
    'ssl_alert_threshold', 'domain_alert_threshold', 'notes', 'manual_expiry_date',
    'check_interval', 'manual_registrar', 'last_alerted', 'tags', 'ssl_fingerprint',
})
_MIGRATION_SETTINGS_COLS = frozenset({
    'last_summary_sent', 'slack_webhook_url', 'slack_enabled',
    'zulip_webhook_url', 'zulip_enabled',
})


def _run_sqlite_migrations():
    conn = get_db()
    conn.executescript(_SQLITE_SCHEMA)
    conn.commit()

    for col, stmt in [
        ('login_fails', 'ALTER TABLE users ADD COLUMN login_fails INTEGER DEFAULT 0'),
        ('last_fail', 'ALTER TABLE users ADD COLUMN last_fail TEXT'),
        ('last_login', 'ALTER TABLE users ADD COLUMN last_login TEXT'),
        ('is_active', 'ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1'),
        ('manual_registrar', 'ALTER TABLE domains ADD COLUMN manual_registrar TEXT'),
        ('manual_expiry_date', 'ALTER TABLE domains ADD COLUMN manual_expiry_date TEXT'),
        ('tags', 'ALTER TABLE domains ADD COLUMN tags TEXT DEFAULT ""'),
        ('ssl_fingerprint', 'ALTER TABLE domains ADD COLUMN ssl_fingerprint TEXT'),
        ('check_interval', 'ALTER TABLE domains ADD COLUMN check_interval INTEGER DEFAULT 360'),
        ('slack_webhook_url', 'ALTER TABLE settings ADD COLUMN slack_webhook_url TEXT DEFAULT ""'),
        ('slack_enabled', 'ALTER TABLE settings ADD COLUMN slack_enabled INTEGER DEFAULT 0'),
        ('zulip_webhook_url', 'ALTER TABLE settings ADD COLUMN zulip_webhook_url TEXT DEFAULT ""'),
        ('zulip_enabled', 'ALTER TABLE settings ADD COLUMN zulip_enabled INTEGER DEFAULT 0'),
    ]:
        try:
            conn.execute(stmt)
            conn.commit()
        except Exception:
            logger.debug("Column %s already exists, skipping", col)

    dcols = {r[1] for r in conn.execute("PRAGMA table_info(domains)").fetchall()}
    for col, dtype in [("ssl_alert_threshold", "INTEGER"), ("domain_alert_threshold", "INTEGER"),
                        ("notes", "TEXT"), ("manual_expiry_date", "TEXT"),
                        ("check_interval", "INTEGER"), ("manual_registrar", "TEXT"),
                        ("last_alerted", "TEXT")]:
        if col not in dcols:
            if col not in _MIGRATION_DOMAIN_COLS:
                raise ValueError(f"Invalid migration column: {col}")
            conn.execute(f"ALTER TABLE domains ADD COLUMN {col} {dtype}")
    ucols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "role" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    if "is_active" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
    lcols = {r[1] for r in conn.execute("PRAGMA table_info(logs)").fetchall()}
    if "username" not in lcols:
        conn.execute("ALTER TABLE logs ADD COLUMN username TEXT")
    if "client_ip" not in lcols:
        conn.execute("ALTER TABLE logs ADD COLUMN client_ip TEXT")
    scols = {r[1] for r in conn.execute("PRAGMA table_info(settings)").fetchall()}
    for col in ("last_summary_sent",):
        if col not in scols:
            if col not in _MIGRATION_SETTINGS_COLS:
                raise ValueError(f"Invalid migration column: {col}")
            conn.execute(f"ALTER TABLE settings ADD COLUMN {col} TEXT")
    wcols = {r[1] for r in conn.execute("PRAGMA table_info(webapps)").fetchall()}
    if "last_alerted" not in wcols:
        conn.execute("ALTER TABLE webapps ADD COLUMN last_alerted TEXT")
    if "status_changed_at" not in wcols:
        conn.execute("ALTER TABLE webapps ADD COLUMN status_changed_at TEXT")
    conn.commit()


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
        ('check_interval', 'INTEGER', '360'),
        ('ssl_alert_threshold', 'INTEGER', None),
        ('domain_alert_threshold', 'INTEGER', None),
        ('notes', 'TEXT', None),
        ('last_alerted', 'TIMESTAMPTZ', None),
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
    if 'username' not in db.table_columns('logs'):
        conn.execute("ALTER TABLE logs ADD COLUMN username TEXT")
    if 'client_ip' not in db.table_columns('logs'):
        conn.execute("ALTER TABLE logs ADD COLUMN client_ip TEXT")
    if 'last_summary_sent' not in db.table_columns('settings'):
        conn.execute("ALTER TABLE settings ADD COLUMN last_summary_sent TIMESTAMPTZ")

    for col, dtype in [
        ('slack_webhook_url', 'TEXT'), ('slack_enabled', 'BOOLEAN'),
        ('zulip_webhook_url', 'TEXT'), ('zulip_enabled', 'BOOLEAN'),
    ]:
        if col not in db.table_columns('settings'):
            if col not in _MIGRATION_SETTINGS_COLS:
                raise ValueError(f"Invalid migration column: {col}")
            conn.execute(f"ALTER TABLE settings ADD COLUMN {col} {dtype} DEFAULT FALSE")

    if 'last_alerted' not in db.table_columns('webapps'):
        conn.execute("ALTER TABLE webapps ADD COLUMN last_alerted TIMESTAMPTZ")
    if 'status_changed_at' not in db.table_columns('webapps'):
        conn.execute("ALTER TABLE webapps ADD COLUMN status_changed_at TIMESTAMPTZ")

    conn.commit()


def init_db():
    logger.info("Database backend: %s", db.DB_TYPE)

    if db.DB_TYPE == 'postgresql':
        _run_postgres_migrations()
    else:
        _run_sqlite_migrations()

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


_ALLOWED_DOMAIN_COLS = frozenset({'url', 'type', 'notes', 'manual_expiry_date', 'manual_registrar'})
_ALLOWED_SETTINGS_COLS = frozenset({
    'smtp_server', 'smtp_port', 'smtp_email', 'smtp_password', 'smtp_enabled',
    'ssl_alert_threshold', 'domain_alert_threshold', 'alert_emails',
    'slack_webhook_url', 'slack_enabled', 'zulip_webhook_url', 'zulip_enabled',
    'email_templates', 'backup_schedule_hour', 'backup_schedule_minute', 'max_backups',
})
_ALLOWED_USER_COLS = frozenset({'password', 'role'})


def update_domain(domain_id, url=None, domain_type=None, notes=None, manual_expiry_date=None, manual_registrar=None):
    conn = get_db()
    fields = {}
    if url is not None: fields["url"] = url
    if domain_type is not None: fields["type"] = domain_type
    if notes is not None: fields["notes"] = notes
    if manual_expiry_date is not None: fields["manual_expiry_date"] = manual_expiry_date
    if manual_registrar is not None: fields["manual_registrar"] = manual_registrar
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
        domain_expiry=?, domain_days_left=?, domain_status=?, domain_registrar=?,
        status=?, last_checked=?
        WHERE id=?""", (
        r.get("ssl_expiry"), r.get("ssl_days_left"), r.get("ssl_status"),
        r.get("ssl_issuer"), r.get("ssl_subject"), r.get("ssl_sans"),
        r.get("ssl_valid_from"), r.get("ssl_valid_until"),
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
            domain_expiry, domain_days_left, domain_status,
            r.get("domain_registrar"), r.get("status"), now, domain_id
        ))
    try:
        conn.executemany("""UPDATE domains SET
            ssl_expiry=?, ssl_days_left=?, ssl_status=?, ssl_issuer=?, ssl_subject=?,
            ssl_sans=?, ssl_valid_from=?, ssl_valid_until=?,
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
                 'domain_expiry', 'domain_days_left', 'domain_status',
                 'domain_registrar', 'domain_error')
    }, default=str)
    if db.DB_TYPE == 'postgresql':
        result_json = result_json
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


def add_log(log_type, message, domain_id=None, username=None, client_ip=None):
    conn = get_db()
    conn.execute("INSERT INTO logs (type, message, domain_id, username, client_ip) VALUES (?, ?, ?, ?, ?)",
                 (log_type, message, domain_id, username, client_ip))
    conn.commit()


def _log_filters(log_type=None, query=None):
    clauses = []
    params = []
    if log_type and log_type != 'all':
        if log_type == 'error':
            clauses.append("(l.type=? OR l.type LIKE ?)")
            params.extend(['error', '%error%'])
        else:
            clauses.append("l.type=?")
            params.append(log_type)
    if query:
        escaped = query.replace('%', '\\%').replace('_', '\\_')
        like = f"%{escaped}%"
        clauses.append("(l.message LIKE ? ESCAPE '\\' OR l.username LIKE ? ESCAPE '\\' OR d.url LIKE ? ESCAPE '\\' OR l.type LIKE ? ESCAPE '\\')")
        params.extend([like, like, like, like])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    return where, params


def get_logs(limit=100, offset=0, log_type=None, query=None):
    conn = get_db()
    where, params = _log_filters(log_type, query)
    rows = conn.execute(f"""
        SELECT l.*, d.url as domain_url FROM logs l
        LEFT JOIN domains d ON l.domain_id = d.id
        {where}
        ORDER BY l.created_at DESC LIMIT ? OFFSET ?
    """, params + [limit, offset]).fetchall()
    return [dict(r) for r in rows]


def get_logs_count(log_type=None, query=None):
    conn = get_db()
    where, params = _log_filters(log_type, query)
    row = conn.execute(f"""
        SELECT COUNT(*) as cnt FROM logs l
        LEFT JOIN domains d ON l.domain_id = d.id
        {where}
    """, params).fetchone()
    return row['cnt']


def get_logs_summary(log_type=None, query=None):
    conn = get_db()
    where, params = _log_filters(log_type=log_type, query=query)
    rows = conn.execute(f"""
        SELECT l.type, COUNT(*) as cnt FROM logs l
        LEFT JOIN domains d ON l.domain_id = d.id
        {where}
        GROUP BY l.type
    """, params).fetchall()
    summary = {r['type'] or 'info': r['cnt'] for r in rows}
    summary['total'] = sum(summary.values())
    return summary


def get_users():
    conn = get_db()
    rows = conn.execute("SELECT id, username, role, login_fails, last_login, created_at, is_active FROM users ORDER BY username").fetchall()
    return [dict(r) for r in rows]


def get_user_by_username(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None


def add_user(username, password, role="user"):
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                     (username, generate_password_hash(password), role))
        conn.commit()
        return {"ok": True}
    except Exception as e:
        if db.is_integrity_error(e):
            conn.rollback()
            return {"ok": False, "error": "Username already exists"}
        conn.rollback()
        raise


def update_user(user_id, password=None, role=None, is_active=None):
    conn = get_db()
    filtered = []
    if password:
        filtered.append(("password=?", generate_password_hash(password)))
    if role and role in ('admin', 'user', 'viewer'):
        filtered.append(("role=?", role))
    if is_active is not None:
        filtered.append(("is_active=?", bool(is_active)))
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
    rows = conn.execute("SELECT id, name, key_masked, created_at, last_used FROM api_keys WHERE revoked=0 ORDER BY created_at DESC").fetchall()
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
    conn.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))
    conn.commit()


def verify_api_key(key):
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    conn = get_db()
    row = conn.execute("SELECT id FROM api_keys WHERE key_hash=? AND revoked=0", (key_hash,)).fetchone()
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

    if db.DB_TYPE == 'postgresql':
        conn.execute("""INSERT INTO health_snapshots
            (snapshot_date, ssl_healthy, ssl_total, domain_healthy, domain_total)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (snapshot_date)
            DO UPDATE SET ssl_healthy=EXCLUDED.ssl_healthy,
                ssl_total=EXCLUDED.ssl_total,
                domain_healthy=EXCLUDED.domain_healthy,
                domain_total=EXCLUDED.domain_total""",
            (today, ssl_healthy, ssl_total, domain_healthy, domain_total))
    else:
        conn.execute("""INSERT OR REPLACE INTO health_snapshots
            (snapshot_date, ssl_healthy, ssl_total, domain_healthy, domain_total)
            VALUES (?, ?, ?, ?, ?)""", (today, ssl_healthy, ssl_total, domain_healthy, domain_total))
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
    }


def count_users():
    conn = get_db()
    return conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()['cnt']


def count_domains():
    conn = get_db()
    return conn.execute("SELECT COUNT(*) AS cnt FROM domains").fetchone()['cnt']


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


# ─── Webapps ────────────────────────────────────────────────────

def get_webapps():
    conn = get_db()
    rows = conn.execute("SELECT * FROM webapps ORDER BY name ASC").fetchall()
    return [dict(r) for r in rows]


def get_webapp(webapp_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM webapps WHERE id=?", (webapp_id,)).fetchone()
    return dict(row) if row else None


def add_webapp(name, url, method='GET', expected_status=200, expected_body=None,
               timeout=10, headers=None, body=None, check_interval=300,
               notify_on_down=True, notify_on_recovery=True, notes=''):
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO webapps (name, url, method, expected_status, expected_body, "
            "timeout, headers, body, check_interval, notify_on_down, notify_on_recovery, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (name, url, method, expected_status, expected_body,
             timeout, headers, body, check_interval,
             bool(notify_on_down), bool(notify_on_recovery), notes)
        )
        new_id = cur.fetchone()['id']
        conn.commit()
        return {"ok": True, "id": new_id}
    except Exception as e:
        conn.rollback()
        logger.exception("Failed to add webapp %s", url)
        return {"ok": False, "error": str(e)}


def update_webapp(webapp_id, **kwargs):
    allowed = frozenset({'name', 'url', 'method', 'expected_status', 'expected_body',
                         'timeout', 'headers', 'body', 'check_interval', 'notes',
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
    vals.append(webapp_id)
    conn = get_db()
    conn.execute(f"UPDATE webapps SET {', '.join(sets)}, updated_at={db.placeholder()} WHERE id=?",
                 (*vals, timezone_now_str()))
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
    sca = parse_dt(wa.get('status_changed_at')) if wa else None
    if sca:
        current_duration = int((now - sca).total_seconds())
    elif wa:
        lc = parse_dt(wa.get('last_checked'))
        if lc:
            current_duration = int((now - lc).total_seconds())

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

    return {
        'current_duration_seconds': current_duration,
        'uptime': uptime_data,
        'incidents': incidents_list[-20:],
        'incident_count': len(incidents_list),
        'avg_response_time_ms': round(rt_stats['avg_r'], 1) if rt_stats and rt_stats['avg_r'] else None,
        'min_response_time_ms': round(rt_stats['min_r'], 1) if rt_stats and rt_stats['min_r'] else None,
        'max_response_time_ms': round(rt_stats['max_r'], 1) if rt_stats and rt_stats['max_r'] else None,
    }


def count_webapps():
    conn = get_db()
    return conn.execute("SELECT COUNT(*) AS cnt FROM webapps").fetchone()['cnt']


def get_webapp_stats():
    conn = get_db()
    rows = conn.execute(
        "SELECT COALESCE(status, 'unknown') AS st, COUNT(*) AS cnt FROM webapps GROUP BY st"
    ).fetchall()
    stats = {'up': 0, 'down': 0, 'slow': 0, 'unknown': 0}
    for r in rows:
        if r['st'] in stats:
            stats[r['st']] = r['cnt']
    stats['total'] = sum(stats.values())
    return stats
