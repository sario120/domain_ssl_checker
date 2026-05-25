import gzip
import io
import json
import logging
import os
import shutil
import glob
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone

import db

logger = logging.getLogger(__name__)

_ALLOWED_BACKUP_TABLES = frozenset({
    'domains', 'users', 'settings', 'logs', 'check_results',
    'check_runs', 'check_result_history', 'rate_limits',
})
_ALLOWED_BACKUP_COLUMNS = frozenset({
    'id', 'url', 'type', 'notes', 'manual_expiry_date', 'manual_registrar',
    'ssl_status', 'domain_status', 'ssl_expiry', 'domain_expiry',
    'ssl_days_left', 'domain_days_left', 'ssl_issuer', 'ssl_fingerprint',
    'tags', 'check_interval', 'last_checked', 'last_alerted', 'created_at',
    'username', 'password', 'role', 'is_active', 'login_fails', 'last_fail', 'last_login',
    'smtp_server', 'smtp_port', 'smtp_email', 'smtp_password', 'smtp_enabled',
    'ssl_alert_threshold', 'domain_alert_threshold', 'alert_emails',
    'slack_webhook_url', 'slack_enabled', 'zulip_webhook_url', 'zulip_enabled',
    'email_templates', 'last_summary_sent', 'check_type', 'status', 'message',
    'domain_id', 'client_ip', 'started_at', 'completed_at', 'error',
    'ssl_alert_sent', 'domain_alert_sent', 'key', 'count', 'window_start',
})

BACKUP_DIR = os.environ.get(
    "BACKUP_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backups")
)
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data_volume", "ssl_checker.db")
)
MAX_BACKUPS = int(os.environ.get("MAX_BACKUPS", "30"))


def ensure_backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def _is_gz(path):
    return path.endswith('.gz')


def _strip_gz(path):
    return path[:-3] if _is_gz(path) else path


def _count_domains_from_conn(conn):
    try:
        row = conn.execute("SELECT COUNT(*) FROM domains").fetchone()
        return row[0]
    except Exception:
        return None


def _list_tables(conn):
    if db.DB_TYPE == 'postgresql':
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = current_schema AND table_type = 'BASE TABLE'"
        ).fetchall()
        return [r['table_name'] for r in rows if r['table_name'] not in ('rate_limits',)]
    else:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return [r[0] for r in rows]


def _export_pg_dump(backup_path):
    host = os.environ.get('POSTGRES_HOST', 'localhost')
    port = os.environ.get('POSTGRES_PORT', '5432')
    dbname = os.environ.get('POSTGRES_DB', 'vigil')
    user = os.environ.get('POSTGRES_USER', 'vigil')
    password = os.environ.get('POSTGRES_PASSWORD', '')
    schema = os.environ.get('POSTGRES_SCHEMA', 'vigil').strip()

    env = os.environ.copy()
    env['PGPASSWORD'] = password

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_name = f"ssl_checker_{ts}.sql.gz"
    backup_path_out = os.path.join(BACKUP_DIR, backup_name)

    try:
        result = subprocess.run(
            ['pg_dump', '--no-owner', '--no-acl', f'--schema={schema}',
             '-h', host, '-p', port, '-U', user, '-d', dbname],
            capture_output=True, text=True, env=env, timeout=60
        )
        if result.returncode != 0:
            raise RuntimeError(f"pg_dump failed: {result.stderr}")

        with gzip.open(backup_path_out, 'wt', encoding='utf-8') as f:
            f.write(result.stdout)
    except FileNotFoundError:
        raise RuntimeError("pg_dump not found on system")
    except subprocess.TimeoutExpired:
        raise RuntimeError("pg_dump timed out")

    conn = db.connect()
    count = _count_domains_from_conn(conn)
    conn.close()

    meta = {
        "filename": backup_name,
        "created": datetime.now(timezone.utc).isoformat(),
        "size": os.path.getsize(backup_path_out),
        "domain_count": count,
        "format": "pg_dump",
    }
    meta_path = backup_path_out + ".meta"
    with open(meta_path, 'w') as f:
        json.dump(meta, f)

    logger.info(f"PostgreSQL backup created: {backup_name} ({count} domains, pg_dump)")
    cleanup_old_backups()
    return backup_path_out


def _export_pg_json(backup_path):
    conn = db.connect()
    tables = _list_tables(conn)
    dump = {}
    for table in tables:
        if table not in _ALLOWED_BACKUP_TABLES:
            raise ValueError(f"Unexpected table in backup export: {table}")
        rows = conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
        dump[table] = [dict(r) for r in rows]
    conn.close()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_name = f"ssl_checker_{ts}.json.gz"
    backup_path_out = os.path.join(BACKUP_DIR, backup_name)

    with gzip.open(backup_path_out, 'wt', encoding='utf-8') as f:
        json.dump(dump, f, default=str)

    count = (d.get('domain_count') for _, d in dump.items() if _ == 'domains')
    domain_count = next(count, None)

    meta = {
        "filename": backup_name,
        "created": datetime.now(timezone.utc).isoformat(),
        "size": os.path.getsize(backup_path_out),
        "domain_count": domain_count,
        "format": "json",
    }
    meta_path = backup_path_out + ".meta"
    with open(meta_path, 'w') as f:
        json.dump(meta, f)

    logger.info(f"PostgreSQL backup created: {backup_name} (JSON fallback)")
    cleanup_old_backups()
    return backup_path_out


def create_backup():
    ensure_backup_dir()

    if db.DB_TYPE == 'postgresql':
        try:
            return _export_pg_dump(BACKUP_DIR)
        except (RuntimeError, FileNotFoundError) as e:
            logger.warning("pg_dump export failed (%s), falling back to JSON export", e)
            return _export_pg_json(BACKUP_DIR)

    if not os.path.exists(DB_PATH):
        logger.warning("Database file not found, skipping backup")
        return None

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_name = f"ssl_checker_{ts}.db.gz"
    backup_path = os.path.join(BACKUP_DIR, backup_name)

    with open(DB_PATH, 'rb') as f_in:
        with gzip.open(backup_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    count = verify_backup(backup_path)

    meta_path = backup_path + ".meta"
    meta = {
        "filename": backup_name,
        "created": datetime.now(timezone.utc).isoformat(),
        "size": os.path.getsize(backup_path),
        "domain_count": count,
        "db_size": os.path.getsize(DB_PATH),
        "format": "sqlite",
    }
    with open(meta_path, 'w') as f:
        json.dump(meta, f)

    logger.info(f"Backup created: {backup_name} ({count} domains)")
    cleanup_old_backups()
    return backup_path


def verify_backup(backup_path):
    if db.DB_TYPE == 'postgresql':
        try:
            reader = gzip.open if _is_gz(backup_path) else open
            ext = os.path.splitext(_strip_gz(backup_path))[1]
            if ext == '.sql':
                with reader(backup_path, 'rt', encoding='utf-8') as f:
                    content = f.read(512)
                    if 'pg_dump' not in content and 'PostgreSQL' not in content:
                        logger.error(f"Backup {backup_path} is not a valid pg_dump SQL file")
                        return None
                return True
            elif ext == '.json':
                with reader(backup_path, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
                if not isinstance(data, dict) or 'domains' not in data:
                    logger.error(f"Backup {backup_path} has invalid JSON structure")
                    return None
                return len(data.get('domains', []))
            else:
                logger.error(f"Unknown PostgreSQL backup format: {backup_path}")
                return None
        except Exception as e:
            logger.error(f"Backup verification failed for {backup_path}: {e}")
            return None

    try:
        reader = gzip.open if _is_gz(backup_path) else open
        with reader(backup_path, 'rb') as f:
            header = f.read(16)
            if header != b'SQLite format 3\x00':
                logger.error(f"Backup {backup_path} has invalid SQLite header")
                return None

        with reader(backup_path, 'rb') as f_in:
            tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
            tmp_path = tmp.name
            shutil.copyfileobj(f_in, tmp)
            tmp.close()

        conn = sqlite3.connect(tmp_path)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            conn.close()
            logger.error(f"Backup {backup_path} failed integrity check: {integrity}")
            os.unlink(tmp_path)
            return None

        count = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        conn.close()
        os.unlink(tmp_path)
        return count
    except Exception as e:
        logger.error(f"Backup verification failed for {backup_path}: {e}")
        return None


def cleanup_old_backups():
    pattern = os.path.join(BACKUP_DIR, "ssl_checker_*")
    backups = sorted(glob.glob(pattern))
    gz_files = [p for p in backups if not p.endswith('.meta')]
    while len(gz_files) > MAX_BACKUPS:
        oldest = gz_files.pop(0)
        meta = oldest + ".meta"
        if os.path.exists(oldest):
            os.remove(oldest)
        if os.path.exists(meta):
            os.remove(meta)
        logger.info(f"Removed old backup: {os.path.basename(oldest)}")


def list_backups():
    ensure_backup_dir()
    pattern = os.path.join(BACKUP_DIR, "ssl_checker_*")
    all_files = glob.glob(pattern)
    backups = sorted(p for p in all_files if not p.endswith('.meta'))
    result = []
    for path in reversed(backups):
        stat = os.stat(path)
        meta = None
        meta_path = path + ".meta"
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as f:
                    meta = json.load(f)
            except Exception:
                pass
        entry = {
            "filename": os.path.basename(path),
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        }
        if meta:
            entry["domain_count"] = meta.get("domain_count")
            entry["db_size"] = meta.get("db_size")
        result.append(entry)
    return result


def restore_backup(filename):
    resolved = os.path.realpath(os.path.join(BACKUP_DIR, filename))
    real_base = os.path.realpath(BACKUP_DIR)
    if not resolved.startswith(real_base):
        raise ValueError("Invalid backup filename")
    if not os.path.exists(resolved):
        raise FileNotFoundError(f"Backup file not found: {filename}")

    if db.DB_TYPE == 'postgresql':
        ext = os.path.splitext(_strip_gz(resolved))[1]
        reader = gzip.open if _is_gz(resolved) else open

        if ext == '.sql':
            with reader(resolved, 'rt', encoding='utf-8') as f:
                sql = f.read()
            conn = db.connect()
            try:
                conn.executescript(sql)
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise ValueError(f"PostgreSQL restore failed: {e}")
            finally:
                conn.close()
        elif ext == '.json':
            with reader(resolved, 'rt', encoding='utf-8') as f:
                data = json.load(f)
            conn = db.connect()
            try:
                for table, rows in data.items():
                    if table not in _ALLOWED_BACKUP_TABLES:
                        raise ValueError(f"Unexpected table in backup: {table}")
                    for row in rows:
                        for col in row:
                            if col not in _ALLOWED_BACKUP_COLUMNS:
                                raise ValueError(f"Unexpected column in backup: {table}.{col}")
                        cols = ', '.join(row.keys())
                        vals = ', '.join(['?' for _ in row])
                        conn.execute(
                            f"INSERT INTO {table} ({cols}) VALUES ({vals}) "
                            f"ON CONFLICT DO NOTHING",
                            tuple(row.values())
                        )
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise ValueError(f"PostgreSQL JSON restore failed: {e}")
            finally:
                conn.close()
        else:
            raise ValueError(f"Unknown PostgreSQL backup format: {filename}")

        logger.info(f"Database restored from {filename}")
        return True

    conn = sqlite3.connect(resolved)
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    conn.close()
    if integrity != "ok":
        raise ValueError("Backup file is not a valid SQLite database")

    reader = gzip.open if _is_gz(resolved) else open
    with reader(resolved, 'rb') as f_in:
        with open(DB_PATH, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    logger.info(f"Database restored from {filename}")
    return True


def schedule_backup(scheduler):
    scheduler.add_job(
        create_backup,
        "cron",
        hour=3,
        minute=0,
        id="db_backup",
        name="Database backup",
        replace_existing=True,
    )
    logger.info("Daily DB backup scheduled for 03:00")
