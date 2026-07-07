import gzip
import json
import logging
import os
import glob
import stat
import subprocess
from datetime import datetime, timezone

import db

logger = logging.getLogger(__name__)

_ALLOWED_BACKUP_TABLES = frozenset({
    'domains', 'users', 'settings', 'logs', 'check_results',
    'check_runs', 'check_result_history', 'rate_limits',
    'webapps', 'webapp_results', 'webapp_health_log',
    'health_snapshots', 'security_settings', 'api_keys', 'schema_version',
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
    'name', 'is_active', 'notify_on_down', 'notify_on_recovery',
    'response_time_threshold', 'uptime_check_interval', 'status_changed_at',
    'webapp_id', 'response_time_ms', 'status_code', 'error_message', 'checked_at',
    'date', 'uptime_percent', 'total_checks', 'up_checks', 'slow_checks', 'down_checks',
    'avg_response_time_ms', 'webapp_count',
    'snapshot_date', 'ssl_healthy', 'ssl_total', 'domain_healthy', 'domain_total',
    'session_timeout', 'max_login_attempts', 'lockout_duration',
    'min_password_length', 'require_uppercase', 'require_lowercase',
    'require_number', 'require_special',
    'key_hash', 'key_masked', 'revoked', 'last_used',
    'version',
})

BACKUP_DIR = os.environ.get(
    "BACKUP_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backups")
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
    rows = conn.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = current_schema AND table_type = 'BASE TABLE'"
    ).fetchall()
    return [r['table_name'] for r in rows if r['table_name'] not in ('rate_limits',)]


def _export_pg_dump(backup_path, notes=None):
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
            capture_output=True, text=True, env=env, timeout=120
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
    if notes:
        meta["notes"] = notes
    meta_path = backup_path_out + ".meta"
    with open(meta_path, 'w') as f:
        json.dump(meta, f)

    logger.info(f"PostgreSQL backup created: {backup_name} ({count} domains, pg_dump)")
    cleanup_old_backups()
    return backup_path_out


def _export_pg_json(backup_path, notes=None):
    import time as _time
    conn = None
    for attempt in range(5):
        try:
            conn = db.connect()
            break
        except Exception as e:
            if 'connection pool exhausted' in str(e).lower() or 'pool exhausted' in str(e).lower():
                if attempt < 4:
                    logger.warning("PG pool exhausted on attempt %d/5, retrying in 2s...", attempt + 1)
                    _time.sleep(2)
                    continue
                raise RuntimeError("PostgreSQL connection pool exhausted — too many concurrent operations. Try again later.")
            raise
    tables = _list_tables(conn)
    dump = {}
    for table in tables:
        if table not in _ALLOWED_BACKUP_TABLES:
            conn.close()
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
    if notes:
        meta["notes"] = notes
    meta_path = backup_path_out + ".meta"
    with open(meta_path, 'w') as f:
        json.dump(meta, f)

    logger.info(f"PostgreSQL backup created: {backup_name} (JSON fallback)")
    cleanup_old_backups()
    return backup_path_out


def get_db_info():
    backups = list_backups()
    info = {
        'type': db.DB_TYPE,
        'size': None,
        'domain_count': None,
        'webapp_count': None,
        'backup_count': len(backups),
        'max_backups': MAX_BACKUPS,
        'backup_dir': BACKUP_DIR,
        'schedule_hour': 3,
        'schedule_minute': 0,
        'next_backup_at': None,
        'last_backup_at': backups[0]['created'] if backups else None,
    }
    try:
        from scheduler import scheduler as _sched
        job = _sched.get_job('db_backup')
        if job and job.next_run_time:
            info['next_backup_at'] = job.next_run_time.isoformat()
    except Exception:
        pass
    try:
        conn = db.connect()
        row = conn.execute("SELECT backup_schedule_hour, backup_schedule_minute, max_backups FROM settings WHERE id=1").fetchone()
        if row:
            if row.get('backup_schedule_hour') is not None:
                info['schedule_hour'] = int(row['backup_schedule_hour'])
            if row.get('backup_schedule_minute') is not None:
                info['schedule_minute'] = int(row['backup_schedule_minute'])
            if row.get('max_backups') is not None:
                info['max_backups'] = int(row['max_backups'])
        info['host'] = os.environ.get('POSTGRES_HOST', 'localhost')
        info['db'] = os.environ.get('POSTGRES_DB', 'vigil')
        info['schema'] = os.environ.get('POSTGRES_SCHEMA', 'vigil').strip()
        row2 = conn.execute("SELECT COUNT(*) AS cnt FROM domains").fetchone()
        info['domain_count'] = row2['cnt'] if row2 else None
        row3 = conn.execute("SELECT COUNT(*) AS cnt FROM webapps").fetchone()
        info['webapp_count'] = row3['cnt'] if row3 else None
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
    return info


def create_backup(notes=None):
    ensure_backup_dir()

    try:
        return _export_pg_dump(BACKUP_DIR, notes=notes)
    except (RuntimeError, FileNotFoundError) as e:
        logger.warning("pg_dump export failed (%s), falling back to JSON export", e)
        try:
            return _export_pg_json(BACKUP_DIR, notes=notes)
        except RuntimeError as e2:
            logger.error("JSON fallback backup also failed: %s", e2)
            raise


def verify_backup(backup_path):
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
            entry["notes"] = meta.get("notes")
            entry["format"] = meta.get("format")
        result.append(entry)
    return result


def restore_backup(filename):
    resolved = os.path.realpath(os.path.join(BACKUP_DIR, filename))
    real_base = os.path.realpath(BACKUP_DIR)
    if not resolved.startswith(real_base):
        raise ValueError("Invalid backup filename")
    if not os.path.exists(resolved):
        raise FileNotFoundError(f"Backup file not found: {filename}")

    ext = os.path.splitext(_strip_gz(resolved))[1]
    reader = gzip.open if _is_gz(resolved) else open

    if ext == '.sql':
        host = os.environ.get('POSTGRES_HOST', 'localhost')
        port = os.environ.get('POSTGRES_PORT', '5432')
        pg_db = os.environ.get('POSTGRES_DB', 'vigil')
        user = os.environ.get('POSTGRES_USER', 'vigil')
        password = os.environ.get('POSTGRES_PASSWORD', '')
        env = os.environ.copy()
        env['PGPASSWORD'] = password
        with reader(resolved, 'rt', encoding='utf-8') as f:
            sql_data = f.read()
        result = subprocess.run(
            ['psql', '-h', host, '-p', port, '-U', user, '-d', pg_db, '-f', '-'],
            input=sql_data, capture_output=True, text=True, env=env, timeout=120
        )
        if result.returncode != 0:
            raise ValueError(f"psql restore failed: {result.stderr[:500]}")
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


def _safe_basename(name):
    return os.path.basename(name).replace('\0', '')


def upload_and_restore(file_storage):
    ensure_backup_dir()
    original_name = _safe_basename(file_storage.filename or 'uploaded_backup.db.gz')
    dest_path = os.path.join(BACKUP_DIR, f"_upload_{int(datetime.now(timezone.utc).timestamp())}_{original_name}")
    file_storage.save(dest_path)
    os.chmod(dest_path, stat.S_IRUSR | stat.S_IWUSR)
    try:
        restore_backup(os.path.basename(dest_path))
        # On success, move to proper backup name
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        final_name = f"ssl_checker_{ts}_{original_name}"
        final_path = os.path.join(BACKUP_DIR, final_name)
        os.rename(dest_path, final_path)
        meta_path = dest_path + ".meta"
        if os.path.exists(meta_path):
            os.rename(meta_path, final_path + ".meta")
        logger.info(f"Uploaded backup restored and saved: {final_name}")
        return final_name
    except Exception:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        raise


def schedule_backup(scheduler):
    hour = 3
    minute = 0
    try:
        conn = db.connect()
        row = conn.execute("SELECT backup_schedule_hour, backup_schedule_minute, max_backups FROM settings WHERE id=1").fetchone()
        if row:
            if row.get('backup_schedule_hour') is not None:
                hour = int(row['backup_schedule_hour'])
            if row.get('backup_schedule_minute') is not None:
                minute = int(row['backup_schedule_minute'])
            if row.get('max_backups') is not None:
                global MAX_BACKUPS
                MAX_BACKUPS = int(row['max_backups'])
        conn.close()
    except Exception:
        pass
    scheduler.add_job(
        create_backup,
        "cron",
        hour=hour,
        minute=minute,
        id="db_backup",
        name="Database backup",
        replace_existing=True,
    )
    logger.info("Daily DB backup scheduled for %02d:%02d UTC", hour, minute)
