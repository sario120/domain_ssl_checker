import logging
import os
import re
import threading

from flask import g

logger = logging.getLogger(__name__)

DB_TYPE = os.environ.get('DB_TYPE', 'sqlite')

# Thread-local connection for non-request contexts (background workers, migrations)
_tls = threading.local()

# ─── PostgreSQL connection pool ──────────────────────────────

_pg_pool = None
_pg_pool_lock = threading.Lock()
_PG_POOL_MIN = int(os.environ.get('PG_POOL_MIN', '2'))
_PG_POOL_MAX = int(os.environ.get('PG_POOL_MAX', '10'))


def _get_pg_pool():
    global _pg_pool
    if _pg_pool is None:
        with _pg_pool_lock:
            if _pg_pool is None:
                import psycopg2
                from psycopg2 import pool
                conn_str = _build_pg_conn_string()
                _pg_pool = pool.ThreadedConnectionPool(
                    _PG_POOL_MIN, _PG_POOL_MAX, conn_str
                )
                logger.info("PostgreSQL connection pool created (min=%s, max=%s)",
                            _PG_POOL_MIN, _PG_POOL_MAX)
    return _pg_pool


def _close_pg_pool():
    global _pg_pool
    with _pg_pool_lock:
        if _pg_pool is not None:
            _pg_pool.closeall()
            _pg_pool = None
            logger.debug("PostgreSQL connection pool closed")


# ─── PostgreSQL connection wrapper ────────────────────────────

class _PostgreSQLConnection:
    def __init__(self, schema):
        import psycopg2
        import psycopg2.extras
        pool = _get_pg_pool()
        self._raw = pool.getconn()
        self._pool = pool
        self._schema = schema
        self._cursor_factory = psycopg2.extras.RealDictCursor
        with self._raw.cursor() as cur:
            cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
            cur.execute(f'SET search_path TO "{schema}", public')
        self._raw.commit()
        self._raw.autocommit = True

    def execute(self, sql, params=None):
        sql = sql.replace('?', '%s')
        if params is not None and not isinstance(params, dict):
            params = tuple(params)
        cur = self._raw.cursor(cursor_factory=self._cursor_factory)
        cur.execute(sql, params)
        return cur

    def executemany(self, sql, params_list):
        sql = sql.replace('?', '%s')
        cur = self._raw.cursor(cursor_factory=self._cursor_factory)
        cur.executemany(sql, params_list)
        return cur

    def executescript(self, sql):
        for stmt in (s.strip() for s in sql.split(';') if s.strip()):
            self.execute(stmt)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        pool = self._pool
        conn = self._raw
        self._pool = None
        self._raw = None
        if conn is not None:
            try:
                if pool is not None:
                    pool.putconn(conn)
                else:
                    conn.close()
            except Exception:
                pass


# ─── Connection helpers ───────────────────────────────────────

def _build_pg_conn_string():
    host = os.environ.get('POSTGRES_HOST', 'localhost')
    port = os.environ.get('POSTGRES_PORT', '5432')
    dbname = os.environ.get('POSTGRES_DB', 'vigil')
    user = os.environ.get('POSTGRES_USER', 'vigil')
    password = os.environ.get('POSTGRES_PASSWORD', '')
    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


def connect():
    if DB_TYPE == 'postgresql':
        schema = os.environ.get('POSTGRES_SCHEMA', 'vigil').strip()
        if not schema:
            schema = 'vigil'
        try:
            return _PostgreSQLConnection(schema)
        except Exception as e:
            logger.error("PostgreSQL connection failed: %s", e)
            raise
    else:
        import sqlite3
        from models import DB_PATH
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, isolation_level='')
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn


def get_db():
    try:
        if 'db' not in g:
            g.db = connect()
        return g.db
    except RuntimeError:
        if not hasattr(_tls, 'db') or _tls.db is None:
            _tls.db = connect()
        return _tls.db


def close_db(e=None):
    try:
        db = g.pop('db', None)
        if db is not None:
            db.close()
    except Exception:
        pass
    if hasattr(_tls, 'db') and _tls.db is not None:
        try:
            _tls.db.close()
        except Exception:
            pass
        _tls.db = None


# ─── Introspection helpers ────────────────────────────────────

def table_columns(table):
    conn = get_db()
    if DB_TYPE == 'postgresql':
        cur = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema AND table_name = %s",
            (table,)
        )
        return {r['column_name'] for r in cur.fetchall()}
    else:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return {r[1] for r in rows}


def column_type(table, column):
    conn = get_db()
    if DB_TYPE == 'postgresql':
        cur = conn.execute(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_schema = current_schema AND table_name = %s AND column_name = %s",
            (table, column)
        )
        row = cur.fetchone()
        return row['data_type'] if row else None
    else:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        for r in rows:
            if r[1] == column:
                return r[2]
        return None


def has_table(table):
    conn = get_db()
    if DB_TYPE == 'postgresql':
        cur = conn.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema AND table_name = %s) AS exists",
            (table,)
        )
        return cur.fetchone()['exists']
    else:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table,)
        ).fetchall()
        return len(rows) > 0


# ─── Dialect helpers ──────────────────────────────────────────

def placeholder():
    return '%s' if DB_TYPE == 'postgresql' else '?'


def lastrowid(conn, table=None):
    if DB_TYPE == 'postgresql':
        cur = conn.execute("SELECT lastval() AS lastval")
        return cur.fetchone()['lastval']
    else:
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def is_integrity_error(e):
    if DB_TYPE == 'postgresql':
        from psycopg2.errors import UniqueViolation
        return isinstance(e, UniqueViolation)
    else:
        import sqlite3
        return isinstance(e, sqlite3.IntegrityError)


def get_backend_info():
    info = {'type': DB_TYPE}
    if DB_TYPE == 'postgresql':
        info['schema'] = os.environ.get('POSTGRES_SCHEMA', 'vigil').strip()
        info['host'] = os.environ.get('POSTGRES_HOST', 'localhost')
    else:
        from models import DB_PATH
        info['file'] = DB_PATH
    return info
