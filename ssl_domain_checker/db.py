import logging
import os
import threading

from flask import g

logger = logging.getLogger(__name__)

DB_TYPE = 'postgresql'

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
    schema = os.environ.get('POSTGRES_SCHEMA', 'vigil').strip()
    if not schema:
        schema = 'vigil'
    try:
        return _PostgreSQLConnection(schema)
    except Exception as e:
        logger.error("PostgreSQL connection failed: %s", e)
        raise


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


def flush_connections():
    """Close the current connection so the next get_db() call reconnects
    (e.g. picks up a different POSTGRES_SCHEMA, or re-reads post-restore data)."""
    close_db()


# ─── Introspection helpers ────────────────────────────────────

def table_columns(table):
    conn = get_db()
    cur = conn.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema AND table_name = %s",
        (table,)
    )
    return {r['column_name'] for r in cur.fetchall()}


def column_type(table, column):
    conn = get_db()
    cur = conn.execute(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_schema = current_schema AND table_name = %s AND column_name = %s",
        (table, column)
    )
    row = cur.fetchone()
    return row['data_type'] if row else None


def has_table(table):
    conn = get_db()
    cur = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = current_schema AND table_name = %s) AS exists",
        (table,)
    )
    return cur.fetchone()['exists']


# ─── Dialect helpers ──────────────────────────────────────────

def placeholder():
    return '%s'


def lastrowid(conn, table=None):
    cur = conn.execute("SELECT lastval() AS lastval")
    return cur.fetchone()['lastval']


def is_integrity_error(e):
    from psycopg2.errors import UniqueViolation
    return isinstance(e, UniqueViolation)


def get_backend_info():
    return {
        'type': DB_TYPE,
        'schema': os.environ.get('POSTGRES_SCHEMA', 'vigil').strip(),
        'host': os.environ.get('POSTGRES_HOST', 'localhost'),
    }
