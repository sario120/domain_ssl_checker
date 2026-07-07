"""Shared helper for running tests against an isolated PostgreSQL schema.

Each test module gets its own fixed schema name so test runs never touch
the application's real data schema (POSTGRES_SCHEMA from .env). The schema
is dropped and recreated before every test for full isolation.
"""
import atexit
import os

import psycopg2

_created_schemas = set()


def _pg_dsn():
    host = os.environ.get('POSTGRES_HOST', 'localhost')
    port = os.environ.get('POSTGRES_PORT', '5432')
    dbname = os.environ.get('POSTGRES_DB', 'vigil')
    user = os.environ.get('POSTGRES_USER', 'vigil')
    password = os.environ.get('POSTGRES_PASSWORD', '')
    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


def _drop_schema(schema_name):
    """Drop the schema, bounded by a lock timeout so a stray idle-in-transaction
    connection elsewhere can never wedge this (and the test process) forever."""
    conn = psycopg2.connect(_pg_dsn())
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SET lock_timeout = '5s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE')
    finally:
        conn.close()


def reset_test_schema(schema_name):
    """Point the app at schema_name and wipe it for a clean slate."""
    import db as db_mod
    os.environ["POSTGRES_SCHEMA"] = schema_name
    db_mod.flush_connections()
    _drop_schema(schema_name)
    _created_schemas.add(schema_name)


def _cleanup_all():
    for schema in _created_schemas:
        try:
            _drop_schema(schema)
        except Exception:
            pass


atexit.register(_cleanup_all)
