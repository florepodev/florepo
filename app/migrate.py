"""Database schema versioning with Alembic.

* `upgrade_on_startup()` runs in the web container before gunicorn starts (docker/entrypoint.sh → init-db):
  it takes a database lock, brings the schema to the newest revision and returns.
* Installations created before migrations existed (tables made by `create_all`) are detected, patched to the
  baseline schema and stamped as revision 0001, then upgraded like every other installation.
* New migration after changing app/models.py:  flask --app wsgi db-revision -m "describe the change"
"""
import os
import time
from contextlib import contextmanager

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from flask import current_app
from sqlalchemy import inspect, text

from .extensions import db

BASELINE = "0001"
LOCK_ID = 7_265_783_201  # arbitrary constant for pg_advisory_lock

# Columns that pre-migration releases added ad hoc on startup. Needed to bring such databases to the baseline.
LEGACY_COLUMNS = [
    ("user", "restrict_deploy", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ("repository", "proxy_mode", "VARCHAR(16) NOT NULL DEFAULT 'global'"),
    ("repository", "proxy_url", "VARCHAR(512)"),
]


def config(connection=None):
    cfg = Config()
    cfg.set_main_option("script_location", os.path.join(os.path.dirname(__file__), "migrations"))
    cfg.attributes["connection"] = connection
    return cfg


def head_revision():
    return ScriptDirectory.from_config(config()).get_current_head()


def current_revision(connection=None):
    if connection is not None:
        return MigrationContext.configure(connection).get_current_revision()
    with db.engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


@contextmanager
def _lock(connection):
    """Serialize migrations of concurrently starting containers (PostgreSQL); SQLite needs no lock."""
    pg = connection.dialect.name == "postgresql"
    if pg:
        connection.execute(text("SELECT pg_advisory_lock(:id)"), {"id": LOCK_ID})
        connection.commit()
    try:
        yield
    finally:
        if pg:
            connection.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": LOCK_ID})
            connection.commit()


def _patch_legacy_schema(connection):
    insp = inspect(connection)
    for table, column, ddl in LEGACY_COLUMNS:
        if table in insp.get_table_names() and column not in {c["name"] for c in insp.get_columns(table)}:
            quoted = connection.dialect.identifier_preparer.quote(table)
            connection.execute(text(f"ALTER TABLE {quoted} ADD COLUMN {column} {ddl}"))
    connection.commit()


def upgrade_on_startup():
    """Bring the database schema to the newest revision. Returns (from_revision, to_revision)."""
    log = current_app.logger
    with db.engine.connect() as conn:
        with _lock(conn):
            tables = set(inspect(conn).get_table_names())
            before = current_revision(conn)
            if before is None and "user" in tables:
                log.info("pre-migration installation detected – stamping baseline %s", BASELINE)
                _patch_legacy_schema(conn)
                command.stamp(config(conn), BASELINE)
                conn.commit()
                before = BASELINE
            head = head_revision()
            if before != head:
                log.info("migrating database schema %s -> %s", before or "empty", head)
                command.upgrade(config(conn), "head")
                conn.commit()
            return before, head


def wait_until_current(timeout=300):
    """Used by the worker: wait for the web container to finish migrating."""
    head = head_revision()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if current_revision() == head:
                return True
        except Exception:
            db.session.rollback()
        time.sleep(2)
    return False
