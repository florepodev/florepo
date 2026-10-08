"""Alembic environment: uses the Flask app's SQLAlchemy engine and models (see app/migrate.py)."""
from alembic import context

from app.extensions import db
from app import models

target_metadata = db.metadata  # tables are registered by importing app.models
assert models


def run_migrations_online():
    connection = context.config.attributes.get("connection")
    if connection is None:
        with db.engine.connect() as connection:
            _run(connection)
            connection.commit()
    else:
        _run(connection)


def _run(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,   # ALTER TABLE support for SQLite
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


run_migrations_online()
