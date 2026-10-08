"""Schema versioning: migrations must match the models, and every install path must reach head."""
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text

from app import create_app, init_db
from app.config import Config
from app.extensions import db
from app.migrate import BASELINE, current_revision, head_revision, upgrade_on_startup


def make_app(tmp_path, name):
    class C(Config):
        TESTING = True
        DATA_DIR = str(tmp_path)
        STORAGE_PATH = str(tmp_path / "storage")
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / name}"
        SECRET_KEY = "x"
        ADMIN_PASSWORD = "admin-pass"
        KEYS_PATH = str(tmp_path / "keys")
    return create_app(C)


def test_migrations_match_models(app):
    """Fails if app/models.py was changed without adding a migration (flask db-revision -m ...)."""
    with app.app_context():
        assert current_revision() == head_revision()
        with db.engine.connect() as conn:
            diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), db.metadata)
        assert diff == [], f"models and migrations differ – create a migration: {diff}"


def test_fresh_install_and_idempotent_upgrade(tmp_path):
    app = make_app(tmp_path, "fresh.db")
    init_db(app)
    with app.app_context():
        assert current_revision() == head_revision()
        assert upgrade_on_startup() == (head_revision(), head_revision())  # second start: nothing to do


def test_legacy_install_is_stamped_and_upgraded(tmp_path):
    """Installations made with create_all() before migrations existed (missing late columns)."""
    from alembic import command

    from app.migrate import config

    app = make_app(tmp_path, "legacy.db")
    with app.app_context():
        # a v1.1 database made by create_all(): baseline schema without alembic_version ...
        with db.engine.connect() as conn:
            command.upgrade(config(conn), BASELINE)
            conn.commit()
        with db.engine.begin() as conn:
            conn.execute(text("DROP TABLE alembic_version"))
            # ... from an early release where a column was still missing
            conn.execute(text("ALTER TABLE repository DROP COLUMN proxy_url"))
        assert "proxy_url" not in {c["name"] for c in inspect(db.engine).get_columns("repository")}
        assert "repo_file" not in inspect(db.engine).get_table_names()
    init_db(app)
    with app.app_context():
        assert current_revision() == head_revision()
        assert "proxy_url" in {c["name"] for c in inspect(db.engine).get_columns("repository")}
        with db.engine.connect() as conn:
            rows = conn.execute(text("SELECT version_num FROM alembic_version")).all()
        assert rows == [(head_revision(),)] and BASELINE <= head_revision()
