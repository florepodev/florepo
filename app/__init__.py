import logging
import os
import secrets

import click
from flask import Flask
from sqlalchemy import event
from sqlalchemy.engine import Engine
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .extensions import csrf, db, login_manager
from .models import Repository, User

__version__ = "1.3.0"


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    if dbapi_conn.__class__.__module__.startswith("sqlite3"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


def create_app(config=Config):
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = Flask(__name__)
    app.config.from_object(config)
    app.logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
    logging.getLogger("alembic.runtime.plugins").setLevel(logging.WARNING)
    if app.config["BEHIND_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    os.makedirs(app.config["STORAGE_PATH"], exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "ui.login"

    @login_manager.user_loader
    def load_user(uid):
        user = db.session.get(User, int(uid))
        return user if user and user.is_active else None

    from .blueprints import api, cargo, docker, docs, generic, golang, helm, maven, npm, nuget, ospkg, pypi, reports, ui

    app.register_blueprint(ui.bp)
    app.register_blueprint(reports.bp)
    app.register_blueprint(api.bp)
    app.register_blueprint(docs.bp)
    app.register_blueprint(pypi.bp)
    app.register_blueprint(npm.bp)
    for fmt_bp in (maven, golang, nuget, cargo, helm, generic):
        app.register_blueprint(fmt_bp.bp)
    ospkg.register(app)  # /deb/…, /rpm/…, /apk/…
    app.register_blueprint(docker.bp)

    register_cli(app)
    return app


def init_db(app):
    with app.app_context():
        # versioned schema migrations (Alembic) – see app/migrate.py
        from .migrate import upgrade_on_startup

        before, head = upgrade_on_startup()
        if before != head:
            print(f"*** database schema migrated: {before or 'empty'} -> {head}", flush=True)
        if User.query.count() == 0:
            pw = app.config["ADMIN_PASSWORD"] or secrets.token_urlsafe(16)
            admin = User(username=app.config["ADMIN_USERNAME"], role="admin")
            admin.set_password(pw)
            db.session.add(admin)
            db.session.commit()
            if not app.config["ADMIN_PASSWORD"]:
                print(f"*** created admin user '{admin.username}' with password: {pw}", flush=True)
        # signing keys for hosted deb/rpm/apk repositories (created once, before the web workers start)
        from . import signing

        try:
            signing.ensure_keys()
        except Exception as exc:  # gpg missing in dev setups – hosted OS repositories then cannot sign
            app.logger.warning("repository signing keys unavailable: %s", exc)


def register_cli(app):
    @app.cli.command("init-db")
    def init_db_cmd():
        """Create tables and the initial admin user."""
        init_db(app)

    @app.cli.command("worker")
    @click.option("--once", is_flag=True, help="Process pending scans and exit.")
    def worker_cmd(once):
        """Run the background vulnerability scan worker."""
        from .worker import run_worker

        from .migrate import wait_until_current

        # the web container runs the migrations; never work on an outdated schema
        if not wait_until_current(timeout=600):
            raise click.ClickException("database schema is not up to date – is the web container running?")
        run_worker(once=once)

    @app.cli.command("create-user")
    @click.argument("username")
    @click.option("--role", type=click.Choice(["reader", "deployer", "auditor", "admin"]), default="deployer")
    @click.password_option()
    def create_user(username, role, password):
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"created {role} {username}")

    @app.cli.command("gc")
    @click.option("--dry-run", is_flag=True)
    def gc_cmd(dry_run):
        """Delete blobs that are no longer referenced by any artifact, manifest or cache entry."""
        from .cache import collect_garbage

        removed, freed, stale = collect_garbage(dry_run=dry_run)
        click.echo(f"{'would remove' if dry_run else 'removed'} {removed} blobs ({freed / 1e6:.1f} MB), "
                   f"{stale} stale uploads")

    @app.cli.command("purge-cache")
    @click.argument("repository")
    @click.option("--older-than", type=int, default=None, help="days without access (default: everything)")
    def purge_cache_cmd(repository, older_than):
        """Remove cached artifacts of a proxy repository (blobs are deleted by the next gc)."""
        from .cache import purge_repository

        repo = Repository.query.filter_by(name=repository).first()
        if repo is None or not repo.is_proxy:
            raise click.ClickException(f"{repository} is not a proxy repository")
        res = purge_repository(repo, older_than_days=older_than, actor="cli")
        click.echo(f"removed {res['versions']} cached versions (~{res['bytes'] / 1e6:.1f} MB)")

    @app.cli.command("db-upgrade")
    def db_upgrade_cmd():
        """Apply pending database migrations (normally done automatically on start)."""
        from .migrate import upgrade_on_startup

        before, head = upgrade_on_startup()
        click.echo(f"schema: {before or 'empty'} -> {head}")

    @app.cli.command("db-current")
    def db_current_cmd():
        """Show the current and the newest schema revision."""
        from .migrate import current_revision, head_revision

        click.echo(f"current: {current_revision()}  head: {head_revision()}")

    @app.cli.command("db-revision")
    @click.option("-m", "--message", required=True)
    @click.option("--rev-id", default=None, help="explicit revision id, e.g. 0003")
    @click.option("--empty", is_flag=True, help="no autogenerate (for data migrations)")
    def db_revision_cmd(message, rev_id, empty):
        """Create a new migration from the differences between app/models.py and the database."""
        from alembic import command

        from .migrate import config

        with db.engine.connect() as conn:
            command.revision(config(conn), message=message, autogenerate=not empty, rev_id=rev_id)
            conn.commit()

    @app.cli.command("storage-check")
    def storage_check_cmd():
        """Write, read and delete a probe object in the configured blob storage."""
        from . import storage

        result = storage.check()
        click.echo(result)
        if not result.get("ok"):
            raise click.ClickException("storage check failed")

    @app.cli.command("storage-copy")
    @click.option("--from-path", "path", default=None,
                  help="file system storage to copy from (default: STORAGE_PATH)")
    def storage_copy_cmd(path):
        """Copy all blobs and SBOMs of a file system storage into the configured backend (e.g. fs -> S3)."""
        from . import storage

        path = path or app.config["STORAGE_PATH"]
        if not os.path.isdir(os.path.join(path, "blobs")):
            raise click.ClickException(f"{path} does not look like a Florepo storage directory")
        click.echo(f"copying {path} -> {storage.describe()['location']}")
        copied, skipped = storage.copy_from_directory(path, log=click.echo)
        click.echo(f"done: {copied} objects copied, {skipped} already present")

    @app.cli.command("ldap-sync")
    def ldap_sync_cmd():
        """Re-check all LDAP users against the directory now."""
        from . import ldap_auth

        if not ldap_auth.enabled():
            raise click.ClickException("LDAP is not enabled (Administration -> Authentication)")
        click.echo(ldap_auth.sync_all())
