"""Runtime settings stored in the database, with defaults from the environment/config."""
from flask import current_app

from .extensions import db
from .models import Setting

# key -> config name providing the default
DEFAULTS = {
    "trivy_db_interval_hours": "TRIVY_DB_UPDATE_HOURS",
    "trivy_java_db": "TRIVY_JAVA_DB",
    "rescan_interval_hours": "RESCAN_INTERVAL_HOURS",
    "rescan_after_db_update": "RESCAN_AFTER_DB_UPDATE",
}


def get(key, default=None):
    row = db.session.get(Setting, key)
    if row is not None:
        return row.value
    if key in DEFAULTS:
        return current_app.config.get(DEFAULTS[key], default)
    return default


def put(key, value):
    row = db.session.get(Setting, key)
    if row is None:
        db.session.add(Setting(key=key, value=value))
    else:
        row.value = value
