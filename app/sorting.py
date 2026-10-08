"""Server-side sorting for paginated tables (`?sort=<key>&dir=asc|desc`)."""
from flask import request


def apply_sort(query, columns, default_key, default_dir="desc", default_dirs=None):
    """columns: {key: SQLAlchemy column}. Returns (sorted query, spec for the `sort_th` macro)."""
    key = request.args.get("sort", default_key)
    if key not in columns:
        key = default_key
    direction = request.args.get("dir", default_dir if key == default_key else "asc")
    if direction not in ("asc", "desc"):
        direction = default_dir
    col = columns[key]
    # empty values (e.g. packages without versions) always go to the end, in both directions
    query = query.order_by((col.asc() if direction == "asc" else col.desc()).nulls_last())
    return query, {"key": key, "dir": direction, "default_dir": default_dirs or {}}
