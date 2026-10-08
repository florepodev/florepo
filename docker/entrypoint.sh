#!/bin/sh
set -e
case "$1" in
  web)
    flask --app wsgi init-db
    # blobs written by older versions were 0600; nginx serves them via X-Accel-Redirect and needs read access
    if [ -d "${STORAGE_PATH:-/data/storage}" ]; then
      find "${STORAGE_PATH:-/data/storage}" -type f ! -perm -o+r -exec chmod o+r {} + 2>/dev/null || true
    fi
    exec gunicorn wsgi:app --config /app/docker/gunicorn.conf.py
    ;;
  worker)
    exec flask --app wsgi worker
    ;;
  *)
    exec "$@"
    ;;
esac
