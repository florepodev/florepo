import os


def _bool(name, default=False):
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    DATA_DIR = os.environ.get("DATA_DIR", "/data")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'florepo.db')}"
    )
    # gevent workers serve many concurrent requests per process -> larger connection pool
    # pre-ping costs one extra DB round trip per request; recycling connections covers DB restarts well enough
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": _bool("DB_PRE_PING", False),
        "pool_recycle": int(os.environ.get("DB_POOL_RECYCLE", "600")),
        "pool_size": int(os.environ.get("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", "20")),
        "pool_timeout": 30,
    }
    # Blob storage: fs = directory STORAGE_PATH (local disk or a mounted NFS/SMB/CephFS share), s3 = object store
    STORAGE_BACKEND = os.environ.get("STORAGE_BACKEND", "fs").lower()
    STORAGE_PATH = os.environ.get("STORAGE_PATH", os.path.join(DATA_DIR, "storage"))
    # local scratch space for uploads in progress and scans (default: inside STORAGE_PATH for fs, DATA_DIR for s3)
    STAGING_PATH = os.environ.get("STAGING_PATH") or (
        os.path.join(DATA_DIR, "staging") if STORAGE_BACKEND == "s3" else "")
    S3_BUCKET = os.environ.get("S3_BUCKET", "")
    S3_PREFIX = os.environ.get("S3_PREFIX", "")
    S3_ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL", "")  # empty = AWS; e.g. http://minio:9000
    S3_REGION = os.environ.get("S3_REGION", "")
    S3_ACCESS_KEY_ID = os.environ.get("S3_ACCESS_KEY_ID", "")
    S3_SECRET_ACCESS_KEY = os.environ.get("S3_SECRET_ACCESS_KEY", "")
    S3_ADDRESSING_STYLE = os.environ.get("S3_ADDRESSING_STYLE", "auto")  # auto | path | virtual
    # how downloads are delivered: proxy = nginx fetches from S3 (clients only talk to Florepo),
    # redirect = 307 to a pre-signed URL (clients need access to S3), stream = through Python (no nginx)
    S3_SERVE = os.environ.get("S3_SERVE", "proxy").lower()
    S3_PRESIGN_EXPIRES = int(os.environ.get("S3_PRESIGN_EXPIRES", "300"))
    S3_VERIFY_TLS = _bool("S3_VERIFY_TLS", True)
    S3_CA_BUNDLE = os.environ.get("S3_CA_BUNDLE", "")
    S3_USE_PROXY = _bool("S3_USE_PROXY", False)  # route object store traffic through HTTP(S)_PROXY
    S3_MAX_CONNECTIONS = int(os.environ.get("S3_MAX_CONNECTIONS", "50"))
    # signing keys of hosted deb/rpm/apk repositories (GPG + RSA), created on first start
    KEYS_PATH = os.environ.get("KEYS_PATH", os.path.join(DATA_DIR, "keys"))

    # Public URL used in generated links (npm tarballs, setup snippets). Falls back to request host.
    BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")

    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

    # Scanner
    TRIVY_PATH = os.environ.get("TRIVY_PATH", "trivy")
    TRIVY_CACHE_DIR = os.environ.get("TRIVY_CACHE_DIR", os.path.join(DATA_DIR, "trivy-cache"))
    TRIVY_TIMEOUT = int(os.environ.get("TRIVY_TIMEOUT", "900"))
    OSV_ENABLED = _bool("OSV_ENABLED", True)
    OSV_URL = os.environ.get("OSV_URL", "https://api.osv.dev/v1/query")
    SCAN_ON_PUSH = _bool("SCAN_ON_PUSH", True)
    WORKER_POLL_SECONDS = int(os.environ.get("WORKER_POLL_SECONDS", "5"))
    # Re-scan artifacts periodically so newly published CVEs are detected (0 = off)
    RESCAN_INTERVAL_HOURS = int(os.environ.get("RESCAN_INTERVAL_HOURS", "24"))
    # Defaults for the scanner admin page (editable at runtime, stored in the database)
    TRIVY_DB_UPDATE_HOURS = int(os.environ.get("TRIVY_DB_UPDATE_HOURS", "12"))  # 0 = manual only
    TRIVY_JAVA_DB = _bool("TRIVY_JAVA_DB", True)
    RESCAN_AFTER_DB_UPDATE = _bool("RESCAN_AFTER_DB_UPDATE", False)

    # Proxy repositories
    UPSTREAM_TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "30"))
    # How long proxied metadata (pypi index pages, npm packuments, docker tag->digest) is served from the
    # cache before the upstream is asked again. Artifacts themselves are immutable and cached forever.
    PROXY_METADATA_TTL = int(os.environ.get("PROXY_METADATA_TTL", "300"))
    # rendered metadata documents kept per web worker process (see app/metacache.py), 0 = off
    METADATA_CACHE_MB = int(os.environ.get("METADATA_CACHE_MB", "32"))

    # nginx in front: hand blob downloads to nginx via X-Accel-Redirect instead of streaming them in Python.
    # nginx must map ACCEL_PREFIX (internal location) to STORAGE_PATH – see docker/nginx.conf.
    ACCEL_REDIRECT = _bool("ACCEL_REDIRECT", False)
    ACCEL_PREFIX = os.environ.get("ACCEL_PREFIX", "/_storage").rstrip("/")

    # E-mail notifications (alert rules are configured in the UI under Administration → Notifications)
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "florepo@localhost")
    SMTP_SECURITY = os.environ.get("SMTP_SECURITY", "starttls")  # starttls | ssl | none
    SMTP_TIMEOUT = int(os.environ.get("SMTP_TIMEOUT", "30"))

    # ClamAV malware scanning (enable and tune under Administration → Scanner & DB); clamd address defaults
    CLAMAV_HOST = os.environ.get("CLAMAV_HOST", "clamav")
    CLAMAV_PORT = int(os.environ.get("CLAMAV_PORT", "3310"))
    CLAMAV_ENABLED = _bool("CLAMAV_ENABLED", False)
    CLAMAV_TIMEOUT = int(os.environ.get("CLAMAV_TIMEOUT", "300"))

    MAX_CONTENT_LENGTH = None  # docker layers can be large
    WTF_CSRF_TIME_LIMIT = None
    BEHIND_PROXY = _bool("BEHIND_PROXY", False)
