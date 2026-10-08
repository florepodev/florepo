"""gunicorn settings: gevent workers handle thousands of concurrent (mostly I/O-bound) requests per process."""
import multiprocessing
import os

bind = "0.0.0.0:8080"
worker_class = "gevent"
# default: 2 per CPU core (gevent workers are single-threaded, CPU is the limit per process), max. 16
workers = int(os.environ.get("WEB_WORKERS") or min(2 * multiprocessing.cpu_count(), 16))
worker_connections = int(os.environ.get("WEB_WORKER_CONNECTIONS", "1000"))
timeout = 900            # large uploads / slow upstreams
graceful_timeout = 30
keepalive = 75           # matches nginx upstream keepalive
accesslog = "-" if os.environ.get("ACCESS_LOG", "true").lower() == "true" else None
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "*")
