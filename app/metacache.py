"""Cache for rendered package metadata (npm packuments, PyPI simple pages, maven-metadata.xml, Helm index.yaml,
NuGet registrations, Cargo index files, Go version lists).

Rendering these documents means loading every version (and file) of a package from the database and
serializing them – the most expensive requests of the whole application. A rendered document is kept in a
per-process LRU (METADATA_CACHE_MB) together with a *fingerprint* of the data it was built from:

    Package.updated_at (bumped in the same transaction whenever one of its versions or files changes, see
    models._touch_packages) – plus counts / newest timestamps of packages and metadata files for repository-wide
    documents
    + the repository's policy settings + the global ClamAV policy

Computing the fingerprint is a single aggregate query, so every request still sees the current state –
uploads, deletions, scan results, blocks, yanks and policy changes invalidate the entry immediately in all
worker processes, without explicit hooks. Proxy repositories additionally include the PROXY_METADATA_TTL time
window, so upstream changes are picked up as before.

Responses carry a strong ETag derived from the fingerprint; `If-None-Match` is answered with 304 without
rendering. `X-Florepo-Cache: hit|miss` shows what happened.
"""
import gzip
import hashlib
import threading
import time
from collections import OrderedDict

from flask import Response, current_app, make_response, request
from sqlalchemy import text

from .extensions import db

_lock = threading.Lock()
_entries: "OrderedDict[tuple, tuple[str, bytes, str]]" = OrderedDict()
_size = 0
_flights: dict = {}
_flight_lock = threading.Lock()
stats = {"hits": 0, "misses": 0, "not_modified": 0}

_PKG_SQL = text("SELECT id, updated_at FROM package WHERE repository_id = :r AND name = :n")

_REPO_SQL = text("""
SELECT
  (SELECT count(*) FROM package p WHERE p.repository_id = :r),
  (SELECT max(p.id) FROM package p WHERE p.repository_id = :r),
  (SELECT max(p.updated_at) FROM package p WHERE p.repository_id = :r),
  (SELECT count(*) FROM repo_file rf WHERE rf.repository_id = :r),
  (SELECT max(rf.fetched_at) FROM repo_file rf WHERE rf.repository_id = :r)
""")


def _limit():
    return int(current_app.config.get("METADATA_CACHE_MB", 32)) * 1024 * 1024


def fingerprint(repo, package=None):
    from . import malware

    if package is None:
        row = db.session.execute(_REPO_SQL, {"r": repo.id}).one()
    else:
        row = db.session.execute(_PKG_SQL, {"r": repo.id, "n": package}).first() or ("-", "-")
    pol = malware.policy()
    parts = [str(x) for x in row] + [repo.block_severity or "", str(repo.public), str(repo.upstream_url or ""),
                                     str(pol["enabled"]), str(pol["block_infected"]), str(pol["block_unscanned"])]
    if repo.is_proxy:
        ttl = current_app.config["PROXY_METADATA_TTL"] or 1
        parts.append(str(int(time.time() // ttl)))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def serve(repo, render, package=None, vary=()):
    """Return the cached response of `render()` (a Flask Response) for the current request, rendering it only
    if the underlying data changed. `package`: name as stored in Package.name for package-scoped documents
    (cheaper fingerprint, fewer invalidations) – None = whole repository. Authorization must happen before."""
    limit = _limit()
    if request.method not in ("GET", "HEAD") or limit <= 0:
        return make_response(render())
    fp = fingerprint(repo, package)
    key = (repo.id, request.method, request.path, request.query_string, request.host, request.headers.get("Accept", ""),
           *(request.headers.get(h, "") for h in vary))
    gzip_ok = "gzip" in (request.headers.get("Accept-Encoding") or "").lower()
    etag = hashlib.sha256(f"{fp}|{key}".encode()).hexdigest()[:32] + ("-gz" if gzip_ok else "")
    if etag in request.if_none_match:
        stats["not_modified"] += 1
        return Response(status=304, headers={"ETag": f'"{etag}"', "Vary": "Accept-Encoding",
                                             "X-Florepo-Cache": "hit"})
    with _lock:
        hit = _entries.get(key)
        if hit is not None and hit[0] == fp:
            _entries.move_to_end(key)
    if hit is not None and hit[0] == fp:
        stats["hits"] += 1
        _, body, gz, ctype = hit
        state = "hit"
    else:
        # single flight: concurrent misses of the same document wait for one render (no thundering herd of
        # renders / upstream fetches right after a change or a restart)
        with _flight_lock:
            flight = _flights.setdefault(key, threading.Lock())
        with flight:
            with _lock:
                hit = _entries.get(key)
            if hit is not None and hit[0] == fp:
                stats["hits"] += 1
                _, body, gz, ctype = hit
                return _respond(body, gz, ctype, gzip_ok, etag, "hit")
            try:
                return _render_and_store(key, fp, render, limit, gzip_ok, etag)
            finally:
                with _flight_lock:
                    _flights.pop(key, None)
    return _respond(body, gz, ctype, gzip_ok, etag, state)


def _render_and_store(key, fp, render, limit, gzip_ok, etag):
    global _size
    stats["misses"] += 1
    resp = make_response(render())
    if (resp.status_code != 200 or resp.direct_passthrough or resp.is_streamed or request.method != "GET"
            or resp.headers.get("Content-Encoding")):
        return resp
    body, ctype = resp.get_data(), resp.content_type
    # compressed once per change: package managers send Accept-Encoding: gzip, and pushing a 6 MB Helm
    # index or a 300 KB packument through the worker for every request is what limits throughput
    gz = gzip.compress(body, 6) if len(body) >= 1024 else None
    cost = len(body) + len(gz or b"")
    if cost <= limit // 4:
        with _lock:
            old = _entries.pop(key, None)
            if old is not None:
                _size -= len(old[1]) + len(old[2] or b"")
            _entries[key] = (fp, body, gz, ctype)
            _size += cost
            while _size > limit and _entries:
                _, (_, b, g, _) = _entries.popitem(last=False)
                _size -= len(b) + len(g or b"")
    return _respond(body, gz, ctype, gzip_ok, etag, "miss")


def _respond(body, gz, ctype, gzip_ok, etag, state):
    if gzip_ok and gz is not None:
        resp = Response(gz, content_type=ctype, headers={"Content-Encoding": "gzip"})
    else:
        resp = Response(body, content_type=ctype)
    resp.headers["Vary"] = "Accept-Encoding"
    resp.set_etag(etag)
    resp.headers["X-Florepo-Cache"] = state
    return resp


def clear():
    global _size
    with _lock:
        _entries.clear()
        _size = 0


def info():
    with _lock:
        return {**stats, "entries": len(_entries), "bytes": _size, "limit_bytes": _limit()}
