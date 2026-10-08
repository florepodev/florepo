import json
from datetime import datetime

from flask import Response, abort, current_app, request

from .. import netproxy, quotas
from ..auth import can_download, can_read, can_write, resolve_identity
from ..extensions import db
from ..models import ArtifactFile, DownloadEvent, Package, Repository, Version, utcnow


def base_url():
    return current_app.config["BASE_URL"] or request.host_url.rstrip("/")


def unauthorized(message="authentication required"):
    return Response(message + "\n", 401, {"WWW-Authenticate": 'Basic realm="Florepo"'})


def load_repo(name, fmt, write=False):
    """Fetch a repository and enforce access. Aborts with a proper response on failure."""
    repo = Repository.query.filter_by(name=name, format=fmt).first()
    user = resolve_identity()
    if repo is None:
        # don't leak existence of private repos
        abort(unauthorized() if not user else Response("repository not found\n", 404))
    if write:
        if not user:
            abort(unauthorized())
        if not can_write(repo, user):
            abort(Response(f"no write permission for repository {repo.name}\n", 403))
        if repo.is_proxy:
            abort(Response("cannot deploy to a proxy repository\n", 405))
    elif not can_read(repo, user):
        abort(unauthorized())
    elif not can_download(repo, user):
        abort(Response("auditors have read-only access (UI, reports, SBOMs) and cannot download packages\n", 403))
    return repo, user


def get_or_create_package(repo, name, display_name=None):
    pkg = Package.query.filter_by(repository_id=repo.id, name=name).first()
    if pkg is None:
        pkg = Package(repository=repo, name=name, display_name=display_name or name, meta={})
        db.session.add(pkg)
        db.session.flush()
    return pkg


def get_or_create_version(pkg, version):
    ver = Version.query.filter_by(package_id=pkg.id, version=version).first()
    created = False
    if ver is None:
        ver = Version(package=pkg, version=version, meta={})
        db.session.add(ver)
        db.session.flush()
        created = True
    return ver, created


def schedule_scan(version):
    """New / changed content: queue the vulnerability scan and reset the malware verdict."""
    from .. import malware

    version.malware_status = "none"
    if current_app.config["SCAN_ON_PUSH"] or malware.enabled():
        version.request_scan()


def record_download(version, user, filename=None, cache_hit=None):
    """Log a pull for usage reporting. Caller commits.

    Append-only on purpose: incrementing version.download_count here would make every concurrent download
    of the same file wait for the same row lock. The worker folds new events into the counters instead.
    """
    pkg = version.package
    repo = pkg.repository
    fwd = request.headers.get("X-Forwarded-For", "") if current_app.config["BEHIND_PROXY"] else ""
    db.session.add(DownloadEvent(
        repository_id=repo.id, package_id=pkg.id, version_id=version.id,
        format=repo.format, repo_name=repo.name, package_name=pkg.display_name,
        version_name=version.version, filename=filename,
        username=user.username if user else "anonymous",
        ip=(fwd.split(",")[0].strip() or request.remote_addr or "")[:64],
        user_agent=(request.headers.get("User-Agent") or "")[:255],
        cache_hit=cache_hit,
    ))


def blocked_response(version):
    reason = version.block_reason()
    if reason == "malware":
        message = f"blocked: malware detected ({version.malware_name or 'ClamAV'})"
    elif reason == "unscanned":
        message = "blocked until the malware scan has finished - retry in a moment"
    else:
        message = "blocked by security policy"
    return Response(
        json.dumps(
            {
                "error": message,
                "reason": reason,
                "package": version.package.display_name,
                "version": version.version,
                "max_severity": version.max_severity,
            }
        ),
        403,
        mimetype="application/json",
    )


def metadata_fresh(fetched_at):
    """True if proxied metadata fetched at `fetched_at` (ISO string) is still within PROXY_METADATA_TTL."""
    ttl = current_app.config["PROXY_METADATA_TTL"]
    if not ttl or not fetched_at:
        return False
    try:
        return (utcnow() - datetime.fromisoformat(fetched_at)).total_seconds() < ttl
    except ValueError:
        return False


def now_iso():
    return utcnow().isoformat(timespec="seconds")


def upstream_get(url, repo=None, **kwargs):
    """GET from an upstream, honouring the outbound proxy configured globally or on the repository.

    Upstream credentials of the repository are sent as HTTP Basic auth (requests drops them on redirects to
    other hosts, e.g. CDN download URLs)."""
    kwargs.setdefault("timeout", current_app.config["UPSTREAM_TIMEOUT"])
    if repo is not None and repo.upstream_username and "auth" not in kwargs:
        kwargs["auth"] = (repo.upstream_username, repo.upstream_password or "")
    return netproxy.get(url, repo=repo, **kwargs)


def quota_check(repo, user, incoming=0):
    """Abort with 413 if storing `incoming` bytes would exceed the repository or user quota."""
    try:
        quotas.check(repo, user, incoming)
    except quotas.QuotaExceeded as exc:
        abort(Response(json.dumps({"error": str(exc)}), 413, mimetype="application/json"))


def uploaded(repo, user, size):
    """Bookkeeping after a successful upload (cached quota usage)."""
    quotas.consumed(repo, user, size)


def json_error(status, message):
    return Response(json.dumps({"error": message}), status, mimetype="application/json")


# --- helpers for path based formats (maven, go, nuget, cargo, helm, generic) ------------------------------

def upload_stream(*fields):
    """The uploaded content: a multipart file field (first of `fields`, else any) or the raw request body.

    Form fields are only parsed for multipart requests – touching request.files on e.g. `curl --data-binary`
    (application/x-www-form-urlencoded) would consume the body as form data."""
    if request.mimetype == "multipart/form-data":
        for name in fields:
            if request.files.get(name):
                return request.files[name].stream
        first = next(iter(request.files.values()), None)
        if first is not None:
            return first.stream
    return request.stream


def find_file(repo, path):
    """The ArtifactFile stored at `path` inside a repository, or None."""
    return (ArtifactFile.query.join(Version).join(Package)
            .filter(Package.repository_id == repo.id, ArtifactFile.path == path).first())


def file_checksums(local_path):
    """md5/sha1/sha512 of a local file (sha256 is the blob digest) – served as .md5/.sha1/.sha512 checksum files."""
    import hashlib

    hs = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha512": hashlib.sha512()}
    with open(local_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in hs.values():
                h.update(chunk)
    return {k: h.hexdigest() for k, h in hs.items()}


def add_file(version, path, digest, size, content_type="application/octet-stream", meta=None, filename=None):
    """Attach a stored blob to a version (replacing a file at the same path). Caller commits."""
    existing = ArtifactFile.query.filter_by(version_id=version.id, path=path).first()
    if existing is not None:
        db.session.delete(existing)
        db.session.flush()
    f = ArtifactFile(version=version, filename=filename or path.rsplit("/", 1)[-1], path=path,
                     sha256=digest.split(":", 1)[-1], size=size, content_type=content_type, meta=meta or {})
    db.session.add(f)
    return f


def remove_file(f):
    """Delete a file; its version / package disappear when they become empty. Caller commits."""
    ver = f.version
    pkg = ver.package
    db.session.delete(f)
    db.session.flush()
    if not ver.files:
        db.session.delete(ver)
        db.session.flush()
        if not pkg.versions:
            db.session.delete(pkg)


def cached_metadata(repo, path, url, ttl=True, headers=None, transform=None):
    """Upstream metadata of a proxy repository, cached as RepoFile under `path`.

    ttl=True: refreshed after PROXY_METADATA_TTL, False: immutable (cached forever). `transform(bytes) -> bytes`
    may rewrite the document before it is stored. Returns the RepoFile or None if the upstream has no such
    file. While the upstream is unreachable a stale copy is served."""
    from sqlalchemy.exc import IntegrityError

    from .. import storage
    from ..models import RepoFile

    rf = RepoFile.query.filter_by(repository_id=repo.id, path=path).first()
    if rf is not None and (not ttl or (rf.fetched_at and metadata_fresh(rf.fetched_at.isoformat()))):
        return rf
    try:
        r = upstream_get(url, repo=repo, **({"headers": headers} if headers else {}))
    except Exception as exc:
        current_app.logger.warning("%s upstream error for %s: %s", repo.format, url, exc)
        if rf is not None:
            return rf
        abort(json_error(502, "upstream unavailable"))
    if r.status_code in (404, 410):
        return None
    if r.status_code != 200:
        if rf is not None:
            return rf
        abort(json_error(502, f"upstream returned {r.status_code}"))
    data = transform(r.content) if transform else r.content
    digest, size = storage.store_bytes(data)
    ctype = (r.headers.get("Content-Type") or "application/octet-stream").split(";")[0]
    try:
        if rf is None:
            rf = RepoFile(repository_id=repo.id, path=path)
            db.session.add(rf)
        rf.digest, rf.size, rf.content_type, rf.fetched_at = digest, size, ctype, utcnow()
        db.session.commit()
    except IntegrityError:  # fetched concurrently by another request
        db.session.rollback()
        rf = RepoFile.query.filter_by(repository_id=repo.id, path=path).first()
    return rf


def read_metadata(rf):
    from .. import storage

    return storage.read_blob(rf.digest)


def fetch_upstream_file(repo, url, expected_sha256=None):
    """Download an upstream artifact into a closed Spool (caller commits or discards). None on 404."""
    from .. import storage

    r = upstream_get(url, repo=repo, stream=True)
    with r:
        if r.status_code in (404, 410):
            return None
        if r.status_code != 200:
            abort(json_error(502, f"upstream returned {r.status_code}"))
        r.raw.decode_content = True
        sp = storage.spool_stream(r.raw)
    if expected_sha256 and sp.digest != f"sha256:{expected_sha256}":
        sp.discard()
        abort(json_error(502, "upstream checksum mismatch"))
    return sp


def safe_path(path, pattern=None):
    """Normalized relative path or abort(404) – no '..', no empty segments, no control characters."""
    import re

    path = (path or "").strip("/")
    rx = pattern or re.compile(r"^[A-Za-z0-9._+~@=,!-]+(/[A-Za-z0-9._+~@=,!-]+)*$")
    if not path or not rx.match(path) or any(seg in (".", "..") for seg in path.split("/")):
        abort(404)
    return path
