"""Storage quotas.

* Repository quota (`Repository.quota_bytes`)
  - hosted: uploads that would exceed it are rejected with HTTP 413
  - proxy: cache size limit – the worker evicts the least recently used cached versions (hourly) until the
    cache is below 90 % of the limit
* User quota (`User.quota_bytes`, default: setting `quota_default_user_bytes`, applies to non-admins): total
  size of everything the user uploaded to hosted repositories. 0 / empty = unlimited.

Usage is the logical size of the stored artifacts: file sizes, for Docker the distinct config/layer blobs of
all manifests in the repository (layers shared by several tags count once).
"""
import json
import threading
import time

from sqlalchemy import func

from . import settings, storage
from .extensions import db
from .models import ArtifactFile, DockerManifest, Package, Repository, Version

TTL = 30
_cache: dict[tuple, tuple[int, float]] = {}
_lock = threading.Lock()


class QuotaExceeded(Exception):
    pass


def human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def parse_size(value):
    """'10G', '500 MB', '1.5TB', '1048576' -> bytes; '' / None / 0 -> None (unlimited)."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return int(value) or None
    s = str(value).strip().upper().replace(" ", "").rstrip("B").replace("I", "")
    mult = 1
    for suffix, m in (("K", 1024), ("M", 1024 ** 2), ("G", 1024 ** 3), ("T", 1024 ** 4)):
        if s.endswith(suffix):
            s, mult = s[:-1], m
            break
    try:
        n = int(float(s) * mult)
    except ValueError:
        raise ValueError(f"invalid size {value!r} (examples: 500M, 10G, 1T)")
    if n < 0:
        raise ValueError("size must not be negative")
    return n or None


def _cached(key, fn):
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and hit[1] > now:
            return hit[0]
    value = fn()
    with _lock:
        if len(_cache) > 10_000:
            _cache.clear()
        _cache[key] = (value, now + TTL)
    return value


def _add(key, n):
    with _lock:
        hit = _cache.get(key)
        if hit:
            _cache[key] = (hit[0] + n, hit[1])


def forget(repo_id=None):
    with _lock:
        if repo_id is None:
            _cache.clear()
        else:
            _cache.pop(("repo", repo_id), None)


def docker_blob_set(repo_id):
    """Digests of all config/layer blobs referenced by the repository's manifests."""
    out = set()
    for m in DockerManifest.query.filter_by(repository_id=repo_id):
        out.update(manifest_blobs(m))
    return out


def check_manifest(repo, user, doc, body_size):
    """Quota check when a manifest is pushed: layers that already exist in the store (pushed to another
    repository) are not uploaded again, so they are only accounted here."""
    if not (repo.quota_bytes and not repo.is_proxy):
        return
    known = docker_blob_set(repo.id)
    new = {d: s for d, s in blobs_of(doc).items() if d not in known}
    incoming = sum(new.values()) + body_size
    used = repo_usage(repo, fresh=True)
    if used + incoming > repo.quota_bytes:
        raise QuotaExceeded(f"repository quota exceeded: '{repo.name}' uses {human(used)} of "
                            f"{human(repo.quota_bytes)}, this image adds {human(incoming)}")


def manifest_blobs(m):
    """{digest: size} of an image manifest's config + layers (computed once and stored)."""
    if m.blobs is None:
        try:
            doc = json.loads(storage.read_blob(m.digest))
        except (OSError, ValueError):
            return {}
        m.blobs = blobs_of(doc)
    return m.blobs


def blobs_of(doc):
    blobs = {}
    if isinstance(doc.get("config"), dict) and doc["config"].get("digest"):
        blobs[doc["config"]["digest"]] = int(doc["config"].get("size") or 0)
    for layer in doc.get("layers") or []:
        if layer.get("digest"):
            blobs[layer["digest"]] = int(layer.get("size") or 0)
    return blobs


def _repo_usage(repo_id, fmt):
    files = (db.session.query(func.coalesce(func.sum(ArtifactFile.size), 0))
             .join(Version, ArtifactFile.version_id == Version.id).join(Package)
             .filter(Package.repository_id == repo_id).scalar())
    total = int(files or 0)
    if fmt == "docker":
        blobs, manifests, dirty = {}, 0, False
        for m in DockerManifest.query.filter_by(repository_id=repo_id):
            dirty |= m.blobs is None
            blobs.update(manifest_blobs(m))
            manifests += m.size
        if dirty:
            db.session.commit()
        total += sum(blobs.values()) + manifests
    return total


def repo_usage(repo, fresh=False):
    if fresh:
        return _repo_usage(repo.id, repo.format)
    return _cached(("repo", repo.id), lambda: _repo_usage(repo.id, repo.format))


def _user_usage(username):
    files = (db.session.query(func.coalesce(func.sum(ArtifactFile.size), 0))
             .join(Version, ArtifactFile.version_id == Version.id).join(Package).join(Repository)
             .filter(Version.uploaded_by == username, Repository.kind == "hosted").scalar())
    docker = sum((v.meta or {}).get("size") or 0 for v in
                 Version.query.join(Package).join(Repository)
                 .filter(Version.uploaded_by == username, Repository.format == "docker", Repository.kind == "hosted"))
    return int(files or 0) + int(docker)


def user_usage(user, fresh=False):
    if fresh:
        return _user_usage(user.username)
    return _cached(("user", user.username), lambda: _user_usage(user.username))


def default_user_quota():
    return int(settings.get("quota_default_user_bytes") or 0) or None


def user_limit(user):
    if user.quota_bytes is not None:
        return user.quota_bytes or None  # 0 = explicitly unlimited
    return None if user.is_admin else default_user_quota()


def check(repo, user, incoming=0):
    """Raise QuotaExceeded if storing `incoming` more bytes would exceed the repository or user quota."""
    incoming = max(int(incoming or 0), 0)
    if repo.quota_bytes and not repo.is_proxy:
        used = repo_usage(repo)
        if used + incoming > repo.quota_bytes:
            raise QuotaExceeded(f"repository quota exceeded: '{repo.name}' uses {human(used)} of "
                                f"{human(repo.quota_bytes)}" + (f", upload needs {human(incoming)}" if incoming else ""))
    limit = user_limit(user) if user else None
    if limit:
        used = user_usage(user)
        if used + incoming > limit:
            raise QuotaExceeded(f"user quota exceeded: '{user.username}' uses {human(used)} of {human(limit)}"
                                + (f", upload needs {human(incoming)}" if incoming else ""))


def consumed(repo, user, size):
    """Account a successful upload in the cached usage values (exact values are recomputed after TTL)."""
    _add(("repo", repo.id), size)
    if user:
        _add(("user", user.username), size)


def status(repo):
    used = repo_usage(repo)
    limit = repo.quota_bytes
    return {"used_bytes": used, "quota_bytes": limit,
            "percent": round(100 * used / limit, 1) if limit else None}


def enforce_cache_limits():
    """Leader task: shrink proxy caches above their size limit (LRU). Returns {repo: evicted versions}."""
    from .cache import remove_versions

    results = {}
    for repo in Repository.query.filter(Repository.kind == "proxy", Repository.quota_bytes > 0):
        used = repo_usage(repo, fresh=True)
        if used <= repo.quota_bytes:
            continue
        target = used - int(repo.quota_bytes * 0.9)
        victims, freed = [], 0
        q = (Version.query.join(Package).filter(Package.repository_id == repo.id)
             .order_by(func.coalesce(Version.last_accessed_at, Version.created_at)))
        for v in q:
            victims.append(v)
            freed += sum(f.size for f in v.files) + int((v.meta or {}).get("size") or 0)
            if freed >= target:
                break
        if victims:
            remove_versions(repo, victims, reason=f"cache size limit {human(repo.quota_bytes)}")
            results[repo.name] = len(victims)
    if results:
        forget()
    return results
