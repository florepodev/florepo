"""Proxy cache retention and blob garbage collection.

* Each proxy repository can define `cache_retention_days`: cached artifacts (versions / tags) that were not
  requested for that many days are removed by the worker (hourly). Last access = newest pull (DownloadEvent),
  or the caching time if never pulled. 0 / empty = keep forever.
* Garbage collection deletes blobs no longer referenced by any artifact, manifest, metadata file or cache entry.
"""
import json
import time
from datetime import timedelta

from flask import current_app
from sqlalchemy import func, or_

from . import storage
from .extensions import db
from .models import (ArtifactFile, AuditEvent, DockerBlobLink, DockerManifest, DockerUpload, Package, RepoFile, Repository,
                     Version, utcnow)


def _docker_children(digest):
    try:
        doc = json.loads(storage.read_blob(digest))
    except (OSError, ValueError):
        return []
    return [m["digest"] for m in doc.get("manifests", [])]


def purge_repository(repo, older_than_days=None, actor="worker"):
    """Remove cached artifacts of a proxy repository not accessed for `older_than_days` (None = everything).

    Returns {"versions": n, "bytes": approx. freed bytes}."""
    if not repo.is_proxy:
        raise ValueError("only proxy repositories have a cache")
    q = Version.query.join(Package).filter(Package.repository_id == repo.id)
    if older_than_days is not None:
        cutoff = utcnow() - timedelta(days=older_than_days)
        q = q.filter(func.coalesce(Version.last_accessed_at, Version.created_at) < cutoff)
    victims = q.all()
    if not victims:
        return {"versions": 0, "bytes": 0}
    freed = remove_versions(repo, victims, actor=actor, purge_metadata=older_than_days is None,
                            reason=f"older than {older_than_days} days" if older_than_days is not None else "(all)")
    return {"versions": len(victims), "bytes": freed}


def remove_versions(repo, victims, actor="worker", purge_metadata=False, reason=""):
    """Delete cached versions of a proxy repository (blobs are freed by the next garbage collection)."""
    freed = sum(f.size for v in victims for f in v.files) + sum((v.meta or {}).get("size") or 0 for v in victims)
    dropped_digests = {v.digest for v in victims if v.digest}
    packages = {v.package for v in victims}
    for v in victims:
        db.session.delete(v)
    db.session.flush()
    if repo.format == "docker":
        keep = {v.digest for v in Version.query.join(Package).filter(Package.repository_id == repo.id)}
        keep |= {c for d in keep for c in _docker_children(d)}
        drop = set(dropped_digests) | {c for d in dropped_digests for c in _docker_children(d)}
        for digest in drop - keep:
            DockerManifest.query.filter_by(repository_id=repo.id, digest=digest).delete()
    for pkg in packages:
        if not pkg.versions:
            db.session.delete(pkg)
    if purge_metadata:
        RepoFile.query.filter_by(repository_id=repo.id).delete()
    AuditEvent.log(actor, "cache.purge", f"{repo.name}: {len(victims)} versions {reason}".strip())
    db.session.commit()
    return freed


def evict_expired():
    """Apply cache_retention_days of all proxy repositories. Returns {repo: result}."""
    results = {}
    for repo in Repository.query.filter(Repository.kind == "proxy", Repository.cache_retention_days > 0):
        res = purge_repository(repo, older_than_days=repo.cache_retention_days)
        if res["versions"]:
            results[repo.name] = res
            current_app.logger.info("cache retention: removed %d versions from %s (%d days)",
                                    res["versions"], repo.name, repo.cache_retention_days)
    return results


def cache_usage(repo):
    """(versions, bytes) cached in a repository."""
    files = (db.session.query(func.count(func.distinct(Version.id)), func.coalesce(func.sum(ArtifactFile.size), 0))
             .select_from(Version).join(Package).outerjoin(ArtifactFile)
             .filter(Package.repository_id == repo.id).one())
    docker_bytes = 0
    if repo.format == "docker":
        docker_bytes = sum((v.meta or {}).get("size") or 0
                           for v in Version.query.join(Package).filter(Package.repository_id == repo.id))
    return int(files[0] or 0), int(files[1] or 0) + docker_bytes


def collect_garbage(dry_run=False, min_age_seconds=3600):
    """Delete unreferenced blobs and stale uploads. Returns (blobs removed, bytes freed, stale uploads)."""
    referenced = {f"sha256:{sha}" for (sha,) in db.session.query(ArtifactFile.sha256)}
    referenced |= {d for (d,) in db.session.query(RepoFile.digest)}
    for m in DockerManifest.query:
        referenced.add(m.digest)
        try:
            doc = json.loads(storage.read_blob(m.digest))
        except (OSError, ValueError):
            continue
        if "config" in doc:
            referenced.add(doc["config"]["digest"])
        referenced.update(layer["digest"] for layer in doc.get("layers", []))
    for p in Package.query.filter(or_(Package.meta.isnot(None))):
        meta = p.meta or {}
        if meta.get("packument"):
            referenced.add(meta["packument"])
        for info in (meta.get("upstream_files") or {}).values():
            if info.get("metadata_sha256"):
                referenced.add(f"sha256:{info['metadata_sha256']}")

    cutoff = time.time() - min_age_seconds
    removed = freed = 0
    for digest, size, mtime in storage.iter_blobs():
        if digest in referenced or mtime >= cutoff:
            continue
        if not dry_run:
            storage.delete_blob(digest)
            DockerBlobLink.query.filter_by(digest=digest).delete()
        removed += 1
        freed += size
    stale = DockerUpload.query.filter(DockerUpload.created_at < utcnow() - timedelta(days=1)).all()
    if not dry_run:
        for up in stale:
            storage.delete_upload(up.id)
            db.session.delete(up)
        db.session.commit()
    return removed, freed, len(stale)
