"""Debian (apt), RPM (dnf/yum/zypper) and Alpine (apk) repositories – hosted (signed indexes) and proxy.

URLs: /deb/<repo>/…, /rpm/<repo>/…, /apk/<repo>/…  – the path below the repository mirrors the upstream
layout (proxy) or the generated layout (hosted). Uploads: PUT/POST /<format>/<repo>/upload[/<filename>].
"""
import os
import re

from flask import Blueprint, Response, abort, current_app, jsonify, request
from sqlalchemy import text

from .. import ospkg, settings, signing, storage
from ..extensions import csrf, db
from ..models import OS_FORMATS, ArtifactFile, AuditEvent, Package, RepoFile, Version, utcnow
from .common import (blocked_response, get_or_create_package, get_or_create_version, load_repo, metadata_fresh,
                     quota_check, record_download, schedule_scan, upstream_get)

bp = Blueprint("ospkg", __name__)
csrf.exempt(bp)

PATH_RE = re.compile(r"^[A-Za-z0-9._+~%:@=-]+(/[A-Za-z0-9._+~%:@=-]+)*$")
CONTENT_TYPES = {".gz": "application/gzip", ".xz": "application/x-xz", ".bz2": "application/x-bzip2",
                 ".zst": "application/zstd", ".xml": "application/xml", ".asc": "text/plain", ".gpg": "application/pgp-signature",
                 ".deb": "application/vnd.debian.binary-package", ".rpm": "application/x-rpm", ".apk": "application/octet-stream"}


def content_type(path):
    for suffix, ctype in CONTENT_TYPES.items():
        if path.endswith(suffix):
            return ctype
    return "text/plain" if path.rsplit("/", 1)[-1] in ("Release", "InRelease", "Packages", "Sources") else \
        "application/octet-stream"


def register(app):
    app.register_blueprint(bp)


def _make_view(fmt):
    def view(repo_name, path):
        if path == "upload" or path.startswith("upload/"):
            if request.method not in ("PUT", "POST"):
                abort(405)
            return upload(fmt, repo_name, path[len("upload/"):] if "/" in path else "")
        if request.method not in ("GET", "HEAD"):
            abort(405)
        return serve(fmt, repo_name, path)
    view.__name__ = f"{fmt}_view"
    return view


# --- serving ---------------------------------------------------------------------------------

def _serve_blob(digest, path, size=None):
    if request.method == "HEAD":
        return Response(status=200, headers={"Content-Length": str(size if size is not None else storage.blob_size(digest))},
                        content_type=content_type(path))
    return storage.serve_blob(digest, mimetype=content_type(path))


def _key_file(fmt, repo, path):
    if fmt in ("deb", "rpm") and path in ("key.asc", "key.gpg", "RPM-GPG-KEY-florepo"):
        data = signing.gpg_public_key(armor=path != "key.gpg")
        return Response(data, content_type="application/pgp-keys")
    if fmt == "apk" and (path == "key.rsa.pub" or path == f"keys/{signing.apk_key_name()}"):
        return Response(signing.apk_public_key(), content_type="application/x-pem-file")
    return None


def serve(fmt, repo_name, path):
    repo, user = load_repo(repo_name, fmt)
    if path == "":
        return Response(_index_help(fmt, repo), content_type="text/plain")
    path = path.strip("/")
    if not PATH_RE.match(path) or ".." in path.split("/"):
        abort(404)
    if not repo.is_proxy:
        key = _key_file(fmt, repo, path)
        if key is not None:
            return key

    if ospkg.is_package(fmt, path):
        f = (ArtifactFile.query.join(Version).join(Package)
             .filter(Package.repository_id == repo.id, ArtifactFile.path == path).first())
        cache_hit = True if repo.is_proxy else None
        if f is None and repo.is_proxy:
            f = _proxy_fetch_package(fmt, repo, path)
            cache_hit = False
        if f is None:
            abort(404)
        if f.version.is_blocked():
            return blocked_response(f.version)
        if request.method == "GET":
            record_download(f.version, user, f.filename, cache_hit)
            db.session.commit()
        return _serve_blob(f.sha256, path, f.size)

    rf = RepoFile.query.filter_by(repository_id=repo.id, path=path).first()
    if repo.is_proxy and fmt == "deb":
        _remember_suite(repo, path)
    if repo.is_proxy:
        fresh = rf and (ospkg.is_immutable_metadata(fmt, path) or metadata_fresh(rf.fetched_at.isoformat()))
        if not fresh:
            rf = _proxy_fetch_metadata(repo, path, rf)
    if rf is None:
        abort(404)
    return _serve_blob(rf.digest, path, rf.size)


def _index_help(fmt, repo):
    return (f"Florepo {fmt} repository '{repo.name}' ({repo.kind}).\n"
            f"Setup instructions: see the repository page in the web UI or /docs.\n")


# --- proxy ----------------------------------------------------------------------------------------

def _remember_suite(repo, path):
    """Debian pool files carry no release – remember requested suites (dists/<suite>/…) to infer the distro."""
    m = re.match(r"^dists/([a-z]+)(?:-[a-z]+)?/", path)
    if not m:
        return
    key = f"deb_suites:{repo.id}"
    suites = settings.get(key) or []
    if m.group(1) not in suites and len(suites) < 20:
        settings.put(key, sorted(suites + [m.group(1)]))
        db.session.commit()


def _upstream_url(repo, path):
    return f"{(repo.upstream_url or '').rstrip('/')}/{path}"


def _proxy_fetch_metadata(repo, path, rf):
    try:
        r = upstream_get(_upstream_url(repo, path), repo=repo, stream=True, headers={"Accept-Encoding": "identity"})
    except Exception as exc:
        current_app.logger.warning("%s upstream error for %s: %s", repo.format, path, exc)
        if rf:
            return rf  # serve stale metadata while the upstream is unreachable
        abort(Response("upstream unavailable\n", 502))
    with r:
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            if rf:
                return rf
            abort(Response(f"upstream returned {r.status_code}\n", 502))
        r.raw.decode_content = True
        digest, size = storage.store_stream(r.raw)
    if rf is None:
        rf = RepoFile(repository_id=repo.id, path=path)
        db.session.add(rf)
    rf.digest, rf.size, rf.content_type, rf.fetched_at = digest, size, content_type(path), utcnow()
    db.session.commit()
    return rf


def _proxy_fetch_package(fmt, repo, path):
    filename = path.rsplit("/", 1)[-1]
    r = upstream_get(_upstream_url(repo, path), repo=repo, stream=True, headers={"Accept-Encoding": "identity"})
    with r:
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            abort(Response(f"upstream returned {r.status_code}\n", 502))
        r.raw.decode_content = True  # identity encoding requested: bytes stay identical to the signed index
        sp = storage.spool_stream(r.raw)
    with sp:
        try:
            info = ospkg.package_info(fmt, sp.path)
        except ospkg.PackageError:
            ident = ospkg.parse_filename(fmt, filename, path)
            if ident is None:
                abort(Response("not a valid package\n", 502))
            info = {"name": ident[0], "version": ident[1], "arch": ident[2], "source": ident[0],
                    "source_version": ident[1], "fields": {}}
        hashes = ospkg.file_hashes(sp.path)
        digest, size = sp.commit()
    return _register_file(fmt, repo, path, digest, size, info, uploaded_by="proxy", hashes=hashes)


def _register_file(fmt, repo, path, digest, size, info, uploaded_by, hashes, extra=None):
    pkg = get_or_create_package(repo, info["name"])
    ver, _ = get_or_create_version(pkg, info["version"])
    ver.uploaded_by = uploaded_by
    md5, sha1 = hashes
    ver.meta = {**(ver.meta or {}), "summary": info.get("summary"), "license": info.get("license")}
    f = ArtifactFile(version=ver, filename=path.rsplit("/", 1)[-1], path=path, sha256=digest.split(":", 1)[1],
                     size=size, content_type=content_type(path),
                     meta={"info": _json_safe(info), "md5": md5, "sha1": sha1, **(extra or {})})
    db.session.add(f)
    schedule_scan(ver)
    db.session.commit()
    return f


def _json_safe(info):
    return {k: v for k, v in info.items() if isinstance(v, (str, int, float, list, dict, type(None)))}


# --- hosted: upload & indexes -------------------------------------------------------------------------

def upload(fmt, repo_name, filename):
    repo, user = load_repo(repo_name, fmt, write=True)
    up = request.files.get("file") if request.mimetype == "multipart/form-data" else None
    filename = os.path.basename(filename or (up.filename if up else "") or request.args.get("filename", ""))
    if filename and (not ospkg.FILENAME_RE.match(filename) or not ospkg.is_package(fmt, filename)):
        return jsonify({"error": f"file name must end with {', '.join(ospkg.SUFFIXES[fmt])}"}), 400
    quota_check(repo, user, request.content_length)
    with storage.spool_stream(up.stream if up else request.stream) as sp:
        try:
            info = ospkg.package_info(fmt, sp.path)
        except ospkg.PackageError as exc:
            return jsonify({"error": str(exc)}), 400
        quota_check(repo, user, sp.size)
        hashes = ospkg.file_hashes(sp.path)
        digest, size = sp.commit()
    # curl --upload-file does not always append the file name (e.g. when the URL has a query string)
    filename = filename or ospkg.canonical_filename(fmt, info)
    path = ospkg.hosted_path(fmt, info, filename, request.args)
    existing = (ArtifactFile.query.join(Version).join(Package)
                .filter(Package.repository_id == repo.id, ArtifactFile.path == path).first())
    if existing:
        if not repo.allow_redeploy:
            return jsonify({"error": f"{path} already exists (repository is immutable)"}), 409
        ver = existing.version
        db.session.delete(existing)
        db.session.flush()
        if not ver.files:
            db.session.delete(ver)
        db.session.flush()
    extra = {}
    if fmt == "deb":
        extra = {"distribution": request.args.get("distribution") or "stable",
                 "component": request.args.get("component") or "main"}
    f = _register_file(fmt, repo, path, digest, size, info, uploaded_by=user.username, hashes=hashes, extra=extra)
    AuditEvent.log(user.username, f"{fmt}.upload", f"{repo.name}/{path}")
    rebuild_indexes(repo)
    db.session.commit()
    return jsonify({"ok": True, "path": path, "name": info["name"], "version": info["version"],
                    "arch": info.get("arch"), "version_id": f.version_id}), 201


def rebuild_indexes(repo):
    """Regenerate (and sign) all index files of a hosted OS repository from the database."""
    if repo.format not in OS_FORMATS or repo.is_proxy:
        return
    if db.engine.dialect.name == "postgresql":  # serialize concurrent uploads to the same repository
        db.session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": 4_200_000 + repo.id})
    files = (ArtifactFile.query.join(Version).join(Package).filter(Package.repository_id == repo.id)
             .order_by(ArtifactFile.path).all())
    generated = ospkg.BUILDERS[repo.format](repo, files)
    RepoFile.query.filter_by(repository_id=repo.id).delete()
    for path, data in generated.items():
        digest, size = storage.store_bytes(data)
        db.session.add(RepoFile(repository_id=repo.id, path=path, digest=digest, size=size,
                                content_type=content_type(path)))
    db.session.flush()


# routes are attached once at import time (the blueprint is registered on every app instance)
for _fmt in OS_FORMATS:
    _view = _make_view(_fmt)
    bp.add_url_rule(f"/{_fmt}/<repo_name>/", f"{_fmt}_root", _view, defaults={"path": ""}, methods=["GET", "HEAD"])
    bp.add_url_rule(f"/{_fmt}/<repo_name>/<path:path>", f"{_fmt}_path", _view, methods=["GET", "HEAD", "PUT", "POST"])
