"""Generic file repository – arbitrary files (tarballs, installers, firmware, binaries, ...).

Hosted:  PUT    /generic/<repo>/<package path>/<version>/<file>   (curl -T)
         GET    /generic/<repo>/<package path>/<version>/<file>
         DELETE /generic/<repo>/<package path>/<version>/<file>
         GET    /generic/<repo>/<prefix>/                          JSON listing
Proxy:   GET /generic/<repo>/<path> is fetched from <upstream>/<path> and cached (any HTTP file server).

The last two path segments before the file name are package and version, e.g.
`tools/jq/1.7.1/jq-linux-amd64` -> package `tools/jq`, version `1.7.1`.
An optional `X-Checksum-Sha256` request header is verified on upload.
"""
import hmac
import mimetypes

from flask import Blueprint, Response, abort, jsonify, request

from .. import storage
from ..extensions import csrf, db
from ..models import ArtifactFile, AuditEvent, Package, Version
from .common import (add_file, base_url, blocked_response, fetch_upstream_file, file_checksums, find_file,
                     get_or_create_package, get_or_create_version, json_error, load_repo, quota_check,
                     record_download, remove_file, safe_path, schedule_scan, uploaded)

bp = Blueprint("generic", __name__, url_prefix="/generic")
csrf.exempt(bp)


def split_path(path):
    """'a/b/1.0/file' -> ('a/b', '1.0', 'file'); fewer than 3 segments -> (parent or file, file, file)."""
    parts = path.split("/")
    if len(parts) >= 3:
        return "/".join(parts[:-2]), parts[-2], parts[-1]
    return (parts[0] if len(parts) == 2 else parts[-1]), parts[-1], parts[-1]


def _ctype(filename):
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


@bp.get("/<repo_name>/")
def listing_root(repo_name):
    return listing(repo_name, "")


@bp.route("/<repo_name>/<path:path>", methods=["GET", "HEAD", "PUT", "DELETE"])
def file(repo_name, path):
    if request.method == "PUT":
        return upload(repo_name, path)
    if request.method == "DELETE":
        return delete(repo_name, path)
    if path.endswith("/"):
        return listing(repo_name, path)
    return download(repo_name, path)


def listing(repo_name, prefix):
    repo, _ = load_repo(repo_name, "generic")
    prefix = prefix.strip("/")
    q = (ArtifactFile.query.join(Version).join(Package).filter(Package.repository_id == repo.id)
         .order_by(ArtifactFile.path))
    if prefix:
        q = q.filter(ArtifactFile.path.startswith(prefix + "/"))
    items = [{"path": f.path, "size": f.size, "sha256": f.sha256, "created": f.created_at.isoformat() + "Z",
              "url": f"{base_url()}/generic/{repo.name}/{f.path}"} for f in q.limit(5000)]
    return jsonify({"repository": repo.name, "prefix": prefix, "files": items})


def download(repo_name, path):
    repo, user = load_repo(repo_name, "generic")
    path = safe_path(path)
    for algo in ("sha256", "sha1", "md5", "sha512"):  # checksum side files (<file>.sha256 etc.)
        if path.endswith(f".{algo}"):
            f = find_file(repo, path[: -len(algo) - 1])
            if f is not None:
                value = f.sha256 if algo == "sha256" else (f.meta or {}).get(algo)
                if value:
                    return Response(value + "\n", content_type="text/plain")
    f = find_file(repo, path)
    cache_hit = True if repo.is_proxy else None
    if f is None and repo.is_proxy:
        f = _proxy_fetch(repo, path)
        cache_hit = False
    if f is None:
        abort(404)
    if f.version.is_blocked():
        return blocked_response(f.version)
    headers = {"X-Checksum-Sha256": f.sha256}
    if request.method == "HEAD":
        headers["Content-Length"] = str(f.size)
        return Response(status=200, headers=headers, content_type=f.content_type or "application/octet-stream")
    record_download(f.version, user, f.filename, cache_hit)
    db.session.commit()
    return storage.serve_blob(f"sha256:{f.sha256}", mimetype=f.content_type or "application/octet-stream",
                              download_name=f.filename, as_attachment=True, headers=headers)


def _proxy_fetch(repo, path):
    sp = fetch_upstream_file(repo, f"{repo.upstream_url.rstrip('/')}/{path}")
    if sp is None:
        return None
    with sp:
        sums = file_checksums(sp.path)
        digest, size = sp.commit()
    name, version, filename = split_path(path)
    pkg = get_or_create_package(repo, name)
    ver, _ = get_or_create_version(pkg, version)
    ver.uploaded_by = "proxy"
    f = add_file(ver, path, digest, size, _ctype(filename), meta=sums)
    schedule_scan(ver)
    db.session.commit()
    return f


def upload(repo_name, path):
    repo, user = load_repo(repo_name, "generic", write=True)
    path = safe_path(path)
    if path.count("/") < 2:
        return json_error(400, "use /generic/<repo>/<package>/<version>/<file> (package may contain slashes)")
    name, version, filename = split_path(path)
    existing = find_file(repo, path)
    if existing is not None and not repo.allow_redeploy:
        return json_error(409, f"{path} already exists (repository is immutable)")
    quota_check(repo, user, request.content_length)
    with storage.spool_stream(request.stream) as sp:
        expected = request.headers.get("X-Checksum-Sha256")
        if expected and not hmac.compare_digest(expected.lower(), sp.digest.split(":", 1)[1]):
            return json_error(400, "X-Checksum-Sha256 does not match the uploaded content")
        quota_check(repo, user, sp.size)
        sums = file_checksums(sp.path)
        digest, size = sp.commit()
    pkg = get_or_create_package(repo, name)
    ver, _ = get_or_create_version(pkg, version)
    ver.uploaded_by = user.username
    f = add_file(ver, path, digest, size, _ctype(filename), meta=sums)
    schedule_scan(ver)
    AuditEvent.log(user.username, "generic.upload", f"{repo.name}/{path}")
    db.session.commit()
    uploaded(repo, user, size)
    return jsonify({"ok": True, "path": path, "package": name, "version": version, "size": size,
                    "sha256": f.sha256, "url": f"{base_url()}/generic/{repo.name}/{path}"}), 201


def delete(repo_name, path):
    repo, user = load_repo(repo_name, "generic", write=True)
    path = safe_path(path)
    f = find_file(repo, path)
    if f is None:
        abort(404)
    remove_file(f)
    AuditEvent.log(user.username, "generic.delete", f"{repo.name}/{path}")
    db.session.commit()
    return Response(status=204)
