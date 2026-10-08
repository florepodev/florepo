"""Docker / OCI registry (Distribution API v2): hosted push/pull and pull-through cache.

Image references are `<host>/<repository>/<image>:<tag>`; the first path segment selects the
Florepo repository, the rest is the image name inside it.
"""
import json
import re
import uuid
from datetime import timedelta

from flask import Blueprint, Response, current_app, request

from .. import quotas, storage
from ..auth import can_download, can_read, can_write, resolve_identity
from ..docker_upstream import (DOCKER_HUB, INDEX_TYPES, MANIFEST_TYPES, Upstream, blob_linked, cache_manifest,
                               link_blobs, tee_blob)
from ..extensions import csrf, db
from ..models import (AuditEvent, DockerManifest, DockerUpload, DownloadEvent, Package, Repository, Version,
                      utcnow)
from .common import (get_or_create_package, get_or_create_version, metadata_fresh, now_iso, record_download,
                     schedule_scan)

bp = Blueprint("docker", __name__)
csrf.exempt(bp)

IMAGE_RE = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")

ROUTES = [
    (re.compile(r"^(?P<name>.+)/tags/list$"), "tags"),
    (re.compile(r"^(?P<name>.+)/manifests/(?P<ref>[A-Za-z0-9_+.:-]+)$"), "manifest"),
    (re.compile(r"^(?P<name>.+)/blobs/uploads/?$"), "upload_start"),
    (re.compile(r"^(?P<name>.+)/blobs/uploads/(?P<uid>[0-9a-f-]{36})$"), "upload"),
    (re.compile(r"^(?P<name>.+)/blobs/(?P<digest>sha256:[a-f0-9]{64})$"), "blob"),
]


def derr(status, code, message, detail=None):
    body = {"errors": [{"code": code, "message": message, "detail": detail}]}
    headers = {"Docker-Distribution-API-Version": "registry/2.0"}
    if status == 401:
        headers["WWW-Authenticate"] = 'Basic realm="Florepo"'
    return Response(json.dumps(body), status, headers, mimetype="application/json")


class Abort(Exception):
    def __init__(self, response):
        self.response = response


def resolve(name, write=False):
    repo_name, _, image = name.partition("/")
    user = resolve_identity()
    repo = Repository.query.filter_by(name=repo_name, format="docker").first()
    if not image or not IMAGE_RE.match(image):
        raise Abort(derr(400, "NAME_INVALID", "invalid repository name, use <repo>/<image>"))
    if repo is None:
        raise Abort(derr(401 if not user else 404, "NAME_UNKNOWN", "repository not found"))
    if repo.is_proxy and "/" not in image and Upstream(repo).base == DOCKER_HUB:
        image = f"library/{image}"  # nginx -> library/nginx, so both spellings share one cache entry
    if write:
        if not user:
            raise Abort(derr(401, "UNAUTHORIZED", "authentication required"))
        if not can_write(repo, user):
            raise Abort(derr(403, "DENIED", f"no write permission for repository {repo.name}"))
        if repo.is_proxy:
            raise Abort(derr(405, "UNSUPPORTED", "cannot push to a proxy repository"))
    elif not can_read(repo, user):
        raise Abort(derr(401, "UNAUTHORIZED", "authentication required"))
    elif not can_download(repo, user):
        raise Abort(derr(403, "DENIED", "auditors have read-only access and cannot pull images"))
    return repo, image, user


@bp.after_request
def api_version_header(resp):
    if request.path.startswith("/v2"):
        resp.headers["Docker-Distribution-API-Version"] = "registry/2.0"
    return resp


@bp.get("/v2/")
def ping():
    if not resolve_identity():
        return derr(401, "UNAUTHORIZED", "authentication required")
    return {}


@bp.get("/v2/_catalog")
def catalog():
    user = resolve_identity()
    if not user:
        return derr(401, "UNAUTHORIZED", "authentication required")
    names = []
    for repo in Repository.query.filter_by(format="docker").order_by(Repository.name):
        if can_read(repo, user):
            names += [f"{repo.name}/{p.name}" for p in sorted(repo.packages, key=lambda p: p.name)]
    n = request.args.get("n", type=int)
    last = request.args.get("last")
    if last:
        names = [x for x in names if x > last]
    if n:
        names = names[:n]
    return {"repositories": names}


@bp.route("/v2/<path:rest>", methods=["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"])
def dispatch(rest):
    for rx, handler in ROUTES:
        m = rx.match(rest)
        if m:
            try:
                return HANDLERS[handler](**m.groupdict())
            except Abort as a:
                db.session.rollback()
                return a.response
    return derr(404, "NOT_FOUND", "unknown endpoint")


# --- tags ---------------------------------------------------------------------

def tags(name):
    repo, image, _ = resolve(name)
    pkg = Package.query.filter_by(repository_id=repo.id, name=image).first()
    if pkg is None and not repo.is_proxy:
        return derr(404, "NAME_UNKNOWN", "repository name not known to registry")
    if repo.is_proxy:
        try:
            r = Upstream(repo).request("GET", image, "tags/list?" + request.query_string.decode())
            if r.status_code == 200:
                data = r.json()
                data["name"] = name
                return data
        except Exception as exc:
            current_app.logger.warning("docker upstream tags error: %s", exc)
    tag_names = sorted(v.version for v in pkg.versions) if pkg else []
    last = request.args.get("last")
    if last:
        tag_names = [t for t in tag_names if t > last]
    n = request.args.get("n", type=int)
    if n:
        tag_names = tag_names[:n]
    return {"name": name, "tags": tag_names}


# --- manifests ------------------------------------------------------------------

def _versions_for_digest(pkg, digest):
    if pkg is None:
        return []
    return [v for v in pkg.versions if v.digest == digest or digest in (v.meta or {}).get("children", [])]


def _manifest_summary(body, media_type):
    doc = json.loads(body)
    if media_type in INDEX_TYPES:
        children = [m["digest"] for m in doc.get("manifests", [])]
        platforms = [
            f"{m.get('platform', {}).get('os', '?')}/{m.get('platform', {}).get('architecture', '?')}"
            for m in doc.get("manifests", [])
            if m.get("platform", {}).get("os") != "unknown"
        ]
        return {"media_type": media_type, "children": children, "platforms": platforms}
    layers = doc.get("layers", [])
    return {
        "media_type": media_type,
        "layers": len(layers),
        "size": sum(layer.get("size", 0) for layer in layers),
        "config": doc.get("config", {}).get("digest"),
    }


def _tag_version(repo, image, tag, manifest, body, username):
    pkg = get_or_create_package(repo, image)
    ver, _ = get_or_create_version(pkg, tag)
    if ver.digest != manifest.digest:
        ver.digest = manifest.digest
        ver.meta = _manifest_summary(body, manifest.media_type)
        ver.uploaded_by = username
        schedule_scan(ver)
    return ver


def manifest(name, ref):
    if request.method in ("GET", "HEAD"):
        return get_manifest(name, ref)
    if request.method == "PUT":
        return put_manifest(name, ref)
    if request.method == "DELETE":
        return delete_manifest(name, ref)
    return derr(405, "UNSUPPORTED", "method not allowed")


def get_manifest(name, ref):
    repo, image, user = resolve(name)
    is_digest = bool(DIGEST_RE.match(ref))
    if not is_digest and not TAG_RE.match(ref):
        return derr(400, "TAG_INVALID", "invalid tag")
    pkg = Package.query.filter_by(repository_id=repo.id, name=image).first()
    m = None
    cache_hit = None

    if is_digest:
        m = DockerManifest.query.filter_by(repository_id=repo.id, image=image, digest=ref).first()
        if m is None and repo.is_proxy:
            cache_hit = False
            m = _proxy_manifest(repo, image, ref)
        elif repo.is_proxy:
            cache_hit = True
    else:
        if repo.is_proxy:
            m, cache_hit = _proxy_tag(repo, image, ref, pkg)
        else:
            ver = Version.query.filter_by(package_id=pkg.id, version=ref).first() if pkg else None
            if ver:
                m = DockerManifest.query.filter_by(repository_id=repo.id, image=image, digest=ver.digest).first()
    if m is None:
        return derr(404, "MANIFEST_UNKNOWN", "manifest unknown", {"reference": ref})

    pkg = pkg or Package.query.filter_by(repository_id=repo.id, name=image).first()
    versions = _versions_for_digest(pkg, m.digest)
    if not is_digest and pkg:
        versions = [v for v in versions if v.version == ref] or versions
    for v in versions:
        if v.is_blocked():
            return derr(403, "DENIED", "blocked by security policy",
                        {"tag": v.version, "max_severity": v.max_severity})

    # A pull = resolving a tag (HEAD or GET) or fetching the top-level manifest by digest.
    # Clients typically do HEAD <tag> followed by GET <digest>: every tag resolution counts, the GET by
    # digest only when it is not the second half of such a pull (pull by digest).
    top = [v for v in versions if v.digest == m.digest]
    if top and not is_digest:
        record_download(top[0], user, m.digest, cache_hit)
    elif top and request.method == "GET":
        _record_digest_pull(top[0], user, m.digest, cache_hit)
    db.session.commit()

    headers = {"Docker-Content-Digest": m.digest, "Content-Length": str(m.size), "ETag": f'"{m.digest}"'}
    if request.method == "HEAD":
        return Response(status=200, headers=headers, content_type=m.media_type)
    return Response(storage.read_blob(m.digest), 200, headers, content_type=m.media_type)


def _record_digest_pull(version, user, digest, cache_hit):
    """Record a GET-by-digest unless it directly follows a tag resolution of the same user (same pull)."""
    username = user.username if user else "anonymous"
    recent = (DownloadEvent.query
              .filter(DownloadEvent.version_id == version.id, DownloadEvent.username == username,
                      DownloadEvent.created_at >= utcnow() - timedelta(seconds=60))
              .first())
    if recent is None:
        record_download(version, user, digest, cache_hit)


def _proxy_tag(repo, image, tag, pkg):
    """Resolve a tag against the upstream, reusing cached manifests when the digest is unchanged."""
    up = Upstream(repo)
    ver = Version.query.filter_by(package_id=pkg.id, version=tag).first() if pkg else None
    cached = (DockerManifest.query.filter_by(repository_id=repo.id, image=image, digest=ver.digest).first()
              if ver and ver.digest else None)
    if cached and metadata_fresh((ver.meta or {}).get("resolved_at")):
        return cached, True  # resolved recently – no upstream round trip (and no Docker Hub rate limit hit)
    try:
        digest = up.head_manifest(image, tag)
        if digest and cached and cached.digest == digest:
            ver.meta = {**(ver.meta or {}), "resolved_at": now_iso()}
            db.session.commit()
            return cached, True
        m = up.fetch_manifest(image, digest or tag)
        if m is None:
            return None, False
        ver = _tag_version(repo, image, tag, m, storage.read_blob(m.digest), "proxy")
        ver.meta = {**(ver.meta or {}), "resolved_at": now_iso()}
        db.session.commit()
        return m, False
    except Exception as exc:
        current_app.logger.warning("docker upstream error for %s:%s: %s", image, tag, exc)
        db.session.rollback()
        if ver:
            return DockerManifest.query.filter_by(repository_id=repo.id, image=image, digest=ver.digest).first(), True
        raise Abort(derr(502, "UNAVAILABLE", "upstream unavailable"))


def _proxy_manifest(repo, image, digest):
    try:
        m = Upstream(repo).fetch_manifest(image, digest)
        db.session.commit()
        return m
    except Exception as exc:
        current_app.logger.warning("docker upstream error for %s@%s: %s", image, digest, exc)
        db.session.rollback()
        return None


def put_manifest(name, ref):
    repo, image, user = resolve(name, write=True)
    body = request.get_data()
    media_type = (request.headers.get("Content-Type") or "").split(";")[0]
    try:
        doc = json.loads(body)
    except ValueError:
        return derr(400, "MANIFEST_INVALID", "manifest is not valid json")
    media_type = media_type or doc.get("mediaType", "")
    if media_type not in MANIFEST_TYPES:
        return derr(400, "MANIFEST_INVALID", f"unsupported media type {media_type}")

    if media_type in INDEX_TYPES:
        for child in doc.get("manifests", []):
            if not DockerManifest.query.filter_by(repository_id=repo.id, image=image, digest=child["digest"]).first():
                return derr(400, "MANIFEST_BLOB_UNKNOWN", "referenced manifest unknown", child["digest"])
    else:
        refs = [doc.get("config", {})] + doc.get("layers", [])
        for d in refs:
            dg = d.get("digest", "")
            if d.get("mediaType", "").endswith("foreign.diff.tar.gzip"):
                continue
            if not blob_linked(repo, dg) or not storage.blob_exists(dg):
                return derr(400, "MANIFEST_BLOB_UNKNOWN", "blob unknown", dg)
        _quota_manifest(repo, user, doc, len(body))

    digest, size = storage.store_bytes(body)
    if DIGEST_RE.match(ref) and ref != digest:
        return derr(400, "DIGEST_INVALID", "digest does not match manifest")
    m = cache_manifest(repo, image, digest, media_type, body)

    if not DIGEST_RE.match(ref):
        if not TAG_RE.match(ref):
            return derr(400, "TAG_INVALID", "invalid tag")
        pkg = Package.query.filter_by(repository_id=repo.id, name=image).first()
        existing = Version.query.filter_by(package_id=pkg.id, version=ref).first() if pkg else None
        if existing and existing.digest != digest and not repo.allow_redeploy:
            db.session.rollback()
            return derr(400, "TAG_INVALID", f"tag {ref} is immutable in this repository")
        _tag_version(repo, image, ref, m, body, user.username)
        AuditEvent.log(user.username, "docker.push", f"{repo.name}/{image}:{ref}@{digest}")
        quotas.forget(repo.id)
    db.session.commit()
    return Response(status=201, headers={
        "Location": f"/v2/{name}/manifests/{digest}",
        "Docker-Content-Digest": digest,
    })


def delete_manifest(name, ref):
    repo, image, user = resolve(name, write=True)
    pkg = Package.query.filter_by(repository_id=repo.id, name=image).first()
    if DIGEST_RE.match(ref):
        m = DockerManifest.query.filter_by(repository_id=repo.id, image=image, digest=ref).first()
        if m is None:
            return derr(404, "MANIFEST_UNKNOWN", "manifest unknown")
        if pkg:
            for v in list(pkg.versions):
                if v.digest == ref:
                    db.session.delete(v)
        db.session.delete(m)
    else:
        ver = Version.query.filter_by(package_id=pkg.id, version=ref).first() if pkg else None
        if ver is None:
            return derr(404, "MANIFEST_UNKNOWN", "tag unknown")
        db.session.delete(ver)
    AuditEvent.log(user.username, "docker.delete", f"{repo.name}/{image}@{ref}")
    quotas.forget(repo.id)
    db.session.commit()
    return Response(status=202)


# --- blobs ----------------------------------------------------------------------

def blob(name, digest):
    if request.method == "DELETE":
        resolve(name, write=True)
        return derr(405, "UNSUPPORTED", "blob deletion is handled by garbage collection")
    repo, image, _ = resolve(name)
    headers = {"Docker-Content-Digest": digest}
    # blobs are stored once for all repositories but only served through repositories they belong to
    if blob_linked(repo, digest) and storage.blob_exists(digest):
        if request.method == "HEAD":
            headers["Content-Length"] = str(storage.blob_size(digest))
            return Response(status=200, headers=headers, content_type="application/octet-stream")
        return storage.serve_blob(digest, headers=headers)
    if repo.is_proxy:
        up = Upstream(repo)
        if request.method == "HEAD":
            r = up.request("HEAD", image, f"blobs/{digest}")
            if r.status_code == 200:
                link_blobs(repo.id, [digest])
                db.session.commit()
                headers["Content-Length"] = r.headers.get("Content-Length", "0")
                return Response(status=200, headers=headers, content_type="application/octet-stream")
        else:
            r = up.open_blob(image, digest)
            if r is not None:
                link_blobs(repo.id, [digest])
                db.session.commit()
                if storage.blob_exists(digest):  # already stored (other repository): no second copy
                    r.close()
                    return storage.serve_blob(digest, headers=headers)
                if r.headers.get("Content-Length"):
                    headers["Content-Length"] = r.headers["Content-Length"]
                return Response(tee_blob(r, digest), 200, headers, content_type="application/octet-stream",
                                direct_passthrough=True)
    return derr(404, "BLOB_UNKNOWN", "blob unknown to registry", digest)


# --- uploads --------------------------------------------------------------------

def _quota(repo, user, incoming):
    try:
        quotas.check(repo, user, incoming)
    except quotas.QuotaExceeded as exc:
        raise Abort(derr(413, "DENIED", str(exc)))


def _quota_manifest(repo, user, doc, size):
    try:
        quotas.check_manifest(repo, user, doc, size)
    except quotas.QuotaExceeded as exc:
        raise Abort(derr(413, "DENIED", str(exc)))


def _quota_after_append(repo, user, up):
    """Chunked uploads without Content-Length: re-check with the real size, drop the upload if it is over."""
    try:
        _quota(repo, user, up.size)
    except Abort:
        storage.delete_upload(up.id)
        db.session.delete(up)
        db.session.commit()
        raise


def _upload_headers(name, up):
    return {
        "Location": f"/v2/{name}/blobs/uploads/{up.id}",
        "Docker-Upload-UUID": up.id,
        "Range": f"0-{max(up.size - 1, 0)}",
        "Content-Length": "0",
    }


def upload_start(name):
    if request.method != "POST":
        return derr(405, "UNSUPPORTED", "method not allowed")
    repo, image, user = resolve(name, write=True)

    mount, source = request.args.get("mount"), request.args.get("from")
    if mount and source and DIGEST_RE.match(mount) and storage.blob_exists(mount):
        try:
            src_repo, _, _ = resolve(source)
            if blob_linked(src_repo, mount):  # the blob must really belong to the source repository
                link_blobs(repo.id, [mount])
                db.session.commit()
                return Response(status=201, headers={
                    "Location": f"/v2/{name}/blobs/{mount}", "Docker-Content-Digest": mount})
        except Abort:
            pass  # no access to source -> regular upload

    digest = request.args.get("digest")
    if digest:  # monolithic upload
        if not DIGEST_RE.match(digest):
            return derr(400, "DIGEST_INVALID", "invalid digest")
        _quota(repo, user, request.content_length)
        with storage.spool_stream(request.stream) as sp:
            if sp.digest != digest:
                return derr(400, "DIGEST_INVALID", "digest mismatch")
            _quota(repo, user, sp.size)
            _, size = sp.commit()
        link_blobs(repo.id, [digest])
        db.session.commit()
        quotas.consumed(repo, user, size)
        return Response(status=201, headers={"Location": f"/v2/{name}/blobs/{digest}",
                                             "Docker-Content-Digest": digest})

    up = DockerUpload(id=str(uuid.uuid4()), repository_id=repo.id, image=image, size=0)
    db.session.add(up)
    db.session.commit()
    return Response(status=202, headers=_upload_headers(name, up))


def upload(name, uid):
    repo, image, user = resolve(name, write=True)
    up = DockerUpload.query.filter_by(id=uid, repository_id=repo.id, image=image).first()
    if up is None:
        return derr(404, "BLOB_UPLOAD_UNKNOWN", "upload unknown")

    if request.method == "GET":
        return Response(status=204, headers=_upload_headers(name, up))
    if request.method == "DELETE":
        storage.delete_upload(uid)
        db.session.delete(up)
        db.session.commit()
        return Response(status=204)
    if request.method == "PATCH":
        crange = request.headers.get("Content-Range")
        if crange:
            start = int(crange.split("-")[0])
            if start != up.size:
                return Response(status=416, headers=_upload_headers(name, up))
        _quota(repo, user, up.size + (request.content_length or 0))
        up.size = storage.append_upload(uid, request.stream)
        _quota_after_append(repo, user, up)
        db.session.commit()
        return Response(status=202, headers=_upload_headers(name, up))
    if request.method == "PUT":
        digest = request.args.get("digest", "")
        if not DIGEST_RE.match(digest):
            return derr(400, "DIGEST_INVALID", "invalid digest")
        _quota(repo, user, up.size + (request.content_length or 0))
        up.size = storage.append_upload(uid, request.stream)
        _quota_after_append(repo, user, up)
        try:
            size = storage.finish_upload(uid, digest)
        except ValueError as exc:
            db.session.delete(up)
            db.session.commit()
            return derr(400, "DIGEST_INVALID", str(exc))
        db.session.delete(up)
        db.session.commit()
        link_blobs(repo.id, [digest])
        db.session.commit()
        quotas.consumed(repo, user, size)
        return Response(status=201, headers={
            "Location": f"/v2/{name}/blobs/{digest}", "Docker-Content-Digest": digest, "Content-Length": "0"})
    return derr(405, "UNSUPPORTED", "method not allowed")


HANDLERS = {
    "tags": tags,
    "manifest": manifest,
    "upload_start": upload_start,
    "upload": upload,
    "blob": blob,
}
