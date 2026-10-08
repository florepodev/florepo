"""npm registry: packuments, publish/unpublish, dist-tags, login, search, caching proxy."""
import base64
import copy
import hashlib
import hmac
import json
import re
from urllib.parse import quote, unquote

from flask import Blueprint, Response, abort, current_app, jsonify, request

from .. import metacache, storage
from ..auth import authenticate_password
from ..extensions import csrf, db
from ..models import ApiToken, ArtifactFile, AuditEvent, Package, Version, utcnow
from .common import (
    base_url,
    blocked_response,
    get_or_create_package,
    get_or_create_version,
    load_repo,
    metadata_fresh,
    now_iso,
    quota_check,
    record_download,
    schedule_scan,
    unauthorized,
    uploaded,
    upstream_get,
)

bp = Blueprint("npm", __name__, url_prefix="/npm")
csrf.exempt(bp)

NAME_RE = re.compile(r"^(@[a-z0-9\-~][a-z0-9\-._~]*/)?[a-zA-Z0-9\-~][a-zA-Z0-9\-._~]*$")
TGZ_RE = re.compile(r"^[A-Za-z0-9\-._~]+\.tgz$")


def err(status, message):
    return jsonify({"error": message}), status


def split_name(rest):
    rest = unquote(rest).strip("/")
    parts = rest.split("/")
    if parts[0].startswith("@"):
        if len(parts) < 2:
            return None, []
        return f"{parts[0]}/{parts[1]}", parts[2:]
    return parts[0], parts[1:]


def tarball_name(name, version):
    return f"{name.split('/')[-1]}-{version}.tgz"


def tarball_url(repo, name, filename):
    return f"{base_url()}/npm/{repo.name}/{name}/-/{filename}"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z") if dt else None


# --- dispatcher ---------------------------------------------------------------

@bp.route("/<repo_name>/<path:rest>", methods=["GET", "HEAD", "PUT", "POST", "DELETE"])
def dispatch(repo_name, rest):
    if rest.startswith("-/"):
        return special(repo_name, rest[2:])
    name, tail = split_name(rest)
    if not name or not NAME_RE.match(name):
        return err(400, "invalid package name")

    if request.method in ("GET", "HEAD"):
        if not tail:
            return packument(repo_name, name)
        if len(tail) == 2 and tail[0] == "-":
            return tarball(repo_name, name, tail[1])
        if len(tail) == 1:
            return version_manifest(repo_name, name, tail[0])
    elif request.method == "PUT":
        if not tail:
            return publish(repo_name, name, allow_removal=False)
        if len(tail) == 2 and tail[0] == "-rev":
            return publish(repo_name, name, allow_removal=True)
    elif request.method == "DELETE":
        if len(tail) == 2 and tail[0] == "-rev":
            return unpublish_package(repo_name, name)
        if len(tail) >= 2 and tail[0] == "-":
            # tarball deletion is part of the unpublish flow; versions are removed via PUT -rev
            load_repo(repo_name, "npm", write=True)
            return jsonify({"ok": True})
    return err(404, "not found")


def special(repo_name, rest):
    if rest == "ping":
        load_repo(repo_name, "npm")
        return jsonify({})
    if rest == "whoami":
        repo, user = load_repo(repo_name, "npm")
        if not user:
            return unauthorized()
        return jsonify({"username": user.username})
    if rest.startswith("user/org.couchdb.user:") and request.method == "PUT":
        return login(repo_name)
    if rest == "v1/search":
        return search(repo_name)
    if rest.startswith("package/"):
        return dist_tags(repo_name, rest[len("package/"):])
    return err(404, "not found")


# --- auth ---------------------------------------------------------------------

def login(repo_name):
    body = request.get_json(silent=True) or {}
    user = authenticate_password(body.get("name", ""), body.get("password", ""))
    if not user:
        return err(401, "invalid credentials")
    tok, raw = ApiToken.issue(user, f"npm login ({repo_name})")
    AuditEvent.log(user.username, "token.create", tok.name)
    db.session.commit()
    return jsonify({"ok": True, "id": f"org.couchdb.user:{user.username}", "token": raw}), 201


# --- read ---------------------------------------------------------------------

def _version_doc(repo, pkg, ver):
    manifest = copy.deepcopy((ver.meta or {}).get("manifest") or {"name": pkg.display_name, "version": ver.version})
    f = ver.files[0] if ver.files else None
    if f:
        manifest["dist"] = {
            "tarball": tarball_url(repo, pkg.display_name, f.filename),
            "shasum": (f.meta or {}).get("sha1"),
            "integrity": (f.meta or {}).get("integrity"),
        }
    manifest["_id"] = f"{pkg.display_name}@{ver.version}"
    return manifest


def _fix_dist_tags(tags, versions, times):
    tags = {k: v for k, v in tags.items() if v in versions}
    if "latest" not in tags and versions:
        tags["latest"] = max(versions, key=lambda v: times.get(v, ""))
    return tags


def packument(repo_name, name):
    repo, _ = load_repo(repo_name, "npm")
    return metacache.serve(repo, lambda: _packument(repo, name), package=name)


def _packument(repo, name):
    if repo.is_proxy:
        return proxy_packument(repo, name)
    pkg = Package.query.filter_by(repository_id=repo.id, name=name).first()
    if pkg is None:
        return err(404, "not found")
    versions, times = {}, {"created": iso(pkg.created_at), "modified": iso(pkg.updated_at)}
    for ver in pkg.versions:
        if ver.is_blocked():
            continue
        versions[ver.version] = _version_doc(repo, pkg, ver)
        times[ver.version] = iso(ver.created_at)
    meta = pkg.meta or {}
    doc = {
        "_id": name,
        "_rev": meta.get("rev", "1-0"),
        "name": name,
        "description": meta.get("description", ""),
        "dist-tags": _fix_dist_tags(meta.get("dist-tags", {}), versions, times),
        "versions": versions,
        "time": times,
        "readme": meta.get("readme", ""),
    }
    return Response(json.dumps(doc), mimetype="application/json")


def version_manifest(repo_name, name, spec):
    repo, _ = load_repo(repo_name, "npm")
    pkg = Package.query.filter_by(repository_id=repo.id, name=name).first()
    if pkg is None:
        return err(404, "not found")
    spec = (pkg.meta or {}).get("dist-tags", {}).get(spec, spec)
    ver = Version.query.filter_by(package_id=pkg.id, version=spec).first()
    if ver is None or not ver.files:
        return err(404, "version not found")
    if ver.is_blocked():
        return blocked_response(ver)
    return jsonify(_version_doc(repo, pkg, ver))


def tarball(repo_name, name, filename):
    repo, user = load_repo(repo_name, "npm")
    if not TGZ_RE.match(filename):
        return err(404, "not found")
    f = (
        ArtifactFile.query.join(Version).join(Package)
        .filter(Package.repository_id == repo.id, Package.name == name, ArtifactFile.filename == filename)
        .first()
    )
    cache_hit = True if repo.is_proxy else None
    if f is None and repo.is_proxy:
        f = proxy_tarball(repo, name, filename)
        cache_hit = False
    if f is None:
        return err(404, "not found")
    if f.version.is_blocked():
        return blocked_response(f.version)
    if request.method == "GET":
        record_download(f.version, user, filename, cache_hit)
        db.session.commit()
    return storage.serve_blob(f.sha256, download_name=filename)


def search(repo_name):
    repo, _ = load_repo(repo_name, "npm")
    text = request.args.get("text", "")
    size = min(int(request.args.get("size", 20)), 250)
    q = Package.query.filter_by(repository_id=repo.id)
    if text:
        q = q.filter(Package.name.contains(text))
    objects = []
    for pkg in q.order_by(Package.name).limit(size):
        latest = pkg.versions[0] if pkg.versions else None
        manifest = ((latest.meta or {}).get("manifest") or {}) if latest else {}
        publisher = (latest.uploaded_by if latest else None) or "unknown"
        objects.append({
            # npm >= 10 requires maintainers (array) and reads keywords/publisher/links
            "package": {
                "name": pkg.display_name,
                "version": latest.version if latest else None,
                "description": (pkg.meta or {}).get("description", ""),
                "keywords": manifest.get("keywords") or [],
                "date": iso(latest.created_at if latest else pkg.updated_at),
                "publisher": {"username": publisher},
                "maintainers": [{"username": publisher}],
                "links": {"npm": f"{base_url()}/npm/{repo.name}/{pkg.display_name}"},
            },
            "score": {"final": 1.0, "detail": {"quality": 1, "popularity": 1, "maintenance": 1}},
            "searchScore": 1.0,
        })
    return jsonify({"objects": objects, "total": len(objects), "time": iso(utcnow())})


# --- write --------------------------------------------------------------------

def publish(repo_name, name, allow_removal):
    repo, user = load_repo(repo_name, "npm", write=True)
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return err(400, "invalid json")
    if body.get("name", name) != name:
        return err(400, "name mismatch")
    attachments = body.get("_attachments") or {}
    versions = body.get("versions") or {}

    pkg = get_or_create_package(repo, name)
    meta = dict(pkg.meta or {})
    published = []

    if attachments:
        for vstr, manifest in versions.items():
            existing = Version.query.filter_by(package_id=pkg.id, version=vstr).first()
            if existing and existing.files and not repo.allow_redeploy:
                db.session.rollback()
                return err(403, f"cannot publish over previously published version {vstr}")
            fname = tarball_name(name, vstr)
            att = attachments.get(f"{name}-{vstr}.tgz") or attachments.get(fname)
            if att is None and len(attachments) == 1:
                att = next(iter(attachments.values()))
            if att is None:
                db.session.rollback()
                return err(400, f"missing tarball for {vstr}")
            data = base64.b64decode(att.get("data", ""))
            dist = manifest.get("dist") or {}
            sha1 = hashlib.sha1(data).hexdigest()
            integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
            if dist.get("shasum") and not hmac.compare_digest(dist["shasum"], sha1):
                db.session.rollback()
                return err(400, "shasum mismatch")
            if dist.get("integrity", "").startswith("sha512-") and dist["integrity"] != integrity:
                db.session.rollback()
                return err(400, "integrity mismatch")
            quota_check(repo, user, len(data))
            digest, size = storage.store_bytes(data)
            uploaded(repo, user, size)

            ver, _ = get_or_create_version(pkg, vstr)
            for f in list(ver.files):
                db.session.delete(f)
            clean = {k: v for k, v in manifest.items() if k not in ("dist", "readme", "_id")}
            ver.meta = {"manifest": clean}
            ver.uploaded_by = user.username
            db.session.add(ArtifactFile(
                version=ver, filename=fname, sha256=digest.split(":", 1)[1], size=size,
                content_type="application/octet-stream", meta={"sha1": sha1, "integrity": integrity},
            ))
            schedule_scan(ver)
            published.append(vstr)
            if manifest.get("description"):
                meta["description"] = manifest["description"]
        if body.get("readme"):
            meta["readme"] = body["readme"]
    else:
        # metadata update (deprecate, dist-tags) and – via -rev – version removal
        for ver in list(pkg.versions):
            if ver.version in versions:
                incoming = versions[ver.version]
                manifest = dict((ver.meta or {}).get("manifest") or {})
                if incoming.get("deprecated"):
                    manifest["deprecated"] = incoming["deprecated"]
                else:
                    manifest.pop("deprecated", None)
                ver.meta = {**(ver.meta or {}), "manifest": manifest}
            elif allow_removal:
                AuditEvent.log(user.username, "npm.unpublish", f"{repo.name}/{name}@{ver.version}")
                db.session.delete(ver)

    tags = dict(meta.get("dist-tags", {}))
    tags.update(body.get("dist-tags") or {})
    meta["dist-tags"] = tags
    rev_n = int(str(meta.get("rev", "0-0")).split("-")[0]) + 1
    meta["rev"] = f"{rev_n}-{hashlib.md5(json.dumps(tags, sort_keys=True).encode()).hexdigest()}"
    pkg.meta = meta
    pkg.updated_at = utcnow()
    for v in published:
        AuditEvent.log(user.username, "npm.publish", f"{repo.name}/{name}@{v}")
    db.session.commit()
    return jsonify({"ok": True, "id": name, "rev": meta["rev"]}), 201


def unpublish_package(repo_name, name):
    repo, user = load_repo(repo_name, "npm", write=True)
    pkg = Package.query.filter_by(repository_id=repo.id, name=name).first()
    if pkg is None:
        return err(404, "not found")
    db.session.delete(pkg)
    AuditEvent.log(user.username, "npm.unpublish", f"{repo.name}/{name}")
    db.session.commit()
    return jsonify({"ok": True})


def dist_tags(repo_name, rest):
    name, tail = split_name(rest)
    if not name or not tail or tail[0] != "dist-tags":
        return err(404, "not found")
    write = request.method in ("PUT", "DELETE", "POST")
    repo, user = load_repo(repo_name, "npm", write=write)
    pkg = Package.query.filter_by(repository_id=repo.id, name=name).first()
    if pkg is None:
        return err(404, "not found")
    meta = dict(pkg.meta or {})
    tags = dict(meta.get("dist-tags", {}))
    if request.method == "GET":
        return jsonify(tags)
    if len(tail) != 2:
        return err(400, "tag required")
    tag = tail[1]
    if request.method == "DELETE":
        tags.pop(tag, None)
    else:
        value = request.get_json(force=True, silent=True)
        if not isinstance(value, str) or not Version.query.filter_by(package_id=pkg.id, version=value).first():
            return err(400, "unknown version")
        tags[tag] = value
    meta["dist-tags"] = tags
    pkg.meta = meta
    db.session.commit()
    return jsonify({"ok": True})


# --- proxy --------------------------------------------------------------------

def _upstream_packument(repo, name):
    upstream = (repo.upstream_url or "https://registry.npmjs.org").rstrip("/")
    accept = request.headers.get("Accept", "application/json")
    if "application/vnd.npm.install-v1+json" not in accept:
        accept = "application/json"
    r = upstream_get(f"{upstream}/{quote(name, safe='@')}", repo=repo, headers={"Accept": accept})
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def proxy_packument(repo, name, refresh=False):
    pkg = Package.query.filter_by(repository_id=repo.id, name=name).first()
    want = "corgi" if "application/vnd.npm.install-v1+json" in request.headers.get("Accept", "") else "full"
    meta = (pkg.meta or {}) if pkg else {}
    if (not refresh and meta.get("packument") and metadata_fresh(meta.get("packument_fetched_at"))
            and meta.get("packument_kind") in (want, "full")):
        return _render_proxy_packument(repo, name, pkg, json.loads(storage.read_blob(meta["packument"])))
    try:
        doc = _upstream_packument(repo, name)
        if doc is None:
            return err(404, "not found")
        pkg = pkg or get_or_create_package(repo, name)
        tarballs = {}
        for vstr, vdoc in (doc.get("versions") or {}).items():
            dist = vdoc.get("dist") or {}
            if dist.get("tarball"):
                fn = dist["tarball"].rsplit("/", 1)[-1]
                tarballs[fn] = {"url": dist["tarball"], "version": vstr,
                                "shasum": dist.get("shasum"), "integrity": dist.get("integrity")}
        digest, _ = storage.store_bytes(json.dumps(doc).encode())
        pkg.meta = {**(pkg.meta or {}), "tarballs": tarballs, "packument": digest,
                    "description": doc.get("description", ""), "dist-tags": doc.get("dist-tags", {}),
                    "packument_fetched_at": now_iso(), "packument_kind": want}
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        current_app.logger.warning("npm upstream error for %s: %s", name, exc)
        pkg = Package.query.filter_by(repository_id=repo.id, name=name).first()
        if pkg is None or not (pkg.meta or {}).get("packument"):
            return err(502, "upstream unavailable")
        doc = json.loads(storage.read_blob(pkg.meta["packument"]))
    return _render_proxy_packument(repo, name, pkg, doc)


def _render_proxy_packument(repo, name, pkg, doc):
    blocked = {v.version for v in pkg.versions if v.is_blocked()}
    versions = {}
    for vstr, vdoc in (doc.get("versions") or {}).items():
        if vstr in blocked:
            continue
        dist = vdoc.get("dist") or {}
        if dist.get("tarball"):
            dist["tarball"] = tarball_url(repo, name, dist["tarball"].rsplit("/", 1)[-1])
        versions[vstr] = vdoc
    doc["versions"] = versions
    doc["dist-tags"] = _fix_dist_tags(doc.get("dist-tags", {}), versions, doc.get("time", {}))
    return Response(json.dumps(doc), mimetype=request.headers.get("Accept", "").startswith(
        "application/vnd.npm.install-v1+json") and "application/vnd.npm.install-v1+json" or "application/json")


def proxy_tarball(repo, name, filename):
    pkg = Package.query.filter_by(repository_id=repo.id, name=name).first()
    if pkg is None or filename not in (pkg.meta or {}).get("tarballs", {}):
        proxy_packument(repo, name, refresh=True)
        pkg = Package.query.filter_by(repository_id=repo.id, name=name).first()
    info = ((pkg.meta or {}).get("tarballs") or {}).get(filename) if pkg else None
    if not info:
        return None
    r = upstream_get(info["url"], repo=repo)
    if r.status_code != 200:
        abort(Response("upstream download failed\n", 502))
    data = r.content
    sha1 = hashlib.sha1(data).hexdigest()
    if info.get("shasum") and info["shasum"] != sha1:
        abort(Response("upstream checksum mismatch\n", 502))
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    digest, size = storage.store_bytes(data)
    ver, _ = get_or_create_version(pkg, info["version"])
    ver.uploaded_by = "proxy"
    try:
        full = json.loads(storage.read_blob(pkg.meta["packument"]))
        manifest = (full.get("versions") or {}).get(info["version"], {})
        ver.meta = {"manifest": {k: v for k, v in manifest.items() if k not in ("dist", "readme")}}
    except Exception:
        ver.meta = {"manifest": {"name": name, "version": info["version"]}}
    f = ArtifactFile(version=ver, filename=filename, sha256=digest.split(":", 1)[1], size=size,
                     meta={"sha1": sha1, "integrity": integrity, "upstream_url": info["url"]})
    db.session.add(f)
    schedule_scan(ver)
    db.session.commit()
    return f
