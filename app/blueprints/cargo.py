"""Cargo registry (Rust) – sparse index protocol, hosted (cargo publish) and proxy (crates.io).

  ~/.cargo/config.toml:  [registries.florepo] index = "sparse+https://host/cargo/<repo>/index/"
  GET  /cargo/<repo>/index/config.json
  GET  /cargo/<repo>/index/<prefix>/<name>               index file (one JSON line per version)
  GET  /cargo/<repo>/api/v1/crates/<name>/<version>/download
  PUT  /cargo/<repo>/api/v1/crates/new                   cargo publish
  DELETE /cargo/<repo>/api/v1/crates/<name>/<version>/yank, PUT …/unyank
  GET  /cargo/<repo>/api/v1/crates?q=…                   cargo search
Authentication: cargo sends the API token as `Authorization: <token>` (cargo login --registry …).
"""
import json
import re
import struct

from flask import Blueprint, Response, abort, jsonify, request

from .. import metacache, storage
from ..extensions import csrf, db
from ..models import AuditEvent, Package, utcnow
from .common import (add_file, base_url, blocked_response, cached_metadata, fetch_upstream_file, find_file,
                     get_or_create_package, get_or_create_version, load_repo, quota_check, read_metadata,
                     record_download, schedule_scan, uploaded)

bp = Blueprint("cargo", __name__, url_prefix="/cargo")
csrf.exempt(bp)

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
CRATES_IO_DL = "https://static.crates.io/crates"


def index_path(name):
    """Sparse index location of a crate (lower case)."""
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def errors(msg, status=200):
    """Cargo shows `errors[].detail` to the user (status 200 is what crates.io uses for API errors)."""
    return jsonify({"errors": [{"detail": msg}]}), status


# --- index ---------------------------------------------------------------------------------------------

@bp.get("/<repo_name>/index/config.json")
def config(repo_name):
    repo, _ = load_repo(repo_name, "cargo")
    b = f"{base_url()}/cargo/{repo.name}"
    return jsonify({"dl": f"{b}/api/v1/crates", "api": b, "auth-required": not repo.public})


@bp.get("/<repo_name>/index/<path:path>")
def index_file(repo_name, path):
    repo, _ = load_repo(repo_name, "cargo")
    return metacache.serve(repo, lambda: _index_file(repo, path), package=path.rsplit("/", 1)[-1].lower())


def _index_file(repo, path):
    name = path.rsplit("/", 1)[-1]
    if not NAME_RE.match(name) or index_path(name) != path.lower():
        abort(404)
    if repo.is_proxy:
        rf = cached_metadata(repo, f"index/{index_path(name)}", f"{repo.upstream_url.rstrip('/')}/{index_path(name)}")
        if rf is None:
            abort(404)
        data = read_metadata(rf)
        blocked = _blocked(repo, name)
        if blocked:
            data = b"".join(line + b"\n" for line in data.splitlines()
                            if line.strip() and json.loads(line).get("vers") not in blocked)
        return Response(data, content_type="text/plain")
    pkg = Package.query.filter_by(repository_id=repo.id, name=name.lower()).first()
    lines = []
    for v in sorted(pkg.versions, key=lambda v: v.created_at) if pkg else []:
        entry = (v.meta or {}).get("index")
        if entry and not v.is_blocked():
            entry = {**entry, "yanked": bool((v.meta or {}).get("yanked"))}
            lines.append(json.dumps(entry, separators=(",", ":")))
    if not lines:
        abort(404)
    return Response("\n".join(lines) + "\n", content_type="text/plain")


def _blocked(repo, name):
    pkg = Package.query.filter_by(repository_id=repo.id, name=name.lower()).first()
    return {v.version for v in (pkg.versions if pkg else []) if v.is_blocked()}


# --- downloads -----------------------------------------------------------------------------------------

@bp.get("/<repo_name>/api/v1/crates/<name>/<version>/download")
def download(repo_name, name, version):
    repo, user = load_repo(repo_name, "cargo")
    if not NAME_RE.match(name) or not VERSION_RE.match(version):
        abort(404)
    path = f"crates/{name.lower()}/{name.lower()}-{version}.crate"
    f = find_file(repo, path)
    cache_hit = True if repo.is_proxy else None
    if f is None and repo.is_proxy:
        f = _proxy_fetch(repo, name, version, path)
        cache_hit = False
    if f is None:
        abort(404)
    if f.version.is_blocked():
        return blocked_response(f.version)
    record_download(f.version, user, f.filename, cache_hit)
    db.session.commit()
    return storage.serve_blob(f"sha256:{f.sha256}", mimetype="application/gzip", download_name=f.filename)


def _upstream_dl(repo):
    rf = cached_metadata(repo, "index/config.json", f"{repo.upstream_url.rstrip('/')}/config.json")
    try:
        return json.loads(read_metadata(rf)).get("dl") or CRATES_IO_DL if rf else CRATES_IO_DL
    except ValueError:
        return CRATES_IO_DL


def _proxy_fetch(repo, name, version, path):
    rf = cached_metadata(repo, f"index/{index_path(name)}", f"{repo.upstream_url.rstrip('/')}/{index_path(name)}")
    entry = None
    for line in (read_metadata(rf).splitlines() if rf else []):
        if line.strip():
            e = json.loads(line)
            if e.get("vers") == version:
                entry = e
    if entry is None:
        return None
    dl = _upstream_dl(repo)
    crate = entry["name"]
    if any(m in dl for m in ("{crate}", "{version}", "{prefix}", "{lowerprefix}", "{sha256-checksum}")):
        prefix = index_path(crate).rsplit("/", 1)[0]
        url = (dl.replace("{crate}", crate).replace("{version}", version).replace("{prefix}", prefix)
               .replace("{lowerprefix}", prefix.lower()).replace("{sha256-checksum}", entry.get("cksum", "")))
    else:
        url = f"{dl.rstrip('/')}/{crate}/{version}/download"
    sp = fetch_upstream_file(repo, url, expected_sha256=entry.get("cksum"))
    if sp is None:
        return None
    with sp:
        digest, size = sp.commit()
    pkg = get_or_create_package(repo, crate.lower(), crate)
    ver, _ = get_or_create_version(pkg, version)
    ver.uploaded_by = "proxy"
    ver.meta = {**(ver.meta or {}), "dependencies": _deps(entry)}
    f = add_file(ver, path, digest, size, "application/gzip")
    schedule_scan(ver)
    db.session.commit()
    return f


def _deps(entry):
    return [{"name": d.get("package") or d.get("name"), "version": d.get("req")}
            for d in entry.get("deps") or [] if d.get("kind", "normal") == "normal"]


# --- publish ---------------------------------------------------------------------------------------------

@bp.put("/<repo_name>/api/v1/crates/new")
def publish(repo_name):
    repo, user = load_repo(repo_name, "cargo", write=True)
    quota_check(repo, user, request.content_length)
    body = request.get_data()
    try:
        (jlen,) = struct.unpack("<I", body[:4])
        meta = json.loads(body[4:4 + jlen])
        (clen,) = struct.unpack("<I", body[4 + jlen:8 + jlen])
        crate = body[8 + jlen:8 + jlen + clen]
        if len(crate) != clen:
            raise ValueError("truncated body")
    except (struct.error, ValueError) as exc:
        return errors(f"invalid publish request: {exc}", 400)
    name, version = meta.get("name", ""), meta.get("vers", "")
    if not NAME_RE.match(name):
        return errors("invalid crate name")
    if not VERSION_RE.match(version):
        return errors("invalid version (semantic version required)")
    pkg = Package.query.filter_by(repository_id=repo.id, name=name.lower()).first()
    if pkg is not None and pkg.display_name != name:
        return errors(f"crate already exists as {pkg.display_name!r}")
    path = f"crates/{name.lower()}/{name.lower()}-{version}.crate"
    if find_file(repo, path) is not None and not repo.allow_redeploy:
        return errors(f"crate version `{name}@{version}` is already uploaded")
    quota_check(repo, user, len(crate))
    digest, size = storage.store_bytes(crate)

    deps = []
    for d in meta.get("deps") or []:
        dep = {"name": d.get("explicit_name_in_toml") or d["name"], "req": d.get("version_req", "*"),
               "features": d.get("features") or [], "optional": bool(d.get("optional")),
               "default_features": d.get("default_features", True), "target": d.get("target"),
               "kind": d.get("kind") or "normal"}
        if d.get("registry"):
            dep["registry"] = d["registry"]
        if d.get("explicit_name_in_toml"):
            dep["package"] = d["name"]
        deps.append(dep)
    features = meta.get("features") or {}
    features2 = {k: v for k, v in features.items() if any(x.startswith("dep:") or "?/" in x for x in v)}
    entry = {"name": name, "vers": version, "deps": deps, "cksum": digest.split(":", 1)[1],
             "features": {k: v for k, v in features.items() if k not in features2}, "yanked": False,
             "links": meta.get("links")}
    if features2:
        entry.update(features2=features2, v=2)
    if meta.get("rust_version"):
        entry["rust_version"] = meta["rust_version"]

    pkg = pkg or get_or_create_package(repo, name.lower(), name)
    ver, _ = get_or_create_version(pkg, version)
    ver.uploaded_by = user.username
    ver.meta = {**(ver.meta or {}), "index": entry, "yanked": False, "summary": meta.get("description"),
                "license": meta.get("license"), "keywords": meta.get("keywords") or [],
                "repository": meta.get("repository"), "dependencies": _deps(entry)}
    add_file(ver, path, digest, size, "application/gzip")
    schedule_scan(ver)
    pkg.updated_at = utcnow()
    AuditEvent.log(user.username, "cargo.publish", f"{repo.name}/{name}@{version}")
    db.session.commit()
    uploaded(repo, user, size)
    return jsonify({"warnings": {"invalid_categories": [], "invalid_badges": [], "other": []}})


@bp.route("/<repo_name>/api/v1/crates/<name>/<version>/yank", methods=["DELETE"])
def yank(repo_name, name, version):
    return _set_yanked(repo_name, name, version, True)


@bp.route("/<repo_name>/api/v1/crates/<name>/<version>/unyank", methods=["PUT"])
def unyank(repo_name, name, version):
    return _set_yanked(repo_name, name, version, False)


def _set_yanked(repo_name, name, version, yanked):
    repo, user = load_repo(repo_name, "cargo", write=True)
    pkg = Package.query.filter_by(repository_id=repo.id, name=name.lower()).first()
    ver = next((v for v in (pkg.versions if pkg else []) if v.version == version), None)
    if ver is None:
        return errors(f"crate `{name}@{version}` not found", 404)
    ver.meta = {**(ver.meta or {}), "yanked": yanked}
    AuditEvent.log(user.username, "cargo.yank" if yanked else "cargo.unyank", f"{repo.name}/{name}@{version}")
    db.session.commit()
    return jsonify({"ok": True})


@bp.get("/<repo_name>/api/v1/crates")
def search(repo_name):
    repo, _ = load_repo(repo_name, "cargo")
    q = (request.args.get("q") or "").strip().lower()
    per_page = min(request.args.get("per_page", 10, type=int), 100)
    query = Package.query.filter_by(repository_id=repo.id)
    if q:
        query = query.filter(Package.name.contains(q))
    total = query.count()
    crates = []
    for pkg in query.order_by(Package.name).limit(per_page):
        latest = pkg.versions[0] if pkg.versions else None
        crates.append({"name": pkg.display_name, "max_version": latest.version if latest else "0.0.0",
                       "description": (latest.meta or {}).get("summary") if latest else None})
    return jsonify({"crates": crates, "meta": {"total": total}})
