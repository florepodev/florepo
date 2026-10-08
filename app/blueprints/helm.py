"""Helm chart repository (classic HTTP repository: index.yaml + chart archives).

Hosted: upload with `helm cm-push` (ChartMuseum API) or curl:
        POST   /helm/<repo>/api/charts                 body = chart .tgz (or multipart field "chart")
        PUT    /helm/<repo>/upload[/<file>.tgz]
        DELETE /helm/<repo>/api/charts/<name>/<version>
        GET    /helm/<repo>/index.yaml                 generated from the stored charts
        GET    /helm/<repo>/charts/<name>-<version>.tgz
Proxy:  index.yaml of the upstream repository is cached (PROXY_METADATA_TTL) with all chart URLs rewritten
        to /helm/<repo>/charts/…, charts are fetched from their original location on first download.
"""
import json
import re
import tarfile
from datetime import timezone

import yaml
from flask import Blueprint, Response, abort, jsonify, request

from .. import metacache, storage
from ..extensions import csrf, db
from ..models import AuditEvent, Package, RepoFile, Version, utcnow
from .common import (add_file, base_url, blocked_response, cached_metadata, fetch_upstream_file, find_file,
                     get_or_create_package, get_or_create_version, json_error, load_repo, quota_check,
                     read_metadata, record_download, remove_file, schedule_scan, upload_stream, uploaded)

bp = Blueprint("helm", __name__, url_prefix="/helm")
csrf.exempt(bp)

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$", re.I)
FILE_RE = re.compile(r"^[A-Za-z0-9._+-]+\.tgz(\.prov)?$")
URL_MAP = "_chart_urls.json"
try:
    Loader, Dumper = yaml.CSafeLoader, yaml.CSafeDumper  # libyaml: ~10x faster for big upstream indexes
except AttributeError:  # pragma: no cover
    Loader, Dumper = yaml.SafeLoader, yaml.SafeDumper


class ChartError(ValueError):
    pass


def read_chart(local_path):
    """Chart.yaml of a chart archive as dict (name, version, appVersion, dependencies, ...)."""
    try:
        with tarfile.open(local_path, "r:gz") as tf:
            for m in tf:
                parts = m.name.split("/")
                if len(parts) == 2 and parts[1] == "Chart.yaml" and m.isfile():
                    meta = yaml.load(tf.extractfile(m).read(1024 * 1024), Loader=Loader) or {}
                    break
            else:
                raise ChartError("Chart.yaml not found in the archive")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ChartError(f"not a chart archive: {exc}")
    except yaml.YAMLError as exc:
        raise ChartError(f"invalid Chart.yaml: {exc}")
    if not isinstance(meta, dict) or not meta.get("name") or not meta.get("version"):
        raise ChartError("Chart.yaml needs name and version")
    if not NAME_RE.match(str(meta["name"])):
        raise ChartError("invalid chart name")
    meta["version"] = str(meta["version"])
    return meta


def _json_safe(value):
    return json.loads(json.dumps(value, default=str))


# --- index -------------------------------------------------------------------------------------------

@bp.get("/<repo_name>/index.yaml")
def index(repo_name):
    repo, _ = load_repo(repo_name, "helm")
    return metacache.serve(repo, lambda: _index(repo))


def _index(repo):
    if repo.is_proxy:
        rf = cached_metadata(repo, "index.yaml", f"{repo.upstream_url.rstrip('/')}/index.yaml",
                             transform=lambda data: _rewrite_index(repo, data))
        if rf is None:
            abort(404)
        data = read_metadata(rf)
        blocked = _blocked(repo)
        if blocked:
            doc = yaml.load(data, Loader=Loader)
            for name, entries in list((doc.get("entries") or {}).items()):
                doc["entries"][name] = [e for e in entries if (name, str(e.get("version"))) not in blocked]
            data = yaml.dump(doc, Dumper=Dumper, sort_keys=False).encode()
        return Response(data, content_type="application/x-yaml")
    entries = {}
    pkgs = Package.query.filter_by(repository_id=repo.id).order_by(Package.name).all()
    for pkg in pkgs:
        for v in pkg.versions:  # newest first
            if v.is_blocked():
                continue
            chart = next((f for f in v.files if f.filename.endswith(".tgz")), None)
            if chart is None:
                continue
            entry = dict((v.meta or {}).get("chart") or {"name": pkg.name, "version": v.version})
            entry.update({"urls": [f"{base_url()}/helm/{repo.name}/charts/{chart.filename}"],
                          "digest": chart.sha256,
                          "created": v.created_at.replace(tzinfo=timezone.utc).isoformat()})
            entries.setdefault(pkg.name, []).append(entry)
    doc = {"apiVersion": "v1", "entries": entries, "generated": utcnow().replace(tzinfo=timezone.utc).isoformat()}
    return Response(yaml.dump(doc, Dumper=Dumper, sort_keys=False), content_type="application/x-yaml")


def _blocked(repo):
    return {(v.package.name, v.version) for v in Version.query.join(Package).filter(Package.repository_id == repo.id)
            if v.is_blocked()}


def _rewrite_index(repo, data):
    """Point all chart URLs at this repository and remember where they really are."""
    doc = yaml.load(data, Loader=Loader) or {}
    upstream = repo.upstream_url.rstrip("/")
    mapping = {}
    for name, entries in (doc.get("entries") or {}).items():
        for e in entries or []:
            urls = e.get("urls") or []
            if not urls:
                continue
            original = urls[0] if re.match(r"^https?://", urls[0]) else f"{upstream}/{urls[0].lstrip('/')}"
            filename = f"{name}-{e.get('version')}.tgz"
            mapping[filename] = original
            e["urls"] = [f"{base_url()}/helm/{repo.name}/charts/{filename}"]
    digest, size = storage.store_bytes(json.dumps(mapping).encode())
    rf = RepoFile.query.filter_by(repository_id=repo.id, path=URL_MAP).first()
    if rf is None:
        rf = RepoFile(repository_id=repo.id, path=URL_MAP)
        db.session.add(rf)
    rf.digest, rf.size, rf.content_type, rf.fetched_at = digest, size, "application/json", utcnow()
    return yaml.dump(doc, Dumper=Dumper, sort_keys=False).encode()


# --- downloads -------------------------------------------------------------------------------------------

@bp.route("/<repo_name>/charts/<filename>", methods=["GET", "HEAD"])
def chart(repo_name, filename):
    repo, user = load_repo(repo_name, "helm")
    if not FILE_RE.match(filename):
        abort(404)
    f = find_file(repo, f"charts/{filename}")
    cache_hit = True if repo.is_proxy else None
    if f is None and repo.is_proxy and filename.endswith(".tgz"):
        f = _proxy_fetch(repo, filename)
        cache_hit = False
    if f is None:
        abort(404)
    if f.version.is_blocked():
        return blocked_response(f.version)
    if request.method == "HEAD":
        return Response(status=200, content_type="application/gzip", headers={"Content-Length": str(f.size)})
    record_download(f.version, user, filename, cache_hit)
    db.session.commit()
    return storage.serve_blob(f"sha256:{f.sha256}", mimetype="application/gzip", download_name=filename)


def _proxy_fetch(repo, filename):
    rf = RepoFile.query.filter_by(repository_id=repo.id, path=URL_MAP).first()
    mapping = json.loads(read_metadata(rf)) if rf else {}
    if filename not in mapping:  # index not loaded yet or chart added upstream since
        RepoFile.query.filter_by(repository_id=repo.id, path="index.yaml").update({"fetched_at": None})
        db.session.commit()
        _index(repo)
        rf = RepoFile.query.filter_by(repository_id=repo.id, path=URL_MAP).first()
        mapping = json.loads(read_metadata(rf)) if rf else {}
    url = mapping.get(filename)
    if not url:
        return None
    sp = fetch_upstream_file(repo, url)
    if sp is None:
        return None
    with sp:
        try:
            meta = read_chart(sp.path)
        except ChartError as exc:
            abort(json_error(502, f"upstream chart invalid: {exc}"))
        digest, size = sp.commit()
    return _register(repo, meta, filename, digest, size, "proxy")


def _register(repo, meta, filename, digest, size, uploaded_by):
    pkg = get_or_create_package(repo, str(meta["name"]))
    ver, _ = get_or_create_version(pkg, meta["version"])
    ver.uploaded_by = uploaded_by
    deps = [{"name": d.get("name"), "version": str(d.get("version") or "")} for d in meta.get("dependencies") or []
            if isinstance(d, dict) and d.get("name")]
    ver.meta = {**(ver.meta or {}), "chart": _json_safe(meta), "summary": meta.get("description"),
                "app_version": str(meta.get("appVersion") or "") or None, "dependencies": deps}
    f = add_file(ver, f"charts/{filename}", digest, size, "application/gzip")
    schedule_scan(ver)
    pkg.updated_at = utcnow()
    db.session.commit()
    return f


# --- uploads ---------------------------------------------------------------------------------------------

@bp.post("/<repo_name>/api/charts")
def cm_upload(repo_name):
    return _upload(repo_name, upload_stream("chart"), force=request.args.get("force") is not None)


@bp.route("/<repo_name>/upload", methods=["PUT", "POST"], defaults={"filename": ""})
@bp.route("/<repo_name>/upload/<filename>", methods=["PUT", "POST"])
def put_upload(repo_name, filename):
    return _upload(repo_name, upload_stream("chart", "file"), force=False)


def _upload(repo_name, stream, force):
    repo, user = load_repo(repo_name, "helm", write=True)
    quota_check(repo, user, request.content_length)
    with storage.spool_stream(stream) as sp:
        try:
            meta = read_chart(sp.path)
        except ChartError as exc:
            return json_error(400, str(exc))
        filename = f"{meta['name']}-{meta['version']}.tgz"
        existing = find_file(repo, f"charts/{filename}")
        if existing is not None and not (repo.allow_redeploy or force):
            return json_error(409, f"{filename} already exists")
        quota_check(repo, user, sp.size)
        digest, size = sp.commit()
    _register(repo, meta, filename, digest, size, user.username)
    AuditEvent.log(user.username, "helm.upload", f"{repo.name}/{filename}")
    db.session.commit()
    uploaded(repo, user, size)
    return jsonify({"saved": True, "name": meta["name"], "version": meta["version"]}), 201


@bp.delete("/<repo_name>/api/charts/<name>/<version>")
def cm_delete(repo_name, name, version):
    repo, user = load_repo(repo_name, "helm", write=True)
    f = find_file(repo, f"charts/{name}-{version}.tgz")
    if f is None:
        return json_error(404, "chart not found")
    remove_file(f)
    AuditEvent.log(user.username, "helm.delete", f"{repo.name}/{name}-{version}")
    db.session.commit()
    return jsonify({"deleted": True})


@bp.get("/<repo_name>/api/charts")
def cm_list(repo_name):
    repo, _ = load_repo(repo_name, "helm")
    out = {}
    for pkg in Package.query.filter_by(repository_id=repo.id).order_by(Package.name):
        out[pkg.name] = [dict((v.meta or {}).get("chart") or {}, name=pkg.name, version=v.version) for v in pkg.versions]
    return jsonify(out)
