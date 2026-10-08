"""NuGet v3 feed (dotnet, nuget.exe, Visual Studio, Rider, Paket) – hosted and proxy (nuget.org).

  Source URL:  https://host/nuget/<repo>/index.json
  GET  index.json                                         service index
  GET  v3-flatcontainer/<id>/index.json                   versions (PackageBaseAddress/3.0.0)
  GET  v3-flatcontainer/<id>/<ver>/<id>.<ver>.nupkg | <id>.nuspec
  GET  registration/<id>/index.json                       package metadata (RegistrationsBaseUrl)
  GET  query?q=…                                          search (SearchQueryService)
  PUT  api/v2/package                                     dotnet nuget push -k <token>  (PackagePublish/2.0.0)
  DELETE api/v2/package/<id>/<version>
Proxy repositories read the upstream service index (default https://api.nuget.org/v3/index.json) and serve
its flat container, registration and search resources with all URLs rewritten to this repository.
"""
import json
import re
import xml.etree.ElementTree as ET
import zipfile

from flask import Blueprint, Response, abort, jsonify, request

from .. import metacache, storage
from ..extensions import csrf, db
from ..models import AuditEvent, Package, RepoFile, utcnow
from .common import (add_file, base_url, blocked_response, cached_metadata, fetch_upstream_file, find_file,
                     get_or_create_package, get_or_create_version, json_error, load_repo, quota_check,
                     read_metadata, record_download, remove_file, schedule_scan, upload_stream, upstream_get, uploaded)

bp = Blueprint("nuget", __name__, url_prefix="/nuget")
csrf.exempt(bp)

ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$")
VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
NS = re.compile(r"^\{[^}]*\}")
SEARCH_TYPES = ["SearchQueryService", "SearchQueryService/3.0.0-beta", "SearchQueryService/3.0.0-rc",
                "SearchQueryService/3.5.0"]
REGISTRATION_TYPES = ["RegistrationsBaseUrl", "RegistrationsBaseUrl/3.0.0-beta", "RegistrationsBaseUrl/3.0.0-rc",
                      "RegistrationsBaseUrl/3.4.0", "RegistrationsBaseUrl/3.6.0", "RegistrationsBaseUrl/Versioned"]


def normalize_version(v):
    """NuGet normalized version: 1.0 -> 1.0.0, 1.0.0.0 -> 1.0.0, build metadata dropped, lower case."""
    v = v.split("+", 1)[0]
    core, sep, pre = v.partition("-")
    nums = [str(int(x)) for x in core.split(".")]
    while len(nums) < 3:
        nums.append("0")
    if len(nums) == 4 and nums[3] == "0":
        nums = nums[:3]
    return (".".join(nums) + (f"-{pre}" if sep else "")).lower()


def version_key(v):
    core, _, pre = v.partition("-")
    nums = [int(x) for x in core.split(".") if x.isdigit()]
    return (nums + [0] * (4 - len(nums)), 0 if pre else 1, pre)


def read_nuspec(local_path):
    """Metadata of a .nupkg: id, version, description, authors, dependencies (per target framework)."""
    try:
        with zipfile.ZipFile(local_path) as zf:
            name = next((n for n in zf.namelist() if "/" not in n and n.lower().endswith(".nuspec")), None)
            if name is None:
                raise ValueError("no .nuspec file in the package root")
            raw = zf.read(name)
    except zipfile.BadZipFile:
        raise ValueError("not a NuGet package (zip archive expected)")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"invalid nuspec: {exc}")
    for el in root.iter():
        if isinstance(el.tag, str):
            el.tag = NS.sub("", el.tag)
    md = root.find("metadata")
    if md is None:
        raise ValueError("nuspec without <metadata>")

    def text(tag):
        el = md.find(tag)
        return (el.text or "").strip() if el is not None and el.text else None

    pid, ver = text("id"), text("version")
    if not pid or not ID_RE.match(pid) or not ver or not VERSION_RE.match(ver):
        raise ValueError("nuspec needs a valid <id> and <version>")
    groups = []
    deps = md.find("dependencies")
    if deps is not None:
        flat = [d for d in deps.findall("dependency")]
        if flat:
            groups.append({"targetFramework": "", "dependencies": [
                {"id": d.get("id"), "range": d.get("version") or ""} for d in flat]})
        for g in deps.findall("group"):
            groups.append({"targetFramework": g.get("targetFramework") or "", "dependencies": [
                {"id": d.get("id"), "range": d.get("version") or ""} for d in g.findall("dependency")]})
    return {"id": pid, "version": ver, "description": text("description"), "authors": text("authors"),
            "title": text("title"), "tags": text("tags"), "license": text("license"),
            "projectUrl": text("projectUrl"), "dependencyGroups": groups, "nuspec": raw.decode("utf-8", "replace")}


# --- service index -------------------------------------------------------------------------------------

def _b(repo):
    return f"{base_url()}/nuget/{repo.name}"


@bp.get("/<repo_name>/index.json")
@bp.get("/<repo_name>/v3/index.json")
def service_index(repo_name):
    repo, _ = load_repo(repo_name, "nuget")
    b = _b(repo)
    resources = [{"@id": f"{b}/v3-flatcontainer/", "@type": "PackageBaseAddress/3.0.0"}]
    resources += [{"@id": f"{b}/registration/", "@type": t} for t in REGISTRATION_TYPES]
    resources += [{"@id": f"{b}/query", "@type": t} for t in SEARCH_TYPES]
    if not repo.is_proxy:
        resources.append({"@id": f"{b}/api/v2/package", "@type": "PackagePublish/2.0.0"})
    return jsonify({"version": "3.0.0", "resources": resources})


def _upstream_resources(repo):
    """@type -> @id of the upstream service index (cached like other metadata)."""
    rf = cached_metadata(repo, "_service_index.json", repo.upstream_url)
    if rf is None:
        abort(json_error(502, "upstream service index not found"))
    try:
        doc = json.loads(read_metadata(rf))
    except ValueError:
        abort(json_error(502, "upstream service index is not JSON"))
    out = {}
    for r in doc.get("resources", []):
        out.setdefault(r.get("@type"), r.get("@id"))
    return out


def _upstream(repo, kind):
    res = _upstream_resources(repo)
    if kind == "flat":
        url = res.get("PackageBaseAddress/3.0.0")
    elif kind == "registration":
        url = next((res[t] for t in ("RegistrationsBaseUrl/3.6.0", "RegistrationsBaseUrl/3.4.0",
                                       "RegistrationsBaseUrl/3.0.0-rc", "RegistrationsBaseUrl") if res.get(t)), None)
    else:
        url = next((res[t] for t in reversed(SEARCH_TYPES) if res.get(t)), None)
    if not url:
        abort(json_error(502, f"upstream has no {kind} resource"))
    return url if kind == "search" else url.rstrip("/") + "/"


def _rewriter(repo):
    """Replace upstream resource URLs in proxied JSON documents with our own."""
    b = _b(repo)
    pairs = [(_upstream(repo, "flat"), f"{b}/v3-flatcontainer/"), (_upstream(repo, "registration"), f"{b}/registration/")]

    def rewrite(data):
        text = data.decode("utf-8")
        for old, new in pairs:
            text = text.replace(old, new)
        return text.encode()

    return rewrite


# --- flat container ---------------------------------------------------------------------------------------

@bp.get("/<repo_name>/v3-flatcontainer/<pid>/index.json")
def flat_versions(repo_name, pid):
    repo, _ = load_repo(repo_name, "nuget")
    return metacache.serve(repo, lambda: _flat_versions(repo, pid), package=pid.lower())


def _flat_versions(repo, pid):
    lid = pid.lower()
    if not ID_RE.match(lid):
        abort(404)
    blocked = {v.version for v in _versions(repo, lid) if v.is_blocked()}
    if repo.is_proxy:
        rf = cached_metadata(repo, f"flat/{lid}/index.json", f"{_upstream(repo, 'flat')}{lid}/index.json")
        if rf is None:
            abort(404)
        versions = json.loads(read_metadata(rf)).get("versions", [])
    else:
        versions = sorted((v.version for v in _versions(repo, lid)), key=version_key)
        if not versions:
            abort(404)
    return jsonify({"versions": [v for v in versions if v not in blocked]})


def _versions(repo, lid):
    pkg = Package.query.filter_by(repository_id=repo.id, name=lid).first()
    return pkg.versions if pkg else []


@bp.route("/<repo_name>/v3-flatcontainer/<pid>/<ver>/<filename>", methods=["GET", "HEAD"])
def flat_file(repo_name, pid, ver, filename):
    repo, user = load_repo(repo_name, "nuget")
    lid, lver = pid.lower(), ver.lower()
    if not ID_RE.match(lid) or not VERSION_RE.match(lver):
        abort(404)
    if filename.lower() == f"{lid}.nuspec":
        return _nuspec(repo, lid, lver)
    if filename.lower() != f"{lid}.{lver}.nupkg":
        abort(404)
    path = f"{lid}/{lver}/{lid}.{lver}.nupkg"
    f = find_file(repo, path)
    cache_hit = True if repo.is_proxy else None
    if f is None and repo.is_proxy:
        f = _proxy_fetch(repo, lid, lver, path)
        cache_hit = False
    if f is None:
        abort(404)
    if f.version.is_blocked():
        return blocked_response(f.version)
    if request.method == "HEAD":
        return Response(status=200, content_type="application/octet-stream", headers={"Content-Length": str(f.size)})
    record_download(f.version, user, f.filename, cache_hit)
    db.session.commit()
    return storage.serve_blob(f"sha256:{f.sha256}", mimetype="application/octet-stream")


def _nuspec(repo, lid, lver):
    path = f"nuspec/{lid}/{lver}.nuspec"
    if repo.is_proxy:
        rf = cached_metadata(repo, path, f"{_upstream(repo, 'flat')}{lid}/{lver}/{lid}.nuspec", ttl=False)
    else:
        rf = RepoFile.query.filter_by(repository_id=repo.id, path=path).first()
    if rf is None:
        abort(404)
    return Response(read_metadata(rf), content_type="application/xml")


def _proxy_fetch(repo, lid, lver, path):
    sp = fetch_upstream_file(repo, f"{_upstream(repo, 'flat')}{lid}/{lver}/{lid}.{lver}.nupkg")
    if sp is None:
        return None
    with sp:
        try:
            spec = read_nuspec(sp.path)
        except ValueError as exc:
            abort(json_error(502, f"upstream package invalid: {exc}"))
        digest, size = sp.commit()
    return _register(repo, spec, path, digest, size, "proxy")


def _register(repo, spec, path, digest, size, uploaded_by):
    lid = spec["id"].lower()
    lver = normalize_version(spec["version"])
    pkg = get_or_create_package(repo, lid, spec["id"])
    ver, _ = get_or_create_version(pkg, lver)
    ver.uploaded_by = uploaded_by
    deps = [{"name": d["id"], "version": d["range"]} for g in spec["dependencyGroups"] for d in g["dependencies"]]
    meta = {k: spec[k] for k in ("description", "authors", "title", "tags", "license", "projectUrl", "dependencyGroups")}
    ver.meta = {**(ver.meta or {}), **meta, "summary": spec.get("description"), "dependencies": deps,
                "original_version": spec["version"]}
    f = add_file(ver, path, digest, size, "application/octet-stream")
    if not repo.is_proxy:
        nd, ns = storage.store_bytes(spec["nuspec"].encode())
        rf = RepoFile.query.filter_by(repository_id=repo.id, path=f"nuspec/{lid}/{lver}.nuspec").first()
        if rf is None:
            rf = RepoFile(repository_id=repo.id, path=f"nuspec/{lid}/{lver}.nuspec")
            db.session.add(rf)
        rf.digest, rf.size, rf.content_type, rf.fetched_at = nd, ns, "application/xml", utcnow()
    schedule_scan(ver)
    pkg.updated_at = utcnow()
    db.session.commit()
    return f


# --- registration & search ---------------------------------------------------------------------------------

def _leaf(repo, pkg, v):
    b = _b(repo)
    content = f"{b}/v3-flatcontainer/{pkg.name}/{v.version}/{pkg.name}.{v.version}.nupkg"
    m = v.meta or {}
    return {
        "@id": f"{b}/registration/{pkg.name}/{v.version}.json",
        "catalogEntry": {
            "@id": f"{b}/registration/{pkg.name}/{v.version}.json", "id": pkg.display_name,
            "version": m.get("original_version") or v.version, "description": m.get("description") or "",
            "authors": m.get("authors") or "", "title": m.get("title") or "", "tags": (m.get("tags") or "").split(),
            "projectUrl": m.get("projectUrl") or "", "listed": True, "packageContent": content,
            "published": v.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dependencyGroups": m.get("dependencyGroups") or [],
        },
        "packageContent": content,
        "registration": f"{b}/registration/{pkg.name}/index.json",
    }


@bp.get("/<repo_name>/registration/<path:rest>")
def registration(repo_name, rest):
    repo, _ = load_repo(repo_name, "nuget")
    return metacache.serve(repo, lambda: _registration(repo, rest), package=rest.split("/", 1)[0].lower())


def _registration(repo, rest):
    if repo.is_proxy:
        if ".." in rest or not re.match(r"^[A-Za-z0-9._/-]+\.json$", rest):
            abort(404)
        rf = cached_metadata(repo, f"registration/{rest}", f"{_upstream(repo, 'registration')}{rest}",
                             transform=_rewriter(repo))
        if rf is None:
            abort(404)
        return Response(read_metadata(rf), content_type="application/json")
    parts = rest.split("/")
    if len(parts) != 2:
        abort(404)
    lid = parts[0].lower()
    pkg = Package.query.filter_by(repository_id=repo.id, name=lid).first()
    if pkg is None:
        abort(404)
    versions = sorted((v for v in pkg.versions if not v.is_blocked()), key=lambda v: version_key(v.version))
    if parts[1] != "index.json":
        v = next((v for v in versions if f"{v.version}.json" == parts[1].lower()), None)
        if v is None:
            abort(404)
        leaf = _leaf(repo, pkg, v)
        return jsonify({**leaf, "listed": True})
    if not versions:
        abort(404)
    b = _b(repo)
    page = {"@id": f"{b}/registration/{lid}/index.json#page", "count": len(versions),
            "lower": versions[0].version, "upper": versions[-1].version,
            "items": [_leaf(repo, pkg, v) for v in versions]}
    return jsonify({"@id": f"{b}/registration/{lid}/index.json", "count": 1, "items": [page]})


@bp.get("/<repo_name>/query")
def search(repo_name):
    repo, _ = load_repo(repo_name, "nuget")
    return metacache.serve(repo, lambda: _search(repo))


def _search(repo):
    if repo.is_proxy:
        r = upstream_get(_upstream(repo, "search"), repo=repo, params=request.args)
        if r.status_code != 200:
            return json_error(502, f"upstream search returned {r.status_code}")
        return Response(_rewriter(repo)(r.content), content_type="application/json")
    q = (request.args.get("q") or "").strip().lower()
    skip, take = request.args.get("skip", 0, type=int), min(request.args.get("take", 20, type=int), 1000)
    prerelease = request.args.get("prerelease", "false").lower() == "true"
    query = Package.query.filter_by(repository_id=repo.id)
    if q:
        query = query.filter(Package.name.contains(q.split(":")[-1]))
    data = []
    for pkg in query.order_by(Package.name).all():
        versions = sorted((v for v in pkg.versions if not v.is_blocked() and (prerelease or "-" not in v.version)),
                          key=lambda v: version_key(v.version))
        if not versions:
            continue
        latest = versions[-1]
        b = _b(repo)
        data.append({"@id": f"{b}/registration/{pkg.name}/index.json", "@type": "Package",
                     "registration": f"{b}/registration/{pkg.name}/index.json", "id": pkg.display_name,
                     "version": (latest.meta or {}).get("original_version") or latest.version,
                     "description": (latest.meta or {}).get("description") or "",
                     "authors": [(latest.meta or {}).get("authors") or ""], "totalDownloads": sum(v.download_count for v in versions),
                     "versions": [{"version": v.version, "downloads": v.download_count,
                                   "@id": f"{b}/registration/{pkg.name}/{v.version}.json"} for v in versions]})
    return jsonify({"totalHits": len(data), "data": data[skip:skip + take]})


# --- push / delete ---------------------------------------------------------------------------------------

@bp.route("/<repo_name>/api/v2/package", methods=["PUT", "POST"])
@bp.route("/<repo_name>/api/v2/package/", methods=["PUT", "POST"])
def push(repo_name):
    repo, user = load_repo(repo_name, "nuget", write=True)
    stream = upload_stream("package")
    quota_check(repo, user, request.content_length)
    with storage.spool_stream(stream) as sp:
        try:
            spec = read_nuspec(sp.path)
        except ValueError as exc:
            return json_error(400, str(exc))
        lid, lver = spec["id"].lower(), normalize_version(spec["version"])
        path = f"{lid}/{lver}/{lid}.{lver}.nupkg"
        if find_file(repo, path) is not None and not repo.allow_redeploy:
            return json_error(409, f"{spec['id']} {spec['version']} already exists")
        quota_check(repo, user, sp.size)
        digest, size = sp.commit()
    _register(repo, spec, path, digest, size, user.username)
    AuditEvent.log(user.username, "nuget.push", f"{repo.name}/{spec['id']}@{lver}")
    db.session.commit()
    uploaded(repo, user, size)
    return Response(status=201)


@bp.delete("/<repo_name>/api/v2/package/<pid>/<ver>")
def delete(repo_name, pid, ver):
    repo, user = load_repo(repo_name, "nuget", write=True)
    lid, lver = pid.lower(), normalize_version(ver) if VERSION_RE.match(ver) else ver.lower()
    f = find_file(repo, f"{lid}/{lver}/{lid}.{lver}.nupkg")
    if f is None:
        return json_error(404, "package not found")
    remove_file(f)
    RepoFile.query.filter_by(repository_id=repo.id, path=f"nuspec/{lid}/{lver}.nuspec").delete()
    AuditEvent.log(user.username, "nuget.delete", f"{repo.name}/{pid}@{lver}")
    db.session.commit()
    return Response(status=204)
