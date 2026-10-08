"""Go module proxy (GOPROXY protocol) – hosted private modules and caching proxy (proxy.golang.org).

GOPROXY=https://<user>:<token>@host/go/<repo>
  GET /go/<repo>/<module>/@v/list | <version>.info | <version>.mod | <version>.zip
  GET /go/<repo>/<module>/@latest
  GET /go/<repo>/sumdb/<sumdb host>/…   (proxy repositories: checksum database pass-through)
Hosted upload: PUT /go/<repo>/<module>/@v/<version>.zip
  The zip may contain the module files at the root, below one directory or below <module>@<version>/
  (the layout `go mod download` expects); it is normalized server side. go.mod is taken from the zip.
Module paths use the GOPROXY case encoding: upper-case letters are sent as '!' + lower-case.
"""
import io
import re
import zipfile

from flask import Blueprint, Response, abort, jsonify, request

from .. import metacache, storage
from ..extensions import csrf, db
from ..models import AuditEvent, Package, utcnow
from .common import (add_file, blocked_response, cached_metadata, fetch_upstream_file, find_file,
                     get_or_create_package, get_or_create_version, json_error, load_repo, quota_check,
                     read_metadata, record_download, schedule_scan, upstream_get, uploaded)

bp = Blueprint("go", __name__, url_prefix="/go")
csrf.exempt(bp)

SEMVER_RE = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(\+incompatible)?$")
MODULE_RE = re.compile(r"^[a-z0-9.!_~-]+(/[A-Za-z0-9.!_~+-]+)*$")
MAX_ZIP = 500 * 1024 * 1024


def decode_path(escaped):
    """GOPROXY case encoding: 'github.com/!azure/sdk' -> 'github.com/Azure/sdk'."""
    return re.sub(r"!([a-z])", lambda m: m.group(1).upper(), escaped)


def encode_path(module):
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)


def semver_key(v):
    m = SEMVER_RE.match(v)
    if not m:
        return (0, 0, 0, 0, ())
    pre = m.group(4)
    ident = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")) if pre else ()
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, ident)


def parse_gomod(data):
    """(module path, [{"name", "version"}]) of a go.mod file."""
    text = data.decode("utf-8", errors="replace")
    module = None
    deps, in_block = [], False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("module "):
            module = line[7:].strip().strip('"')
        elif line.startswith("require ("):
            in_block = True
        elif in_block and line == ")":
            in_block = False
        elif in_block or line.startswith("require "):
            parts = (line[8:] if line.startswith("require ") else line).split()
            if len(parts) >= 2:
                deps.append({"name": parts[0].strip('"'), "version": parts[1]})
    return module, deps


def _ok(data, ctype="text/plain; charset=utf-8"):
    return Response(data, content_type=ctype)


def _not_found(msg="not found"):
    return Response(msg + "\n", 404, content_type="text/plain")


@bp.route("/<repo_name>/<path:path>", methods=["GET", "HEAD", "PUT"])
def handle(repo_name, path):
    if path.startswith("sumdb/"):
        return sumdb(repo_name, path)
    if path.endswith("/@latest"):
        escaped, what = path[: -len("/@latest")], "@latest"
    elif "/@v/" in path:
        escaped, what = path.split("/@v/", 1)
    else:
        abort(404)
    if not MODULE_RE.match(escaped) or ".." in escaped.split("/"):
        abort(404)
    if request.method == "PUT":
        if not what.endswith(".zip"):
            return json_error(400, "upload the module as <version>.zip – go.mod is taken from the archive")
        return upload(repo_name, escaped, what[:-4])
    repo, user = load_repo(repo_name, "go")
    module = decode_path(escaped)
    handler = _proxy if repo.is_proxy else _hosted
    args = (repo, user, escaped, module, what) if repo.is_proxy else (repo, user, module, what)
    if what in ("list", "@latest"):
        return metacache.serve(repo, lambda: handler(*args), package=module)
    return handler(*args)


# --- hosted -----------------------------------------------------------------------------------------------

def _visible_versions(repo, module):
    pkg = Package.query.filter_by(repository_id=repo.id, name=module).first()
    return [v for v in (pkg.versions if pkg else []) if not v.is_blocked() and v.files]


def _info(version):
    return {"Version": version.version, "Time": version.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")}


def _hosted(repo, user, module, what):
    if what == "list":
        versions = sorted((v.version for v in _visible_versions(repo, module)), key=semver_key)
        return _ok("".join(v + "\n" for v in versions))
    if what == "@latest":
        versions = _visible_versions(repo, module)
        if not versions:
            return _not_found()
        return jsonify(_info(max(versions, key=lambda v: semver_key(v.version))))
    version, _, ext = what.rpartition(".")
    if ext not in ("info", "mod", "zip"):
        return _not_found()
    f = find_file(repo, f"{module}/@v/{version}.{'mod' if ext == 'info' else ext}")
    if f is None:
        return _not_found(f"{module}@{version}: not found")
    if f.version.is_blocked():
        return blocked_response(f.version)
    if ext == "info":
        return jsonify(_info(f.version))
    if ext == "zip":
        if request.method == "GET":
            record_download(f.version, user, f.filename)
            db.session.commit()
        return storage.serve_blob(f"sha256:{f.sha256}", mimetype="application/zip")
    return Response(storage.read_blob(f"sha256:{f.sha256}"), content_type="text/plain; charset=utf-8")


def _normalize_zip(local_path, module, version):
    """Return (zip bytes or None if already in canonical layout, go.mod bytes). Raises ValueError."""
    prefix = f"{module}@{version}/"
    try:
        zf = zipfile.ZipFile(local_path)
    except zipfile.BadZipFile:
        raise ValueError("not a zip archive")
    with zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        if not names:
            raise ValueError("empty archive")
        if all(n.startswith(prefix) for n in names):
            strip = prefix
        elif "go.mod" in names:
            strip = ""
        else:
            top = {n.split("/", 1)[0] for n in names}
            if len(top) == 1 and f"{next(iter(top))}/go.mod" in names:
                strip = next(iter(top)) + "/"
            else:
                raise ValueError("go.mod not found at the module root of the archive")
        gomod = zf.read(strip + "go.mod")
        declared, _ = parse_gomod(gomod)
        if declared != module:
            raise ValueError(f"go.mod declares module {declared!r}, expected {module!r}")
        if strip == prefix:
            return None, gomod
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
            for n in sorted(names):
                rel = n[len(strip):]
                if rel.startswith(("vendor/", ".git/")) or "/vendor/" in rel:
                    continue
                dst.writestr(prefix + rel, zf.read(n))
        return out.getvalue(), gomod


def upload(repo_name, escaped, version):
    repo, user = load_repo(repo_name, "go", write=True)
    module = decode_path(escaped)
    if not SEMVER_RE.match(version):
        return json_error(400, "version must be a semantic version like v1.2.3 (with leading 'v')")
    major = int(SEMVER_RE.match(version).group(1))
    if major >= 2 and not version.endswith("+incompatible") and not re.search(rf"/v{major}$", module):
        return json_error(400, f"major version v{major} requires the module path to end with /v{major}")
    if find_file(repo, f"{module}/@v/{version}.zip") is not None and not repo.allow_redeploy:
        return json_error(409, f"{module}@{version} already exists (module versions are immutable)")
    quota_check(repo, user, request.content_length)
    with storage.spool_stream(request.stream) as sp:
        if sp.size > MAX_ZIP:
            return json_error(413, "module zip larger than 500 MB")
        try:
            repacked, gomod = _normalize_zip(sp.path, module, version)
        except ValueError as exc:
            return json_error(400, str(exc))
        if repacked is None:
            digest, size = sp.commit()
        else:
            digest, size = storage.store_bytes(repacked)
    quota_check(repo, user, size)
    mod_digest, mod_size = storage.store_bytes(gomod)
    _, deps = parse_gomod(gomod)
    pkg = get_or_create_package(repo, module)
    ver, _ = get_or_create_version(pkg, version)
    ver.uploaded_by = user.username
    ver.meta = {**(ver.meta or {}), "dependencies": deps}
    add_file(ver, f"{module}/@v/{version}.zip", digest, size, "application/zip")
    add_file(ver, f"{module}/@v/{version}.mod", mod_digest, mod_size, "text/plain")
    schedule_scan(ver)
    pkg.updated_at = utcnow()
    AuditEvent.log(user.username, "go.upload", f"{repo.name}/{module}@{version}")
    db.session.commit()
    uploaded(repo, user, size + mod_size)
    return jsonify({"ok": True, "module": module, "version": version, "size": size,
                    "repacked": repacked is not None}), 201


# --- proxy --------------------------------------------------------------------------------------------------

def _upstream(repo, rest):
    return f"{repo.upstream_url.rstrip('/')}/{rest}"


def _proxy(repo, user, escaped, module, what):
    if what in ("list", "@latest"):
        path = f"{escaped}/@v/list" if what == "list" else f"{escaped}/@latest"
        rf = cached_metadata(repo, path, _upstream(repo, path))
        if rf is None:
            return _not_found()
        data = read_metadata(rf)
        if what == "list":
            blocked = {v.version for v in _blocked_versions(repo, module)}
            if blocked:
                data = "".join(line + "\n" for line in data.decode().splitlines() if line.strip() not in blocked).encode()
            return _ok(data)
        return Response(data, content_type="application/json")
    version, _, ext = what.rpartition(".")
    if ext not in ("info", "mod", "zip"):
        return _not_found()
    immutable = bool(SEMVER_RE.match(version))
    pkg = Package.query.filter_by(repository_id=repo.id, name=module).first()
    if pkg is not None:
        cached = next((v for v in pkg.versions if v.version == version), None)
        if cached is not None and cached.is_blocked():
            return blocked_response(cached)
    if ext in ("info", "mod"):
        path = f"{escaped}/@v/{what}"
        rf = cached_metadata(repo, path, _upstream(repo, path), ttl=not immutable)
        if rf is None:
            return _not_found(f"{module}@{version}: not found")
        return Response(read_metadata(rf), content_type="application/json" if ext == "info" else "text/plain")
    f = find_file(repo, f"{module}/@v/{version}.zip")
    cache_hit = True
    if f is None:
        if not immutable:
            return _not_found("only semantic versions can be downloaded through the cache")
        sp = fetch_upstream_file(repo, _upstream(repo, f"{escaped}/@v/{what}"))
        if sp is None:
            return _not_found(f"{module}@{version}: not found")
        with sp:
            try:
                with zipfile.ZipFile(sp.path) as zf:
                    gomod = zf.read(f"{module}@{version}/go.mod")
                deps = parse_gomod(gomod)[1]
            except (zipfile.BadZipFile, KeyError):
                deps = []
            digest, size = sp.commit()
        pkg = get_or_create_package(repo, module)
        ver, _ = get_or_create_version(pkg, version)
        ver.uploaded_by = "proxy"
        ver.meta = {**(ver.meta or {}), "dependencies": deps}
        f = add_file(ver, f"{module}/@v/{version}.zip", digest, size, "application/zip")
        schedule_scan(ver)
        db.session.commit()
        cache_hit = False
    if request.method == "GET":
        record_download(f.version, user, f.filename, cache_hit)
        db.session.commit()
    return storage.serve_blob(f"sha256:{f.sha256}", mimetype="application/zip")


def _blocked_versions(repo, module):
    pkg = Package.query.filter_by(repository_id=repo.id, name=module).first()
    return [v for v in (pkg.versions if pkg else []) if v.is_blocked()]


SUMDB_HOSTS = {"sum.golang.org", "sum.golang.google.cn"}  # only these are proxied (no open relay)


def sumdb(repo_name, path):
    """Checksum database proxy (`<proxy>/sumdb/sum.golang.org/...`): the go command asks
    `<proxy>/sumdb/<db>/supported` and then fetches lookups and tiles through the proxy, so GOSUMDB
    verification works without direct internet access. Responses are passed through unchanged (they are
    signed by the checksum database)."""
    repo, _ = load_repo(repo_name, "go")
    m = re.match(r"^sumdb/([A-Za-z0-9.-]+)/([A-Za-z0-9/._@!+~-]*)$", path)
    if not repo.is_proxy or not m or m.group(1) not in SUMDB_HOSTS or ".." in path:
        return Response(status=404)
    if m.group(2) == "supported":
        return Response(status=200)
    r = upstream_get(f"https://{m.group(1)}/{m.group(2)}", repo=repo)
    return Response(r.content, r.status_code, content_type=r.headers.get("Content-Type", "text/plain"))
