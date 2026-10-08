"""PyPI repository: PEP 503 simple index + legacy upload API (twine) + caching proxy."""
import hmac
import re

from flask import Blueprint, Response, abort, current_app, render_template_string, request, url_for
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)

from .. import metacache, storage
from ..extensions import csrf, db
from ..models import ArtifactFile, AuditEvent, Package, Version
from .common import (
    blocked_response,
    get_or_create_package,
    get_or_create_version,
    load_repo,
    metadata_fresh,
    now_iso,
    quota_check,
    record_download,
    schedule_scan,
    uploaded,
    upstream_get,
)

bp = Blueprint("pypi", __name__, url_prefix="/pypi")
csrf.exempt(bp)

FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]*\.(whl|tar\.gz|zip)$")
SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"

INDEX_TPL = """<!DOCTYPE html>
<html><head><meta name="pypi:repository-version" content="1.0"><title>{{ title }}</title></head><body>
<h1>{{ title }}</h1>
{% for href, label, attrs in links %}<a href="{{ href }}"{% for k, v in attrs %} {{ k }}="{{ v }}"{% endfor %}>{{ label }}</a><br>
{% endfor %}</body></html>"""


def parse_dist_filename(filename):
    try:
        if filename.endswith(".whl"):
            name, ver, _, _ = parse_wheel_filename(filename)
        else:
            name, ver = parse_sdist_filename(filename)
    except (InvalidWheelFilename, InvalidSdistFilename):
        return None, None
    return canonicalize_name(name), str(ver)


def _visible_files(pkg):
    for ver in pkg.versions:
        if ver.is_blocked():
            continue
        for f in ver.files:
            yield ver, f


# --- upload -------------------------------------------------------------------

@bp.post("/<repo_name>/")
@bp.post("/<repo_name>/legacy/")
def upload(repo_name):
    repo, user = load_repo(repo_name, "pypi", write=True)
    if request.form.get(":action") != "file_upload":
        return Response("unsupported action\n", 400)
    name = request.form.get("name", "")
    version = request.form.get("version", "")
    content = request.files.get("content")
    if not (name and version and content and content.filename):
        return Response("missing name, version or content\n", 400)
    filename = content.filename.rsplit("/", 1)[-1]
    if not FILENAME_RE.match(filename):
        return Response("invalid filename\n", 400)
    fn_name, fn_version = parse_dist_filename(filename)
    norm = canonicalize_name(name)
    if fn_name != norm:
        return Response("filename does not match project name\n", 400)
    try:
        from packaging.version import Version as PV

        version = str(PV(version))
    except Exception:
        return Response("invalid version\n", 400)
    if fn_version != version:
        return Response("filename does not match version\n", 400)

    quota_check(repo, user, request.content_length)
    with storage.spool_stream(content.stream) as sp:
        expected = request.form.get("sha256_digest")
        if expected and not hmac.compare_digest(expected.lower(), sp.digest.split(":", 1)[1]):
            return Response("sha256 digest mismatch\n", 400)
        quota_check(repo, user, sp.size)
        digest, size = sp.commit()
    sha = digest.split(":", 1)[1]
    uploaded(repo, user, size)

    pkg = get_or_create_package(repo, norm, name)
    ver, _ = get_or_create_version(pkg, version)
    existing = ArtifactFile.query.filter_by(version_id=ver.id, filename=filename).first()
    if existing:
        if not repo.allow_redeploy:
            db.session.rollback()
            return Response("File already exists\n", 409)
        db.session.delete(existing)
        db.session.flush()

    meta_keys = [
        "summary", "description", "description_content_type", "author", "author_email",
        "maintainer", "license", "home_page", "requires_python", "keywords",
    ]
    meta = {k: request.form.get(k) for k in meta_keys if request.form.get(k)}
    meta["requires_dist"] = request.form.getlist("requires_dist")
    meta["classifiers"] = request.form.getlist("classifiers")
    ver.meta = {**(ver.meta or {}), **meta}
    ver.uploaded_by = user.username
    db.session.add(
        ArtifactFile(
            version=ver, filename=filename, sha256=sha, size=size,
            content_type="application/octet-stream",
            meta={"requires_python": meta.get("requires_python"),
                  "filetype": request.form.get("filetype")},
        )
    )
    schedule_scan(ver)
    AuditEvent.log(user.username, "pypi.upload", f"{repo.name}/{norm}/{filename}")
    db.session.commit()
    return Response("OK\n", 200)


# --- simple index -------------------------------------------------------------

@bp.get("/<repo_name>/simple/")
def simple_index(repo_name):
    repo, _ = load_repo(repo_name, "pypi")
    return metacache.serve(repo, lambda: _simple_index(repo))


def _simple_index(repo):
    pkgs = Package.query.filter_by(repository_id=repo.id).order_by(Package.name).all()
    if SIMPLE_JSON in request.headers.get("Accept", ""):
        return {"meta": {"api-version": "1.0"}, "projects": [{"name": p.display_name} for p in pkgs]}, 200, {
            "Content-Type": SIMPLE_JSON}
    links = [(url_for(".simple_project", repo_name=repo.name, project=p.name), p.display_name, []) for p in pkgs]
    return render_template_string(INDEX_TPL, title=f"Simple index: {repo.name}", links=links)


@bp.get("/<repo_name>/simple/<project>/")
def simple_project(repo_name, project):
    repo, _ = load_repo(repo_name, "pypi")
    norm = canonicalize_name(project)
    if norm != project:
        return Response(status=301, headers={
            "Location": url_for(".simple_project", repo_name=repo.name, project=norm)})
    return metacache.serve(repo, lambda: _simple_project(repo, norm), package=norm)


def _simple_project(repo, norm):
    files = []  # (filename, sha256, requires_python, yanked)
    if repo.is_proxy:
        files = _proxy_listing(repo, norm)
        if files is None:
            abort(404)
    else:
        pkg = Package.query.filter_by(repository_id=repo.id, name=norm).first()
        if pkg is None:
            abort(404)
        files = [(f.filename, f.sha256, (f.meta or {}).get("requires_python"), False, None)
                 for _, f in _visible_files(pkg)]

    if SIMPLE_JSON in request.headers.get("Accept", ""):
        out = []
        for fn, sha, rp, yanked, meta_sha in files:
            item = {"filename": fn,
                    "url": url_for(".download", repo_name=repo.name, project=norm, filename=fn, _external=True),
                    "hashes": {"sha256": sha} if sha else {},
                    "requires-python": rp, "yanked": yanked}
            if meta_sha:
                item["core-metadata"] = {"sha256": meta_sha}
            out.append(item)
        return {"meta": {"api-version": "1.1"}, "name": norm, "files": out}, 200, {"Content-Type": SIMPLE_JSON}

    links = []
    for fn, sha, rp, yanked, meta_sha in files:
        href = url_for(".download", repo_name=repo.name, project=norm, filename=fn)
        if sha:
            href += f"#sha256={sha}"
        attrs = []
        if rp:
            attrs.append(("data-requires-python", rp))
        if yanked:
            attrs.append(("data-yanked", ""))
        if meta_sha:
            attrs.append(("data-core-metadata", f"sha256={meta_sha}"))
            attrs.append(("data-dist-info-metadata", f"sha256={meta_sha}"))
        links.append((href, fn, attrs))
    return render_template_string(INDEX_TPL, title=f"Links for {norm}", links=links)


# --- downloads ----------------------------------------------------------------

@bp.get("/<repo_name>/files/<project>/<filename>")
def download(repo_name, project, filename):
    repo, user = load_repo(repo_name, "pypi")
    norm = canonicalize_name(project)
    if filename.endswith(".metadata") and repo.is_proxy and FILENAME_RE.match(filename[:-9]):
        return _proxy_metadata(repo, norm, filename[:-9])
    if not FILENAME_RE.match(filename):
        abort(404)
    f = (
        ArtifactFile.query.join(Version).join(Package)
        .filter(Package.repository_id == repo.id, Package.name == norm, ArtifactFile.filename == filename)
        .first()
    )
    cache_hit = True if repo.is_proxy else None
    if f is None and repo.is_proxy:
        f = _proxy_fetch(repo, norm, filename)
        cache_hit = False
    if f is None:
        abort(404)
    if f.version.is_blocked():
        return blocked_response(f.version)
    record_download(f.version, user, f.filename, cache_hit)
    db.session.commit()
    return storage.serve_blob(f.sha256, download_name=f.filename, as_attachment=True)


# --- proxy --------------------------------------------------------------------

def _proxy_listing(repo, norm, refresh=False):
    """Fetch the upstream simple page (JSON API) and cache the file->url mapping for PROXY_METADATA_TTL."""
    pkg = Package.query.filter_by(repository_id=repo.id, name=norm).first()
    upstream = (repo.upstream_url or "https://pypi.org").rstrip("/")
    cached = (pkg.meta or {}) if pkg else {}
    if not refresh and cached.get("upstream_files") and metadata_fresh(cached.get("upstream_fetched_at")):
        mapping = cached["upstream_files"]
    else:
        mapping = _refresh_listing(repo, norm, pkg, upstream)
        if mapping is None:
            return None
        pkg = Package.query.filter_by(repository_id=repo.id, name=norm).first()

    blocked = {f.filename for v in pkg.versions if v.is_blocked() for f in v.files}
    return [(fn, m["sha256"], m.get("requires_python"), m.get("yanked"), m.get("metadata_sha256"))
            for fn, m in mapping.items() if fn not in blocked]


def _refresh_listing(repo, norm, pkg, upstream):
    try:
        r = upstream_get(f"{upstream}/simple/{norm}/", repo=repo, headers={"Accept": SIMPLE_JSON})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()
        mapping = {}
        for item in data.get("files", []):
            fn = item["filename"]
            if not FILENAME_RE.match(fn):
                continue
            core = item.get("core-metadata", item.get("data-dist-info-metadata"))
            mapping[fn] = {
                "url": item["url"],
                "sha256": item.get("hashes", {}).get("sha256"),
                "requires_python": item.get("requires-python"),
                "yanked": bool(item.get("yanked")),
                # PEP 658: lets pip resolve from metadata only instead of downloading every candidate
                "metadata_sha256": core.get("sha256") if isinstance(core, dict) else None,
            }
        pkg = pkg or get_or_create_package(repo, norm, data.get("name", norm))
        pkg.meta = {**(pkg.meta or {}), "upstream_files": mapping, "upstream_fetched_at": now_iso()}
        db.session.commit()
        return mapping
    except Exception as exc:  # upstream down -> serve from cache
        db.session.rollback()
        current_app.logger.warning("pypi upstream error for %s: %s", norm, exc)
        pkg = Package.query.filter_by(repository_id=repo.id, name=norm).first()
        if pkg is None or not (pkg.meta or {}).get("upstream_files"):
            abort(Response("upstream unavailable\n", 502))
        return pkg.meta["upstream_files"]


def _proxy_metadata(repo, norm, filename):
    """Serve (and cache) the PEP 658 .metadata file of an upstream distribution."""
    pkg = Package.query.filter_by(repository_id=repo.id, name=norm).first()
    if pkg is None or filename not in (pkg.meta or {}).get("upstream_files", {}):
        if _proxy_listing(repo, norm, refresh=True) is None:
            abort(404)
        pkg = Package.query.filter_by(repository_id=repo.id, name=norm).first()
    info = (pkg.meta or {}).get("upstream_files", {}).get(filename)
    if not info or not info.get("metadata_sha256"):
        abort(404)
    sha = info["metadata_sha256"]
    if not storage.blob_exists(sha):
        r = upstream_get(info["url"] + ".metadata", repo=repo)
        if r.status_code != 200:
            abort(Response("upstream metadata unavailable\n", 502))
        digest, _ = storage.store_bytes(r.content)
        if digest != f"sha256:{sha}":
            abort(Response("upstream metadata checksum mismatch\n", 502))
    return storage.serve_blob(sha, mimetype="text/plain")


def _proxy_fetch(repo, norm, filename):
    pkg = Package.query.filter_by(repository_id=repo.id, name=norm).first()
    if pkg is None or filename not in (pkg.meta or {}).get("upstream_files", {}):
        if _proxy_listing(repo, norm, refresh=True) is None:
            return None
        pkg = Package.query.filter_by(repository_id=repo.id, name=norm).first()
    info = (pkg.meta or {}).get("upstream_files", {}).get(filename)
    if not info:
        return None
    fn_name, fn_version = parse_dist_filename(filename)
    if fn_name != norm or not fn_version:
        return None
    r = upstream_get(info["url"], repo=repo, stream=True)
    if r.status_code != 200:
        abort(Response("upstream download failed\n", 502))
    r.raw.decode_content = True
    digest, size = storage.store_stream(r.raw)
    sha = digest.split(":", 1)[1]
    if info.get("sha256") and info["sha256"] != sha:
        abort(Response("upstream checksum mismatch\n", 502))
    ver, _ = get_or_create_version(pkg, fn_version)
    ver.uploaded_by = "proxy"
    f = ArtifactFile(version=ver, filename=filename, sha256=sha, size=size,
                     meta={"requires_python": info.get("requires_python"), "upstream_url": info["url"]})
    db.session.add(f)
    schedule_scan(ver)
    db.session.commit()
    return f
