"""Maven 2 repository layout (Maven, Gradle, sbt, Leiningen, ...): hosted (mvn deploy) and proxy (Maven Central).

URLs: /maven/<repo>/<group path>/<artifactId>/<version>/<artifactId>-<version>[-classifier].<ext>
* artifact-level maven-metadata.xml of hosted repositories is generated from the stored versions,
  SNAPSHOT (version-level) and plugin (group-level) metadata uploaded by the client is stored as is
* .md5 / .sha1 / .sha256 / .sha512 checksums are served for every file (uploaded checksum files are ignored)
"""
import hashlib
import re
import xml.etree.ElementTree as ET

from flask import Blueprint, Response, abort, request

from .. import metacache, storage
from ..extensions import csrf, db
from ..models import AuditEvent, Package, RepoFile, Version, utcnow
from .common import (add_file, blocked_response, cached_metadata, fetch_upstream_file, file_checksums, find_file,
                     get_or_create_package, get_or_create_version, json_error, load_repo, quota_check,
                     read_metadata, record_download, safe_path, schedule_scan, uploaded)

bp = Blueprint("maven", __name__, url_prefix="/maven")
csrf.exempt(bp)

CHECKSUMS = ("md5", "sha1", "sha256", "sha512")
METADATA = "maven-metadata.xml"
CONTENT_TYPES = {".pom": "application/xml", ".xml": "application/xml", ".jar": "application/java-archive",
                 ".war": "application/java-archive", ".module": "application/json", ".asc": "text/plain"}


def content_type(filename):
    for ext, ctype in CONTENT_TYPES.items():
        if filename.endswith(ext):
            return ctype
    return "application/octet-stream"


def parse_path(path):
    """{'kind': 'metadata', 'dir'} | {'kind': 'artifact', 'group', 'artifact', 'version', 'filename'} | None"""
    parts = path.split("/")
    filename = parts[-1]
    if filename == METADATA:
        return {"kind": "metadata", "dir": "/".join(parts[:-1])}
    if len(parts) < 4:
        return None
    group, artifact, version = ".".join(parts[:-3]), parts[-3], parts[-2]
    if not filename.startswith(f"{artifact}-"):
        return None
    return {"kind": "artifact", "group": group, "artifact": artifact, "version": version, "filename": filename}


def _split_checksum(path):
    for algo in CHECKSUMS:
        if path.endswith(f".{algo}"):
            return path[: -len(algo) - 1], algo
    return path, None


def _digest_of(data, algo):
    return hashlib.new(algo, data).hexdigest()


@bp.route("/<repo_name>/<path:path>", methods=["GET", "HEAD", "PUT"])
def handle(repo_name, path):
    if request.method == "PUT":
        return upload(repo_name, path)
    return get(repo_name, path)


@bp.get("/<repo_name>/")
def root(repo_name):
    repo, _ = load_repo(repo_name, "maven")
    return Response(f"Florepo Maven repository '{repo.name}' ({repo.kind})\n", content_type="text/plain")


# --- downloads ---------------------------------------------------------------------------------------

def _send(data, ctype):
    return Response(data if request.method == "GET" else b"", content_type=ctype,
                    headers={"Content-Length": str(len(data))})


def get(repo_name, path):
    repo, user = load_repo(repo_name, "maven")
    path = safe_path(path)
    base, algo = _split_checksum(path)
    info = parse_path(base)

    if info and info["kind"] == "metadata":
        def render():
            data = _metadata(repo, base, info["dir"])
            if data is None:
                abort(404)
            return _send(_digest_of(data, algo).encode() if algo else data, "text/plain" if algo else "application/xml")
        return metacache.serve(repo, render)

    f = find_file(repo, base)
    cache_hit = True if repo.is_proxy else None
    if f is None and repo.is_proxy:
        if algo:  # checksum of an artifact that is not cached yet: pass the upstream's through
            rf = cached_metadata(repo, path, _upstream(repo, path))
            if rf is None:
                abort(404)
            return _send(read_metadata(rf), "text/plain")
        f = _proxy_fetch(repo, base, info)
        cache_hit = False
    if f is None:
        abort(404)
    if algo:
        value = f.sha256 if algo == "sha256" else (f.meta or {}).get(algo)
        if value is None:
            with storage.local_file(f"sha256:{f.sha256}") as p:
                value = file_checksums(p)[algo]
        return _send(value.encode(), "text/plain")
    if f.version.is_blocked():
        return blocked_response(f.version)
    if request.method == "HEAD":
        return Response(status=200, content_type=f.content_type, headers={"Content-Length": str(f.size)})
    record_download(f.version, user, f.filename, cache_hit)
    db.session.commit()
    return storage.serve_blob(f"sha256:{f.sha256}", mimetype=f.content_type or "application/octet-stream")


def _upstream(repo, path):
    return f"{repo.upstream_url.rstrip('/')}/{path}"


def _metadata(repo, path, directory):
    if repo.is_proxy:
        rf = cached_metadata(repo, path, _upstream(repo, path))
        return _filter_blocked(repo, read_metadata(rf)) if rf else None
    rf = RepoFile.query.filter_by(repository_id=repo.id, path=path).first()
    if rf is not None:  # uploaded SNAPSHOT / plugin metadata
        return read_metadata(rf)
    parts = directory.split("/")
    if len(parts) < 2:
        return None
    pkg = Package.query.filter_by(repository_id=repo.id, name=f"{'.'.join(parts[:-1])}:{parts[-1]}").first()
    if pkg is None:
        return None
    return generate_metadata(pkg)


def generate_metadata(pkg):
    group, _, artifact = pkg.name.partition(":")
    versions = sorted((v for v in pkg.versions if not v.is_blocked()), key=lambda v: v.created_at)
    if not versions:
        return None
    root = ET.Element("metadata")
    ET.SubElement(root, "groupId").text = group
    ET.SubElement(root, "artifactId").text = artifact
    vers = ET.SubElement(root, "versioning")
    ET.SubElement(vers, "latest").text = versions[-1].version
    releases = [v for v in versions if not v.version.endswith("-SNAPSHOT")]
    if releases:
        ET.SubElement(vers, "release").text = releases[-1].version
    lst = ET.SubElement(vers, "versions")
    for v in versions:
        ET.SubElement(lst, "version").text = v.version
    ET.SubElement(vers, "lastUpdated").text = max(v.updated_at or v.created_at for v in versions).strftime("%Y%m%d%H%M%S")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8") + b"\n"


def _filter_blocked(repo, data):
    """Remove blocked versions from proxied artifact-level metadata."""
    blocked = {v.version for v in Version.query.join(Package).filter(Package.repository_id == repo.id)
               if v.is_blocked()}
    if not blocked:
        return data
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return data
    lst = root.find("versioning/versions")
    if lst is None:
        return data
    for el in list(lst):
        if (el.text or "").strip() in blocked:
            lst.remove(el)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8") + b"\n"


def _proxy_fetch(repo, path, info):
    if not info or info["kind"] != "artifact":
        # e.g. archetype-catalog.xml: cache like metadata
        rf = cached_metadata(repo, path, _upstream(repo, path))
        if rf is None:
            return None
        abort(Response(read_metadata(rf) if request.method == "GET" else b"", content_type=content_type(path)))
    sp = fetch_upstream_file(repo, _upstream(repo, path))
    if sp is None:
        return None
    with sp:
        sums = file_checksums(sp.path)
        pom = _read_pom(sp.path) if info["filename"].endswith(".pom") else None
        digest, size = sp.commit()
    return _register(repo, info, path, digest, size, sums, pom, "proxy")


# --- uploads -----------------------------------------------------------------------------------------------

def upload(repo_name, path):
    repo, user = load_repo(repo_name, "maven", write=True)
    path = safe_path(path)
    base, algo = _split_checksum(path)
    if algo:
        request.get_data()  # checksums are computed by the server
        return Response(status=201)
    info = parse_path(base)
    if info is None:
        return json_error(400, "path must follow the Maven layout <group>/<artifactId>/<version>/<artifactId>-<version>.<ext>")
    if info["kind"] == "metadata":
        return _upload_metadata(repo, user, path, info["dir"])

    snapshot = info["version"].endswith("-SNAPSHOT")
    existing = find_file(repo, path)
    if existing is not None and not (repo.allow_redeploy or snapshot):
        request.get_data()
        return json_error(409, f"{path} already exists (release versions are immutable in this repository)")
    quota_check(repo, user, request.content_length)
    with storage.spool_stream(request.stream) as sp:
        quota_check(repo, user, sp.size)
        sums = file_checksums(sp.path)
        pom = _read_pom(sp.path) if info["filename"].endswith(".pom") else None
        digest, size = sp.commit()
    f = _register(repo, info, path, digest, size, sums, pom, user.username)
    AuditEvent.log(user.username, "maven.deploy", f"{repo.name}/{path}")
    db.session.commit()
    uploaded(repo, user, size)
    return Response(status=201, headers={"Location": f"/maven/{repo.name}/{f.path}"})


def _upload_metadata(repo, user, path, directory):
    data = request.get_data()
    parts = directory.split("/")
    if len(parts) >= 2:
        pkg = Package.query.filter_by(repository_id=repo.id, name=f"{'.'.join(parts[:-1])}:{parts[-1]}").first()
        if pkg is not None:
            return Response(status=201)  # artifact-level metadata is generated by the server
    try:
        ET.fromstring(data)
    except ET.ParseError:
        return json_error(400, "maven-metadata.xml is not well-formed XML")
    digest, size = storage.store_bytes(data)
    rf = RepoFile.query.filter_by(repository_id=repo.id, path=path).first()
    if rf is None:
        rf = RepoFile(repository_id=repo.id, path=path)
        db.session.add(rf)
    rf.digest, rf.size, rf.content_type, rf.fetched_at = digest, size, "application/xml", utcnow()
    db.session.commit()
    return Response(status=201)


def _register(repo, info, path, digest, size, sums, pom, uploaded_by):
    name = f"{info['group']}:{info['artifact']}"
    pkg = get_or_create_package(repo, name)
    ver, _ = get_or_create_version(pkg, info["version"])
    ver.uploaded_by = uploaded_by
    if pom:
        ver.meta = {**(ver.meta or {}), **pom}
    f = add_file(ver, path, digest, size, content_type(info["filename"]), meta=sums)
    if info["filename"].endswith((".jar", ".war", ".ear", ".aar", ".pom")):
        schedule_scan(ver)
    pkg.updated_at = utcnow()
    db.session.commit()
    return f


POM_NS = re.compile(r"^\{[^}]*\}")


def _read_pom(local_path):
    """name, description, packaging, licenses and declared dependencies of a POM."""
    try:
        with open(local_path, "rb") as fh:
            root = ET.fromstring(fh.read(5 * 1024 * 1024))
    except (ET.ParseError, OSError):
        return None

    def strip(el):
        for e in el.iter():
            e.tag = POM_NS.sub("", e.tag) if isinstance(e.tag, str) else e.tag
        return el

    root = strip(root)

    def text(el, tag):
        child = el.find(tag)
        return (child.text or "").strip() if child is not None and child.text else None

    deps = []
    for d in root.findall("dependencies/dependency"):
        g, a, v = text(d, "groupId"), text(d, "artifactId"), text(d, "version")
        if g and a and (text(d, "scope") or "compile") in ("compile", "runtime"):
            deps.append({"name": f"{g}:{a}", "version": v if v and "${" not in v else None})
    out = {"summary": text(root, "name") or text(root, "description"), "packaging": text(root, "packaging") or "jar",
           "license": ", ".join(filter(None, (text(lic, "name") for lic in root.findall("licenses/license")))) or None,
           "dependencies": deps[:500]}
    return {k: v for k, v in out.items() if v}
