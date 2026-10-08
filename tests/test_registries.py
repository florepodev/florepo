import base64
import hashlib
import io
import json
import tarfile
import zipfile

from app.extensions import db
from app.models import DownloadEvent, Repository, User, Version


def basic(user="admin", pw="admin-pass"):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


def make_wheel(name="demo_pkg", version="1.0.0"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{name}/__init__.py", "x = 1\n")
        zf.writestr(f"{name}-{version}.dist-info/METADATA",
                    f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
    return buf.getvalue()


# --- PyPI ---------------------------------------------------------------------

def test_pypi_upload_index_download_and_reporting(app):
    c = app.test_client()
    data = make_wheel()
    resp = c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
        ":action": "file_upload", "name": "demo-pkg", "version": "1.0.0", "summary": "demo",
        "sha256_digest": hashlib.sha256(data).hexdigest(),
        "content": (io.BytesIO(data), "demo_pkg-1.0.0-py3-none-any.whl"),
    })
    assert resp.status_code == 200, resp.data

    # duplicate upload rejected unless redeploy allowed
    with app.app_context():
        Repository.query.filter_by(name="py").first().allow_redeploy = False
        db.session.commit()
    dup = c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
        ":action": "file_upload", "name": "demo-pkg", "version": "1.0.0",
        "content": (io.BytesIO(data), "demo_pkg-1.0.0-py3-none-any.whl")})
    assert dup.status_code == 409

    assert c.get("/pypi/py/simple/").status_code == 401  # private repo
    idx = c.get("/pypi/py/simple/demo-pkg/", headers=basic("alice", "alice-pass"))
    assert idx.status_code == 200
    assert b"demo_pkg-1.0.0-py3-none-any.whl#sha256=" in idx.data

    js = c.get("/pypi/py/simple/demo-pkg/", headers={**basic(), "Accept": "application/vnd.pypi.simple.v1+json"})
    assert js.json["files"][0]["hashes"]["sha256"] == hashlib.sha256(data).hexdigest()

    dl = c.get("/pypi/py/files/demo-pkg/demo_pkg-1.0.0-py3-none-any.whl", headers=basic("alice", "alice-pass"))
    assert dl.status_code == 200 and dl.data == data

    with app.app_context():
        ev = DownloadEvent.query.one()
        assert ev.username == "alice" and ev.package_name == "demo-pkg" and ev.version_name == "1.0.0"
        assert Version.query.one().scan_status == "pending"

    # reader cannot upload
    assert c.post("/pypi/py/", headers=basic("alice", "alice-pass"),
                  data={":action": "file_upload"}).status_code == 403


def test_policy_blocks_vulnerable_download(app):
    c = app.test_client()
    data = make_wheel("bad_pkg", "0.1")
    c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
        ":action": "file_upload", "name": "bad-pkg", "version": "0.1",
        "content": (io.BytesIO(data), "bad_pkg-0.1-py3-none-any.whl")})
    with app.app_context():
        v = Version.query.one()
        v.scan_status, v.count_critical = "done", 1
        Repository.query.filter_by(name="py").first().block_severity = "HIGH"
        db.session.commit()
    resp = c.get("/pypi/py/files/bad-pkg/bad_pkg-0.1-py3-none-any.whl", headers=basic())
    assert resp.status_code == 403
    assert b"bad_pkg-0.1" not in c.get("/pypi/py/simple/bad-pkg/", headers=basic()).data


# --- npm ----------------------------------------------------------------------

def make_tgz(name, version):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        pj = json.dumps({"name": name, "version": version}).encode()
        info = tarfile.TarInfo("package/package.json")
        info.size = len(pj)
        tf.addfile(info, io.BytesIO(pj))
    return buf.getvalue()


def test_npm_login_publish_install(app):
    c = app.test_client()
    r = c.put("/npm/js/-/user/org.couchdb.user:admin", json={"name": "admin", "password": "admin-pass"})
    assert r.status_code == 201
    token = r.json["token"]
    auth = {"Authorization": f"Bearer {token}"}
    assert c.get("/npm/js/-/whoami", headers=auth).json == {"username": "admin"}

    name, version = "@acme/widget", "2.0.0"
    tgz = make_tgz(name, version)
    body = {
        "name": name, "dist-tags": {"latest": version},
        "versions": {version: {"name": name, "version": version, "description": "w",
                               "dependencies": {"left-pad": "^1.3.0"},
                               "dist": {"shasum": hashlib.sha1(tgz).hexdigest()}}},
        "_attachments": {f"{name}-{version}.tgz": {"data": base64.b64encode(tgz).decode(), "length": len(tgz)}},
    }
    assert c.put("/npm/js/@acme%2fwidget", json=body, headers=auth).status_code == 201

    doc = c.get("/npm/js/@acme%2fwidget", headers=auth).json
    assert doc["dist-tags"]["latest"] == version
    tarball = doc["versions"][version]["dist"]["tarball"]
    assert tarball == "http://localhost/npm/js/@acme/widget/-/widget-2.0.0.tgz"
    got = c.get("/npm/js/@acme/widget/-/widget-2.0.0.tgz", headers=auth)
    assert got.status_code == 200 and got.data == tgz

    assert c.get("/npm/js/-/package/@acme%2fwidget/dist-tags", headers=auth).json == {"latest": version}
    with app.app_context():
        assert DownloadEvent.query.one().username == "admin"


# --- Docker -------------------------------------------------------------------

def test_docker_push_pull(app):
    c = app.test_client()
    assert c.get("/v2/").status_code == 401
    assert c.get("/v2/", headers=basic()).status_code == 200

    layer = b"layer-bytes" * 100
    config = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}).encode()
    digests = {}
    for label, blob in [("layer", layer), ("config", config)]:
        start = c.post("/v2/img/app/web/blobs/uploads/", headers=basic())
        assert start.status_code == 202
        loc = start.headers["Location"]
        half = len(blob) // 2
        assert c.patch(loc, data=blob[:half], headers=basic()).status_code == 202
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        done = c.put(f"{loc}?digest={digest}", data=blob[half:], headers=basic())
        assert done.status_code == 201, done.data
        digests[label] = digest

    assert c.head(f"/v2/img/app/web/blobs/{digests['layer']}", headers=basic()).status_code == 200
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                   "size": len(config), "digest": digests["config"]},
        "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": len(layer), "digest": digests["layer"]}],
    }).encode()
    put = c.put("/v2/img/app/web/manifests/1.0", data=manifest, headers={
        **basic(), "Content-Type": "application/vnd.docker.distribution.manifest.v2+json"})
    assert put.status_code == 201, put.data
    mdigest = put.headers["Docker-Content-Digest"]

    # reader pulls: HEAD tag, GET by digest (containerd style)
    head = c.head("/v2/img/app/web/manifests/1.0", headers=basic("alice", "alice-pass"))
    assert head.headers["Docker-Content-Digest"] == mdigest
    got = c.get(f"/v2/img/app/web/manifests/{mdigest}", headers=basic("alice", "alice-pass"))
    assert got.status_code == 200 and got.data == manifest
    assert c.get("/v2/img/app/web/tags/list", headers=basic()).json["tags"] == ["1.0"]
    assert "img/app/web" in c.get("/v2/_catalog", headers=basic()).json["repositories"]

    # unknown blob in manifest is rejected
    bad = manifest.replace(digests["layer"].encode(), b"sha256:" + b"0" * 64)
    assert c.put("/v2/img/app/web/manifests/bad", data=bad, headers={
        **basic(), "Content-Type": "application/vnd.docker.distribution.manifest.v2+json"}).status_code == 400

    with app.app_context():
        ev = DownloadEvent.query.one()
        assert ev.username == "alice" and ev.package_name == "app/web" and ev.version_name == "1.0"


# --- UI / reports ---------------------------------------------------------------

def test_ui_pages_render(app):
    c = app.test_client()
    test_pypi = make_wheel()
    c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
        ":action": "file_upload", "name": "demo-pkg", "version": "1.0.0",
        "content": (io.BytesIO(test_pypi), "demo_pkg-1.0.0-py3-none-any.whl")})
    c.get("/pypi/py/files/demo-pkg/demo_pkg-1.0.0-py3-none-any.whl", headers=basic("alice", "alice-pass"))

    assert c.post("/login", data={"username": "admin", "password": "admin-pass"}).status_code == 302
    for url in ["/", "/repos", "/repos/py", "/repos/new", "/repos/py/edit", "/packages/1", "/versions/1",
                "/vulnerabilities", "/tokens", "/users", "/audit", "/reports/", "/reports/usage",
                "/reports/downloads", "/reports/users/alice", "/reports/?days=0&fmt=pypi"]:
        r = c.get(url)
        assert r.status_code == 200, (url, r.status_code)
    assert b"alice" in c.get("/reports/usage").data
    csv = c.get("/reports/downloads?export=csv")
    assert csv.mimetype == "text/csv" and b"demo-pkg" in csv.data


def test_download_log_pagination(app):
    """Regression: the pager macro used a context-only helper and crashed once there were >100 events."""
    with app.app_context():
        for i in range(130):
            db.session.add(DownloadEvent(format="pypi", repo_name="py", package_name=f"p{i}",
                                         version_name="1.0", username="alice"))
        db.session.commit()
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    for url in ["/reports/downloads", "/reports/downloads?page=2", "/audit"]:
        assert c.get(url).status_code == 200, url
    assert b"page=2" in c.get("/reports/downloads").data


def test_deployer_restricted_to_selected_repos(app):
    with app.app_context():
        u = User(username="carol", role="deployer", restrict_deploy=True)
        u.set_password("carol-pass")
        u.deploy_repos = [Repository.query.filter_by(name="py").one()]
        db.session.add(u)
        db.session.commit()
    c = app.test_client()
    carol = basic("carol", "carol-pass")
    ok = c.post("/pypi/py/", headers=carol, content_type="multipart/form-data", data={
        ":action": "file_upload", "name": "demo-pkg", "version": "1.0.0",
        "content": (io.BytesIO(make_wheel()), "demo_pkg-1.0.0-py3-none-any.whl")})
    assert ok.status_code == 200
    # not allowed: npm repo "js" and docker repo "img" – but reading still works
    tgz = make_tgz("x", "1.0.0")
    denied = c.put("/npm/js/x", headers=carol, json={
        "name": "x", "versions": {"1.0.0": {"name": "x", "version": "1.0.0"}},
        "_attachments": {"x-1.0.0.tgz": {"data": base64.b64encode(tgz).decode()}}})
    assert denied.status_code == 403
    assert c.post("/v2/img/app/blobs/uploads/", headers=carol).status_code == 403
    assert c.get("/v2/img/app/tags/list", headers=carol).status_code == 404  # readable, just empty

    # admin edits the scope through the UI
    admin = app.test_client()
    admin.post("/login", data={"username": "admin", "password": "admin-pass"})
    with app.app_context():
        uid = User.query.filter_by(username="carol").one().id
        js_id = Repository.query.filter_by(name="js").one().id
    assert admin.get(f"/users/{uid}").status_code == 200
    admin.post(f"/users/{uid}", data={"role": "deployer", "active": "on", "deploy_scope": "selected",
                                      "deploy_repos": [str(js_id)]})
    with app.app_context():
        assert [r.name for r in User.query.filter_by(username="carol").one().deploy_repos] == ["js"]
    assert c.post("/pypi/py/", headers=carol, data={":action": "file_upload"}).status_code == 403


def test_scanner_admin_page(app, monkeypatch):
    from app.blueprints import ui

    monkeypatch.setattr(ui, "trivy_info", lambda: {
        "Version": "0.74.0",
        "VulnerabilityDB": {"Version": 2, "UpdatedAt": "2026-10-06T06:12:41.123456789Z",
                            "NextUpdate": "2026-10-07T06:12:41.123456789Z",
                            "DownloadedAt": "2026-10-06T08:00:00.5Z"}})
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    page = c.get("/admin/scanner")
    assert page.status_code == 200 and b"2026-10-06 06:12" in page.data
    c.post("/admin/scanner", data={"trivy_db_interval_hours": "6", "rescan_interval_hours": "24",
                                   "trivy_java_db": "on"})
    c.post("/admin/scanner/update")
    with app.app_context():
        from app import settings
        assert settings.get("trivy_db_interval_hours") == 6
        assert settings.get("trivy_java_db") is True
        assert settings.get("rescan_after_db_update") is False
        assert settings.get("trivy_db_update_requested") is True


def test_scan_without_trivy_builds_sbom(app, monkeypatch):
    from app import scanner

    monkeypatch.setattr(scanner, "trivy_available", lambda: False)
    monkeypatch.setitem(app.config, "OSV_ENABLED", True)
    monkeypatch.setattr(scanner, "query_osv", lambda fmt, n, v: [{
        "vuln_id": "CVE-2099-0001", "pkg_name": n, "pkg_type": fmt, "installed_version": v,
        "fixed_version": "1.0.1", "severity": "HIGH", "title": "test", "url": "https://osv.dev/x",
        "aliases": [], "source": "osv"}])
    c = app.test_client()
    c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
        ":action": "file_upload", "name": "demo-pkg", "version": "1.0.0",
        "content": (io.BytesIO(make_wheel()), "demo_pkg-1.0.0-py3-none-any.whl")})
    with app.app_context():
        from app.worker import run_worker
        run_worker(once=True)
        v = Version.query.one()
        assert v.scan_status == "done", v.scan_error
        assert v.count_high == 1
        from app import storage
        sbom = json.loads(storage.read_sbom(v.sbom_key))
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["metadata"]["component"]["purl"] == "pkg:pypi/demo-pkg@1.0.0"


def test_npm_search_format(app):
    """npm >= 10 crashes on search results without a maintainers array."""
    c = app.test_client()
    tok = c.put("/npm/js/-/user/org.couchdb.user:admin", json={"name": "admin", "password": "admin-pass"}).json["token"]
    auth = {"Authorization": f"Bearer {tok}"}
    tgz = make_tgz("searchme", "1.0.0")
    c.put("/npm/js/searchme", headers=auth, json={
        "name": "searchme", "versions": {"1.0.0": {"name": "searchme", "version": "1.0.0", "keywords": ["e2e"]}},
        "_attachments": {"searchme-1.0.0.tgz": {"data": base64.b64encode(tgz).decode()}}})
    obj = c.get("/npm/js/-/v1/search?text=search", headers=auth).json["objects"][0]["package"]
    assert obj["name"] == "searchme" and obj["maintainers"] == [{"username": "admin"}]
    assert obj["keywords"] == ["e2e"] and obj["publisher"]["username"] == "admin"


def test_docker_pull_counting(app):
    """HEAD tag + GET digest is one pull; a second pull (e.g. a cache re-pull) is counted again."""
    c = app.test_client()
    config = json.dumps({"architecture": "amd64", "os": "linux"}).encode()
    cfg_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    c.post(f"/v2/img/count/blobs/uploads/?digest={cfg_digest}", data=config, headers=basic())
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                           "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                                      "size": len(config), "digest": cfg_digest}, "layers": []}).encode()
    digest = c.put("/v2/img/count/manifests/1", data=manifest, headers={
        **basic(), "Content-Type": "application/vnd.docker.distribution.manifest.v2+json"}).headers["Docker-Content-Digest"]

    def pull():
        c.head("/v2/img/count/manifests/1", headers=basic("alice", "alice-pass"))
        c.get(f"/v2/img/count/manifests/{digest}", headers=basic("alice", "alice-pass"))

    pull()
    with app.app_context():
        assert DownloadEvent.query.count() == 1
    pull()
    with app.app_context():
        assert DownloadEvent.query.count() == 2
    c.get(f"/v2/img/count/manifests/{digest}", headers=basic())  # pull by digest by another user
    with app.app_context():
        assert DownloadEvent.query.filter_by(username="admin").count() == 1
