import io
import json

from app.extensions import db
from app.models import DownloadEvent, Notification, Version, Vulnerability, utcnow
from tests.test_registries import basic, make_wheel


def upload_wheel(c, name="demo_pkg", version="1.0.0"):
    resp = c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
        ":action": "file_upload", "name": name.replace("_", "-"), "version": version,
        "content": (io.BytesIO(make_wheel(name, version)), f"{name}-{version}-py3-none-any.whl")})
    assert resp.status_code == 200, resp.data


def bearer(c, user="admin", pw="admin-pass"):
    tok = c.post("/api/v1/tokens", headers=basic(user, pw), json={"name": "t"})
    assert tok.status_code == 201, tok.data
    return {"Authorization": f"Bearer {tok.json['token']}"}


def test_rest_api_end_to_end(app):
    c = app.test_client()
    h = bearer(c)
    assert c.get("/api/v1/whoami", headers=h).json["username"] == "admin"
    assert c.get("/api/v1/whoami").status_code == 401

    r = c.post("/api/v1/repositories", headers=h, json={"name": "npm-proxy", "format": "npm", "kind": "proxy"})
    assert r.status_code == 201 and r.json["upstream_url"] == "https://registry.npmjs.org"
    assert c.post("/api/v1/repositories", headers=h, json={"name": "Bad Name", "format": "npm"}).status_code == 400
    assert c.patch("/api/v1/repositories/py", headers=h, json={"block_severity": "critical"}).json["block_severity"] == "CRITICAL"

    upload_wheel(c)
    pkgs = c.get("/api/v1/repositories/py/packages?sort=name&dir=asc", headers=h).json
    assert pkgs["total"] == 1 and pkgs["items"][0]["name"] == "demo-pkg"
    vid = pkgs["items"][0]["latest"]["id"]
    v = c.get(f"/api/v1/versions/{vid}", headers=h).json
    assert v["files"][0]["filename"] == "demo_pkg-1.0.0-py3-none-any.whl" and v["scan"]["status"] == "pending"
    assert c.post(f"/api/v1/versions/{vid}/scan", headers=h).status_code == 202
    assert c.get(f"/api/v1/versions/{vid}/sbom", headers=h).status_code == 404  # not scanned yet

    # users: restricted deployer through the API
    u = c.post("/api/v1/users", headers=h, json={"username": "dave", "password": "dave-pass-1", "role": "deployer",
                                                 "restrict_deploy": True, "deploy_repos": ["js"]})
    assert u.status_code == 201 and u.json["deploy_repos"] == ["js"]
    assert c.post(f"/api/v1/versions/{vid}/scan", headers=basic("dave", "dave-pass-1")).status_code == 403
    assert c.patch(f"/api/v1/users/{u.json['id']}", headers=h, json={"deploy_repos": ["nope"]}).status_code == 400
    assert c.get("/api/v1/users", headers=basic("alice", "alice-pass")).status_code == 403

    # reports
    c.get("/pypi/py/files/demo-pkg/demo_pkg-1.0.0-py3-none-any.whl", headers=basic("alice", "alice-pass"))
    dl = c.get("/api/v1/reports/downloads?days=0", headers=h).json
    assert dl["items"][0]["user"] == "alice"
    usage = c.get("/api/v1/reports/usage", headers=h).json["items"]
    assert usage[0]["users"] == {"alice": 1}

    # scanner + notifications
    assert c.put("/api/v1/scanner/settings", headers=h, json={"trivy_db_interval_hours": 3}).json["settings"][
        "trivy_db_interval_hours"] == 3
    assert c.put("/api/v1/scanner/settings", headers=h, json={"trivy_db_interval_hours": -1}).status_code == 400
    assert c.post("/api/v1/scanner/db-update", headers=h).status_code == 202
    cfg = c.put("/api/v1/notifications", headers=h, json={"enabled": True, "recipients": ["sec@example.com"],
                                                          "threshold": "critical"}).json["config"]
    assert cfg["threshold"] == "CRITICAL" and cfg["only_new"] is True
    assert c.put("/api/v1/notifications", headers=h, json={"recipients": ["not-an-email"]}).status_code == 400

    assert c.delete(f"/api/v1/versions/{vid}", headers=h).status_code == 204
    assert c.delete("/api/v1/repositories/npm-proxy", headers=h).status_code == 204


def test_docs_and_openapi(app):
    c = app.test_client()
    spec = c.get("/api/openapi.json").json
    assert spec["openapi"].startswith("3.1") and "/api/v1/repositories" in spec["paths"]
    assert "/api/v1/notifications" in spec["paths"]
    page = c.get("/docs")
    assert page.status_code == 200
    for text in [b"Docker registry", b"/api/v1/reports/downloads", b"Notifications", b"curl -H"]:
        assert text in page.data


def test_x_accel_redirect_behind_nginx(app):
    app.config["ACCEL_REDIRECT"] = True
    c = app.test_client()
    upload_wheel(c)
    r = c.get("/pypi/py/files/demo-pkg/demo_pkg-1.0.0-py3-none-any.whl", headers=basic())
    assert r.status_code == 200 and r.data == b""
    assert r.headers["X-Accel-Redirect"].startswith("/_storage/blobs/sha256/")
    assert "demo_pkg-1.0.0-py3-none-any.whl" in r.headers["Content-Disposition"]


def test_server_side_sorting(app):
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    with app.app_context():
        for name in ["zeta", "alpha", "mid"]:
            db.session.add(DownloadEvent(format="npm", repo_name="js", package_name=name, version_name="1",
                                         username="bob"))
        db.session.commit()
    asc = c.get("/reports/downloads?sort=package&dir=asc").data
    assert asc.index(b"alpha") < asc.index(b"mid") < asc.index(b"zeta")
    desc = c.get("/reports/downloads?sort=package&dir=desc").data
    assert desc.index(b"zeta") < desc.index(b"alpha")
    upload_wheel(c, "aaa_pkg")
    upload_wheel(c, "zzz_pkg")
    for key in ["name", "latest", "security", "versions", "created", "updated"]:
        assert c.get(f"/repos/py?sort={key}&dir=asc").status_code == 200, key
    page = c.get("/repos/py?sort=name&dir=desc").data
    assert page.index(b"zzz-pkg") < page.index(b"aaa-pkg")


def test_rescan_alert_email(app, monkeypatch):
    from app import notifications, settings
    from app.worker import run_worker

    sent = []
    monkeypatch.setattr(notifications, "send_mail", lambda to, subj, text, html=None: sent.append((to, subj, text)))
    app.config["SMTP_HOST"] = "smtp.example.com"

    findings = {"round": 0}

    def fake_scan(version):
        # 1st scan: one HIGH; re-scan: additionally a new CRITICAL
        Vulnerability.query.filter_by(version_id=version.id).delete()
        items = [("CVE-2099-0001", "HIGH")]
        if findings["round"] > 0:
            items.append(("CVE-2099-0002", "CRITICAL"))
        for vid, sev in items:
            db.session.add(Vulnerability(version_id=version.id, vuln_id=vid, pkg_name="demo", severity=sev,
                                         installed_version="1.0", fixed_version="1.1"))
        version.scan_status, version.scanned_at = "done", utcnow()
        findings["round"] += 1

    monkeypatch.setattr("app.worker.scan_version", fake_scan)
    c = app.test_client()
    upload_wheel(c)
    with app.app_context():
        settings.put("alerts", {"enabled": True, "recipients": ["sec@example.com"], "threshold": "HIGH"})
        db.session.commit()
        run_worker(once=True)          # first scan of a new upload -> no alert (include_uploads off)
        assert Notification.query.count() == 0 and not sent
        Version.query.one().request_scan()  # periodic re-scan with new signatures
        db.session.commit()
        run_worker(once=True)
        n = Notification.query.one()
        assert [f["id"] for f in n.findings] == ["CVE-2099-0002"]  # only the new finding
        assert n.sent_at is not None
    assert sent and sent[0][0] == ["sec@example.com"] and "CVE-2099-0002" in sent[0][2]
    assert "critical" in sent[0][1]

    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    page = c.get("/admin/notifications")
    assert page.status_code == 200 and b"CVE-2099-0002" in page.data
    r = c.post("/admin/notifications", data={"enabled": "on", "recipients": "a@example.com, b@example.com",
                                             "threshold": "CRITICAL", "only_new": "on"})
    assert r.status_code == 302
    with app.app_context():
        assert settings.get("alerts")["recipients"] == ["a@example.com", "b@example.com"]


def test_ui_is_english(app):
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    for url in ["/", "/repos", "/reports/", "/users", "/admin/scanner", "/admin/notifications", "/docs", "/tokens"]:
        html = c.get(url).data.decode()
        for german in ["Benutzer", "Speichern", "Schwachstellen", "Übersicht", "Paket", "Anmelden"]:
            assert german not in html, (url, german)
    assert json.loads(c.get("/api/openapi.json").data)["info"]["title"] == "Florepo API"


def test_proxy_metadata_ttl_cache(app, monkeypatch):
    from app.blueprints import pypi
    from app.models import Repository

    calls = []

    class FakeResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"name": "demo", "files": [{"filename": "demo-1.0-py3-none-any.whl",
                                               "url": "https://files.example/demo-1.0-py3-none-any.whl",
                                               "hashes": {"sha256": "a" * 64}}]}

    monkeypatch.setattr(pypi, "upstream_get", lambda url, **kw: calls.append(url) or FakeResp())
    with app.app_context():
        db.session.add(Repository(name="pyproxy", format="pypi", kind="proxy", upstream_url="https://pypi.example"))
        db.session.commit()
    c = app.test_client()
    for _ in range(3):
        r = c.get("/pypi/pyproxy/simple/demo/", headers=basic())
        assert r.status_code == 200 and b"demo-1.0-py3-none-any.whl" in r.data
    assert len(calls) == 1  # served from cache within PROXY_METADATA_TTL

    app.config["PROXY_METADATA_TTL"] = 0
    c.get("/pypi/pyproxy/simple/demo/", headers=basic())
    assert len(calls) == 2


def test_download_counts_are_aggregated_by_worker(app):
    from app.worker import aggregate_download_counts

    c = app.test_client()
    upload_wheel(c)
    with app.app_context():
        aggregate_download_counts()  # initialises the high-water mark
    for _ in range(3):
        c.get("/pypi/py/files/demo-pkg/demo_pkg-1.0.0-py3-none-any.whl", headers=basic("alice", "alice-pass"))
    with app.app_context():
        assert Version.query.one().download_count == 0  # no hot-row update on the request path
        aggregate_download_counts()
        assert Version.query.one().download_count == 3
        aggregate_download_counts()
        assert Version.query.one().download_count == 3  # idempotent


def test_token_prefix(app):
    c = app.test_client()
    new = c.post("/api/v1/tokens", headers=basic(), json={"name": "new"}).json["token"]
    assert new.startswith("flo_")
    assert c.get("/api/v1/whoami", headers={"Authorization": f"Bearer {new}"}).json["username"] == "admin"
    assert c.get("/v2/", headers=basic("admin", new)).status_code == 200


def test_repository_rescan_endpoint(app):
    """Regression: POST /repositories/{name}/scan crashed (Query.update with join)."""
    c = app.test_client()
    h = bearer(c)
    upload_wheel(c, "a_pkg")
    upload_wheel(c, "b_pkg")
    with app.app_context():
        for v in Version.query:
            v.scan_status = "done"
        db.session.commit()
    r = c.post("/api/v1/repositories/py/scan", headers=h)
    assert r.status_code == 202 and r.json["queued"] == 2
    with app.app_context():
        assert {v.scan_status for v in Version.query} == {"pending"}
    assert c.post("/api/v1/repositories/js/scan", headers=h).json["queued"] == 0


def test_setup_guides_page(app):
    c = app.test_client()
    page = c.get("/docs/guides").data.decode()
    for text in ["Getting started", "Docker / OCI", "Debian / Ubuntu (apt)", "RPM (dnf / yum)", "Alpine (apk)",
                 "Proxy cache &amp; retention", "Outbound HTTP/HTTPS proxy", "Operations, upgrades &amp; migrations",
                 "db-revision", "WORKER_REPLICAS", "auditor", "Apache License, Version 2.0",
                 "Copyright 2026 Maximilian Thoma", "Lucide icons", "GPL-3.0-or-later"]:
        assert text in page, text
    # examples use this instance's URL and existing repository names (fixture: hosted docker repo "img")
    assert "docker push localhost/img/team/myapp:1.0" in page and "http://localhost/pypi/py/" in page
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    home = c.get("/").data.decode()
    assert "Setup guides" in home and "#life-buoy" in home and "Maximilian Thoma" in home


def test_static_assets_are_cache_busted(app):
    """Regression: browsers kept a 1-day cached app.css after an upgrade (missing classes, huge icons)."""
    c = app.test_client()
    page = c.get("/login").data.decode()
    import re
    m = re.search(r'/static/css/app\.css\?v=([0-9a-f]{12}|0)"', page)
    assert m, "app.css must carry a content hash"
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    home = c.get("/").data.decode()
    assert "/static/js/app.js?v=" in home and "/static/icons/lucide-sprite.svg?v=" in home
