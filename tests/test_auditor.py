"""Security auditor: read everything (incl. private), reports, audit log, SBOMs – no downloads, no changes."""
import io
import json

from app.extensions import db
from app.models import User, Version
from tests.test_registries import basic, make_tgz, make_wheel


def test_security_auditor_role(app):
    with app.app_context():
        u = User(username="audrey", role="auditor")
        u.set_password("audrey-pass")
        db.session.add(u)
        db.session.commit()
    c = app.test_client()
    c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
        ":action": "file_upload", "name": "demo-pkg", "version": "1.0.0",
        "content": (io.BytesIO(make_wheel()), "demo_pkg-1.0.0-py3-none-any.whl")})
    with app.app_context():
        v = Version.query.one()
        v.scan_status, v.sbom_key = "done", "x.cdx.json"
        from app import storage
        storage.write_sbom(v.id, json.dumps({"bomFormat": "CycloneDX"}).encode())
        v.sbom_key = f"{v.id}.cdx.json"
        vid = v.id
        db.session.commit()
    aud = basic("audrey", "audrey-pass")

    # no package downloads through the client protocols
    assert c.get("/pypi/py/simple/demo-pkg/", headers=aud).status_code == 403
    assert c.get("/pypi/py/files/demo-pkg/demo_pkg-1.0.0-py3-none-any.whl", headers=aud).status_code == 403
    assert c.get("/npm/js/anything", headers=aud).status_code == 403
    assert c.get("/v2/img/x/manifests/latest", headers=aud).status_code == 403
    # no writes
    assert c.post("/pypi/py/", headers=aud, data={":action": "file_upload"}).status_code == 403
    tgz = make_tgz("x", "1.0.0")
    assert c.put("/npm/js/x", headers=aud, json={"name": "x", "versions": {"1.0.0": {}},
                                                 "_attachments": {"x-1.0.0.tgz": {"data": ""}}}).status_code == 403
    assert tgz

    # read-only API: metadata, vulnerabilities, SBOM, reports, users
    tok = c.post("/api/v1/tokens", headers=aud, json={"name": "audit"}).json["token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert c.get(f"/api/v1/versions/{vid}", headers=h).status_code == 200
    assert c.get(f"/api/v1/versions/{vid}/vulnerabilities", headers=h).status_code == 200
    sbom = c.get(f"/api/v1/versions/{vid}/sbom", headers=h)
    assert sbom.status_code == 200 and sbom.json["bomFormat"] == "CycloneDX"
    for url in ["/api/v1/reports/downloads", "/api/v1/reports/usage", "/api/v1/users", "/api/v1/scanner",
                "/api/v1/notifications"]:
        assert c.get(url, headers=h).status_code == 200, url
    # ... but no changes
    assert c.post("/api/v1/repositories", headers=h, json={"name": "n", "format": "npm"}).status_code == 403
    assert c.patch("/api/v1/repositories/py", headers=h, json={"public": True}).status_code == 403
    assert c.post(f"/api/v1/versions/{vid}/scan", headers=h).status_code == 403
    assert c.delete(f"/api/v1/versions/{vid}", headers=h).status_code == 403
    assert c.put("/api/v1/scanner/settings", headers=h, json={"rescan_interval_hours": 1}).status_code == 403
    assert c.put("/api/v1/network", headers=h, json={}).status_code == 403
    assert c.post("/api/v1/users", headers=h, json={"username": "z", "password": "zzzzzzzz"}).status_code == 403

    # UI: reports, audit log, SBOM yes – administration no
    c.post("/login", data={"username": "audrey", "password": "audrey-pass"})
    for url in ["/", "/repos/py", f"/versions/{vid}", "/vulnerabilities", "/reports/", "/reports/usage",
                "/reports/downloads", "/reports/downloads?export=csv", "/audit", "/docs/guides"]:
        assert c.get(url).status_code == 200, url
    assert c.get(f"/versions/{vid}/sbom").status_code == 200
    for url in ["/users", "/admin/scanner", "/admin/notifications", "/admin/network", "/repos/new", "/repos/py/edit"]:
        assert c.get(url).status_code == 403, url
    assert c.post(f"/versions/{vid}/rescan").status_code == 403
    page = c.get("/").data
    assert b"Audit log" in page and b"Package inventory" in page and b"Network" not in page
    version_page = c.get(f"/versions/{vid}").data
    assert b"Pulled by" in version_page and b"Delete" not in version_page
