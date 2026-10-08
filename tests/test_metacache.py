"""Metadata cache: hits, immediate invalidation on every kind of change, ETag / 304."""
import base64
import hashlib
import io

from app import metacache
from app.extensions import db
from app.models import Repository, Version, utcnow
from tests.test_formats import ALICE, add_repo, make_chart
from tests.test_registries import basic, make_tgz, make_wheel


def npm_publish(c, name, version):
    tgz = make_tgz(name, version)
    return c.put(f"/npm/js/{name}", headers=basic(), json={
        "name": name, "versions": {version: {"name": name, "version": version,
                                             "dist": {"shasum": hashlib.sha1(tgz).hexdigest()}}},
        "dist-tags": {"latest": version},
        "_attachments": {f"{name}-{version}.tgz": {"data": base64.b64encode(tgz).decode()}}})


def test_npm_packument_cached_and_invalidated(app):
    metacache.clear()
    c = app.test_client()
    assert npm_publish(c, "demo", "1.0.0").status_code in (200, 201)
    r1 = c.get("/npm/js/demo", headers=ALICE)
    r2 = c.get("/npm/js/demo", headers=ALICE)
    assert r1.headers["X-Florepo-Cache"] == "miss" and r2.headers["X-Florepo-Cache"] == "hit"
    assert r1.data == r2.data and r1.headers["ETag"] == r2.headers["ETag"]
    # conditional request -> 304 without body
    r = c.get("/npm/js/demo", headers={**ALICE, "If-None-Match": r1.headers["ETag"]})
    assert r.status_code == 304 and not r.data
    # publish -> the new version is visible immediately (no stale window)
    assert npm_publish(c, "demo", "1.1.0").status_code in (200, 201)
    r = c.get("/npm/js/demo", headers=ALICE)
    assert r.headers["X-Florepo-Cache"] == "miss" and "1.1.0" in r.json["versions"]
    assert c.get("/npm/js/demo", headers={**ALICE, "If-None-Match": r1.headers["ETag"]}).status_code == 200
    # a scan result that blocks a version removes it at once
    with app.app_context():
        v = Version.query.filter_by(version="1.1.0").one()
        v.scan_status, v.count_critical = "done", 2
        v.scanned_at = utcnow()
        v.package.repository.block_severity = "CRITICAL"
        db.session.commit()
    assert "1.1.0" not in c.get("/npm/js/demo", headers=ALICE).json["versions"]
    # a queued re-scan must not lift the block (the last result applies until a new one exists)
    with app.app_context():
        Version.query.filter_by(version="1.1.0").one().request_scan()
        db.session.commit()
    assert "1.1.0" not in c.get("/npm/js/demo", headers=ALICE).json["versions"]
    assert c.get("/npm/js/demo/-/demo-1.1.0.tgz", headers=ALICE).status_code == 403
    # repository policy change (unblock) is picked up as well
    with app.app_context():
        Repository.query.filter_by(name="js").one().block_severity = None
        db.session.commit()
    assert "1.1.0" in c.get("/npm/js/demo", headers=ALICE).json["versions"]
    # HEAD never serves (or stores) a cached GET body
    assert c.head("/npm/js/demo", headers=ALICE).status_code == 200
    assert c.get("/npm/js/demo", headers=ALICE).json["name"] == "demo"
    # authorization is still checked on hits
    assert c.get("/npm/js/demo").status_code == 401


def test_pypi_and_helm_index_invalidation(app):
    metacache.clear()
    c = app.test_client()
    c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
        ":action": "file_upload", "name": "demo-pkg", "version": "1.0.0",
        "content": (io.BytesIO(make_wheel()), "demo_pkg-1.0.0-py3-none-any.whl")})
    html = c.get("/pypi/py/simple/demo-pkg/", headers=ALICE)
    js = c.get("/pypi/py/simple/demo-pkg/", headers={**ALICE, "Accept": "application/vnd.pypi.simple.v1+json"})
    assert b"<a href" in html.data and js.json["name"] == "demo-pkg"  # Accept is part of the key
    assert c.get("/pypi/py/simple/demo-pkg/", headers=ALICE).headers["X-Florepo-Cache"] == "hit"
    c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
        ":action": "file_upload", "name": "demo-pkg", "version": "1.1.0",
        "content": (io.BytesIO(make_wheel(version="1.1.0")), "demo_pkg-1.1.0-py3-none-any.whl")})
    assert b"demo_pkg-1.1.0" in c.get("/pypi/py/simple/demo-pkg/", headers=ALICE).data

    add_repo(app, name="charts", format="helm", allow_redeploy=True)
    c.post("/helm/charts/api/charts", data=make_chart(version="0.1.0"), headers=basic())
    c.post("/helm/charts/api/charts", data=make_chart(version="0.2.0"), headers=basic())
    first = c.get("/helm/charts/index.yaml", headers=ALICE)
    assert c.get("/helm/charts/index.yaml", headers=ALICE).headers["X-Florepo-Cache"] == "hit"
    assert b"0.1.0" in first.data
    c.delete("/helm/charts/api/charts/mychart/0.1.0", headers=basic())
    again = c.get("/helm/charts/index.yaml", headers=ALICE)
    assert again.headers["X-Florepo-Cache"] == "miss" and b"version: 0.1.0" not in again.data
    with app.app_context():
        info = metacache.info()
    assert info["hits"] >= 2 and info["entries"] >= 1


def test_cache_can_be_disabled(app):
    app.config["METADATA_CACHE_MB"] = 0
    c = app.test_client()
    npm_publish(c, "nocache", "1.0.0")
    r = c.get("/npm/js/nocache", headers=ALICE)
    assert r.status_code == 200 and "X-Florepo-Cache" not in r.headers
    app.config["METADATA_CACHE_MB"] = 32


def test_gzip_variant(app):
    import gzip

    metacache.clear()
    c = app.test_client()
    for i in range(8):
        npm_publish(c, "big", f"1.0.{i}")
    plain = c.get("/npm/js/big", headers=ALICE)
    gz = c.get("/npm/js/big", headers={**ALICE, "Accept-Encoding": "gzip, deflate"})
    assert gz.headers["Content-Encoding"] == "gzip" and "Accept-Encoding" in gz.headers["Vary"]
    assert gzip.decompress(gz.data) == plain.data and gz.headers["ETag"] != plain.headers["ETag"]
    assert c.get("/npm/js/big", headers={**ALICE, "Accept-Encoding": "gzip",
                                         "If-None-Match": gz.headers["ETag"]}).status_code == 304
