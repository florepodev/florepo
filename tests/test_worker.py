"""Multiple workers: exclusive claims, recovery of scans of dead workers, heartbeats."""
import io
from datetime import timedelta

from app import settings
from app.extensions import db
from app.models import Version, utcnow
from app.worker import _claim, _cleanup_dead_workers, heartbeat, workers
from tests.test_registries import basic, make_wheel


def _upload(app, n=2):
    c = app.test_client()
    for i in range(n):
        name = f"pkg_{i}"
        c.post("/pypi/py/", headers=basic(), content_type="multipart/form-data", data={
            ":action": "file_upload", "name": name.replace("_", "-"), "version": "1.0.0",
            "content": (io.BytesIO(make_wheel(name)), f"{name}-1.0.0-py3-none-any.whl")})
    return c


def test_claim_is_exclusive(app):
    _upload(app, 1)
    with app.app_context():
        vid = Version.query.one().id
        assert _claim(vid, "w1") is True
        assert _claim(vid, "w2") is False  # second worker loses the race
        v = db.session.get(Version, vid)
        assert v.scan_status == "running" and v.scan_worker == "w1" and v.scan_started_at


def test_scans_of_dead_workers_are_requeued(app):
    _upload(app, 2)
    with app.app_context():
        alive_v, dead_v = Version.query.order_by(Version.id).all()
        heartbeat("alive-1", False, {"scanned": 0})
        _claim(alive_v.id, "alive-1")
        _claim(dead_v.id, "ghost-1")  # never sent a heartbeat (crashed)
        _cleanup_dead_workers()
        db.session.expire_all()
        assert db.session.get(Version, alive_v.id).scan_status == "running"
        assert db.session.get(Version, dead_v.id).scan_status == "pending"
        # an old heartbeat counts as dead as well
        settings.put("worker:alive-1", {"at": (utcnow() - timedelta(minutes=10)).isoformat(timespec="seconds")})
        db.session.commit()
        _cleanup_dead_workers()
        db.session.expire_all()
        assert db.session.get(Version, alive_v.id).scan_status == "pending"


def test_worker_heartbeats_and_scanner_page(app):
    with app.app_context():
        heartbeat("host-a-1", True, {"scanned": 5, "failed": 0, "started": utcnow().isoformat(timespec="seconds")})
        heartbeat("host-b-2", False, {"scanned": 3, "failed": 1, "started": utcnow().isoformat(timespec="seconds")})
        ws = workers()
        assert [w["id"] for w in ws] == ["host-a-1", "host-b-2"] and ws[0]["leader"] and not ws[1]["leader"]
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    page = c.get("/admin/scanner").data
    assert b"host-a-1" in page and b"leader" in page and b"Workers (2 running)" in page
    from tests.test_api import bearer
    assert len(c.get("/api/v1/scanner", headers=bearer(c)).json["workers"]) == 2
