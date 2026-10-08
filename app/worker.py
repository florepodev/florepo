"""Background worker: vulnerability scans and maintenance. `flask --app wsgi worker`.

Several workers can run in parallel (`docker compose up -d --scale worker=4` or WORKER_REPLICAS):

* Scans are distributed: each worker claims a pending version with an atomic UPDATE, so a version is never
  scanned twice. Trivy runs with an in-memory analysis cache, so parallel scans do not block each other.
* Exactly one worker – the *leader*, elected with a PostgreSQL advisory lock – runs the singleton tasks:
  Trivy DB updates, scheduling re-scans, download counters, alert e-mails, cache retention and recovery of
  scans whose worker died. If the leader stops, another worker takes over within seconds.
* While the leader updates the signature DB, the other workers pause scanning.
"""
import os
import socket
import time
import traceback
from datetime import datetime, timedelta

from flask import current_app
from sqlalchemy import func, text

from . import ldap_auth, malware, notifications, settings
from .extensions import db
from .models import DownloadEvent, Setting, Version, utcnow
from .scanner import _db_present, scan_version, trivy_available, update_trivy_db

HISTORY_LEN = 25
LEADER_LOCK_ID = 7_265_783_202
HEARTBEAT_EVERY = 20
WORKER_TIMEOUT = 120  # a worker without heartbeat for this long is considered dead


def worker_id():
    return f"{socket.gethostname()}-{os.getpid()}"


# --- leader election --------------------------------------------------------------------------

class Leadership:
    """Session-level PostgreSQL advisory lock on a dedicated connection; SQLite: always leader (single worker)."""

    def __init__(self):
        self.conn = None
        self.is_leader = False

    def refresh(self):
        if db.engine.dialect.name != "postgresql":
            self.is_leader = True
            return True
        try:
            if self.conn is None:
                self.conn = db.engine.connect()
            if self.is_leader:
                self.conn.execute(text("SELECT 1"))  # lock lives as long as this connection
            else:
                self.is_leader = bool(self.conn.execute(text("SELECT pg_try_advisory_lock(:id)"),
                                                        {"id": LEADER_LOCK_ID}).scalar())
                self.conn.commit()
                if self.is_leader:
                    current_app.logger.info("worker %s is now the leader", worker_id())
        except Exception as exc:  # database restarted -> lock lost, reconnect next round
            current_app.logger.warning("leader connection lost: %s", exc)
            self.release()
        return self.is_leader

    def release(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn, self.is_leader = None, False


# --- heartbeats ------------------------------------------------------------------------------------

def heartbeat(wid, leader, stats):
    now = utcnow().isoformat(timespec="seconds")
    settings.put(f"worker:{wid}", {"at": now, "leader": leader, "host": socket.gethostname(), **stats})
    if leader:
        settings.put("worker_heartbeat", now)
    db.session.commit()


def workers(alive_only=True):
    cutoff = utcnow() - timedelta(seconds=WORKER_TIMEOUT)
    out = []
    for row in Setting.query.filter(Setting.key.like("worker:%")).order_by(Setting.key):
        info = dict(row.value or {})
        info["id"] = row.key.split(":", 1)[1]
        info["alive"] = bool(info.get("at")) and datetime.fromisoformat(info["at"]) >= cutoff
        if info["alive"] or not alive_only:
            out.append(info)
    return out


def _cleanup_dead_workers():
    """Leader: recover scans of dead workers and forget old heartbeat entries."""
    alive = {w["id"] for w in workers()}
    stale = utcnow() - timedelta(seconds=current_app.config["TRIVY_TIMEOUT"] * 2 + 300)
    q = db.update(Version).where(Version.scan_status == "running")
    q = q.where((Version.scan_worker.is_(None)) | (Version.scan_worker.notin_(alive or {""}))
                | (Version.scan_started_at < stale))
    n = db.session.execute(q.values(scan_status="pending", scan_worker=None)).rowcount
    if n:
        current_app.logger.info("re-queued %d scans of stopped workers", n)
    old = utcnow() - timedelta(days=1)
    for w in workers(alive_only=False):
        if not w["alive"] and datetime.fromisoformat(w["at"]) < old:
            db.session.execute(db.delete(Setting).where(Setting.key == f"worker:{w['id']}"))
    db.session.commit()


# --- scans --------------------------------------------------------------------------------------

def _claim(version_id, wid="worker"):
    res = db.session.execute(
        db.update(Version)
        .where(Version.id == version_id, Version.scan_status == "pending")
        .values(scan_status="running", scan_worker=wid, scan_started_at=utcnow())
    )
    db.session.commit()
    return res.rowcount == 1


def _scan_one(vid, wid):
    log = current_app.logger
    version = db.session.get(Version, vid)
    previous = notifications.finding_keys(vid)  # for "only new findings" alerts
    was_rescan = version.scanned_at is not None
    label = f"{version.package.repository.name}/{version.package.display_name}@{version.version}"
    log.info("scanning %s", label)
    if malware.enabled():  # ClamAV first, committed separately: a failing CVE scan must not drop its result
        before = version.malware_status
        try:
            status = malware.scan_version(version)
            if notifications.evaluate_malware(version, before):
                log.warning("malware alert queued for %s", label)
            db.session.commit()
            log.log(30 if status == "infected" else 20, "malware scan of %s: %s %s", label, status,
                    version.malware_name or "")
        except Exception as exc:
            db.session.rollback()
            version = db.session.get(Version, vid)
            version.malware_status = "error"
            version.meta = {**(version.meta or {}), "malware": {"error": str(exc)[:500]}}
            db.session.commit()
            log.error("malware scan of %s failed: %s", label, exc)
    try:
        scan_version(version)
        version.scan_worker = None
        db.session.commit()
        log.info("scanned %s: %d findings", label, version.total_vulns)
        if notifications.evaluate(version, previous, was_rescan):
            db.session.commit()
            log.info("alert queued for %s", label)
        return True
    except Exception as exc:
        db.session.rollback()
        version = db.session.get(Version, vid)
        version.scan_status, version.scan_worker = "failed", None
        version.scan_error = f"{exc}"[:4000]
        version.scanned_at = utcnow()
        db.session.commit()
        log.error("scan of %s failed: %s\n%s", label, exc, traceback.format_exc())
        return False


# --- singleton tasks (leader) ----------------------------------------------------------------------

def _schedule_rescans():
    hours = int(settings.get("rescan_interval_hours") or 0)
    if not hours:
        return
    cutoff = utcnow() - timedelta(hours=hours)
    db.session.execute(
        db.update(Version)
        .where(Version.scan_status == "done", Version.scanned_at < cutoff)
        .values(scan_status="pending")
    )
    db.session.commit()


def db_update_due():
    """Return the reason an update is due, or None."""
    if not trivy_available():
        return None
    if settings.get("trivy_db_update_requested"):
        return "manual"
    if not _db_present("vuln"):
        return "missing"
    hours = int(settings.get("trivy_db_interval_hours") or 0)
    if not hours:
        return None
    last = settings.get("trivy_db_last_run") or {}
    last_at = last.get("at")
    if not last_at or datetime.fromisoformat(last_at) < utcnow() - timedelta(hours=hours):
        return "schedule"
    return None


def _wait_for_running_scans(timeout=900):
    """Before replacing the DB: let scans of other workers finish (they pause claiming meanwhile)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not Version.query.filter_by(scan_status="running").first():
            return
        db.session.rollback()
        time.sleep(2)


def run_db_update(reason):
    log = current_app.logger
    log.info("updating trivy DB (%s)", reason)
    settings.put("trivy_db_update_running", True)
    db.session.commit()
    _wait_for_running_scans()
    before = (settings.get("trivy_db_last_run") or {}).get("db_updated_at")
    try:
        result = update_trivy_db(java=bool(settings.get("trivy_java_db")))
    finally:
        settings.put("trivy_db_update_running", False)
        db.session.commit()
    result["reason"] = reason
    settings.put("trivy_db_last_run", result)
    settings.put("trivy_db_history", ([result] + (settings.get("trivy_db_history") or []))[:HISTORY_LEN])
    settings.put("trivy_db_update_requested", False)
    if result["ok"] and settings.get("rescan_after_db_update") and result.get("db_updated_at") != before:
        n = db.session.execute(db.update(Version).where(Version.scan_status == "done")
                               .values(scan_status="pending")).rowcount
        log.info("DB changed – %d versions queued for re-scan", n)
    db.session.commit()
    log.log(20 if result["ok"] else 40, "trivy DB update %s in %ss: %s", "ok" if result["ok"] else "FAILED",
            result["duration_s"], result.get("error") or result.get("db_updated_at"))


def aggregate_download_counts():
    """Fold new DownloadEvents into Version.download_count (see common.record_download)."""
    last = settings.get("download_count_last_event_id")
    max_id = db.session.query(func.max(DownloadEvent.id)).scalar() or 0
    if last is None:  # first run after upgrade: counters already include older events
        settings.put("download_count_last_event_id", max_id)
        db.session.commit()
        return 0
    if max_id <= last:
        return 0
    rows = (db.session.query(DownloadEvent.version_id, func.count(DownloadEvent.id), func.max(DownloadEvent.created_at))
            .filter(DownloadEvent.id > last, DownloadEvent.id <= max_id, DownloadEvent.version_id.isnot(None))
            .group_by(DownloadEvent.version_id).all())
    for vid, n, last_pull in rows:  # counters + last access time (used by the proxy cache retention)
        db.session.execute(db.update(Version).where(Version.id == vid)
                           .values(download_count=Version.download_count + n, last_accessed_at=last_pull))
    settings.put("download_count_last_event_id", max_id)
    db.session.commit()
    return len(rows)


class LeaderTasks:
    def __init__(self, once=False):
        self.once = once
        self.last_rescan = self.last_counts = self.last_cleanup = 0.0
        self.last_cache = time.time() - 3000  # first retention run ~10 min after start

    def _guard(self, name, fn):
        try:
            return fn()
        except Exception:
            db.session.rollback()
            current_app.logger.error("%s failed:\n%s", name, traceback.format_exc())

    def run(self):
        now = time.time()
        if now - self.last_cleanup > 30:
            self._guard("worker cleanup", _cleanup_dead_workers)
            self.last_cleanup = now
        reason = db_update_due()
        if reason and not self.once:
            self._guard("trivy DB update", lambda: run_db_update(reason))
        if now - self.last_counts > 30 or self.once:
            self._guard("download count aggregation", aggregate_download_counts)
            self.last_counts = now
        if now - self.last_cache > 3600 and not self.once:  # hourly: proxy cache retention + blob GC
            def retention():
                from .cache import collect_garbage, evict_expired
                from .quotas import enforce_cache_limits
                expired = evict_expired()
                if enforce_cache_limits() or expired:
                    collect_garbage()
            self._guard("cache retention", retention)
            self.last_cache = now
        if now - self.last_rescan > 600:
            self._guard("re-scan scheduling", _schedule_rescans)
            self.last_rescan = now
        if not self.once:
            self._guard("LDAP sync", ldap_auth.sync_if_due)
        self._guard("alert delivery", notifications.flush_pending)


# --- main loop ----------------------------------------------------------------------------------------

def run_worker(once=False):
    log = current_app.logger
    poll = current_app.config["WORKER_POLL_SECONDS"]
    wid = worker_id()
    leadership = Leadership()
    tasks = LeaderTasks(once=once)
    stats = {"scanned": 0, "failed": 0, "started": utcnow().isoformat(timespec="seconds")}
    last_beat = 0.0
    log.info("worker %s started", wid)
    try:
        while True:
            leader = leadership.refresh()
            if time.time() - last_beat > HEARTBEAT_EVERY:
                heartbeat(wid, leader, stats)
                last_beat = time.time()
            if leader:
                tasks.run()
            if settings.get("trivy_db_update_running") and not leader:
                db.session.rollback()
                time.sleep(poll)  # leader is replacing the signature DB
                continue
            ids = [v.id for v in Version.query.filter_by(scan_status="pending").order_by(Version.id).limit(10)]
            if not ids:
                if once:
                    if leader:
                        tasks.run()  # e.g. send alerts queued by the last scans
                    return
                db.session.rollback()
                time.sleep(poll)
                continue
            for vid in ids:
                if settings.get("trivy_db_update_running") and not leader:
                    break
                if not _claim(vid, wid):
                    continue  # taken by another worker
                if _scan_one(vid, wid):
                    stats["scanned"] += 1
                else:
                    stats["failed"] += 1
    finally:
        leadership.release()
