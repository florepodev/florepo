import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_

from .. import ldap_auth, malware, netproxy, notifications, quotas, services, settings, storage
from ..auth import authenticate_password, can_read, can_write, forget_token
from ..extensions import db
from ..models import (DEFAULT_UPSTREAMS, FORMAT_LABELS, ROLES, SEVERITIES, ApiToken, AuditEvent, DownloadEvent,
                      Notification, Package, Repository, User, Version, Vulnerability, utcnow)
from ..scanner import trivy_info, trivy_version
from ..worker import workers as worker_list
from ..sorting import apply_sort
from .common import base_url

bp = Blueprint("ui", __name__)


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not current_user.is_admin:
            abort(403)
        return fn(*a, **kw)
    return wrapper


def audit_required(fn):
    """Admins and security auditors (read-only: reports, audit log)."""
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not current_user.can_audit:
            abort(403)
        return fn(*a, **kw)
    return wrapper


def deployer_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not current_user.can_deploy:
            abort(403)
        return fn(*a, **kw)
    return wrapper


def visible_repos():
    q = Repository.query.order_by(Repository.format, Repository.name)
    if not current_user.is_authenticated:
        q = q.filter_by(public=True)
    return q


def _repo_or_404(name):
    repo = Repository.query.filter_by(name=name).first_or_404()
    if not can_read(repo, current_user if current_user.is_authenticated else None):
        abort(404)
    return repo


_ASSET_VERSION = {}


@bp.app_template_global()
def asset_url(filename):
    """Static URL with a content hash, so browsers (and nginx's 1-day cache headers) pick up new versions at once."""
    if filename not in _ASSET_VERSION:
        import hashlib

        path = os.path.join(current_app.static_folder, filename)
        try:
            with open(path, "rb") as f:
                _ASSET_VERSION[filename] = hashlib.sha256(f.read()).hexdigest()[:12]
        except OSError:
            _ASSET_VERSION[filename] = "0"
    return url_for("static", filename=filename, v=_ASSET_VERSION[filename])


@bp.app_context_processor
def inject():
    return {"SEVERITIES": SEVERITIES, "base_url": base_url, "can_write": can_write, "mask_proxy": netproxy.mask,
            "registry_host": lambda: urlparse(base_url()).netloc, "FORMAT_LABELS": FORMAT_LABELS,
            "human_size": quotas.human, "malware_policy": malware.policy}


# --- auth -------------------------------------------------------------------

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = authenticate_password(request.form.get("username", ""), request.form.get("password", ""))
        if user:
            login_user(user, remember=bool(request.form.get("remember")))
            AuditEvent.log(user.username, "login", request.remote_addr)
            db.session.commit()
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for(".dashboard"))
        flash("Invalid username or password", "error")
    return render_template("login.html")


@bp.post("/logout")
def logout():
    logout_user()
    return redirect(url_for(".login"))


# --- dashboard ----------------------------------------------------------------

@bp.get("/")
def dashboard():
    if not current_user.is_authenticated and not Repository.query.filter_by(public=True).count():
        return redirect(url_for(".login"))
    repos = visible_repos()
    repo_ids = [r.id for r in repos]
    formats = sorted({r.format for r in repos})
    vq = Version.query.join(Package).filter(Package.repository_id.in_(repo_ids))
    sev_totals = {s: 0 for s in SEVERITIES}
    sums = vq.with_entities(*[func.coalesce(func.sum(getattr(Version, f"count_{s.lower()}")), 0)
                              for s in SEVERITIES]).first()
    for s, n in zip(SEVERITIES, sums or []):
        sev_totals[s] = int(n or 0)
    stats = {
        "repos": len(repo_ids),
        "formats": len(formats),
        "packages": Package.query.filter(Package.repository_id.in_(repo_ids)).count(),
        "versions": vq.count(),
        "pending": vq.filter(Version.scan_status.in_(["pending", "running"])).count(),
        "failed": vq.filter(Version.scan_status == "failed").count(),
        "vulnerable": vq.filter(or_(Version.count_critical > 0, Version.count_high > 0)).count(),
        "pulls": DownloadEvent.query.filter(DownloadEvent.repository_id.in_(repo_ids)).count(),
    }
    recent = vq.order_by(Version.created_at.desc()).limit(10).all()
    critical = (vq.filter(or_(Version.count_critical > 0, Version.count_high > 0))
                .order_by(Version.count_critical.desc(), Version.count_high.desc()).limit(8).all())
    return render_template("dashboard.html", stats=stats, sev_totals=sev_totals, recent=recent,
                           critical=critical, trivy=trivy_version(),
                           db_updated=_parse_ts(((trivy_info() or {}).get("VulnerabilityDB") or {}).get("UpdatedAt")),
                           rescan_hours=settings.get("rescan_interval_hours"))


# --- repositories ---------------------------------------------------------------

@bp.get("/repos")
def repos():
    if not current_user.is_authenticated and not Repository.query.filter_by(public=True).count():
        return redirect(url_for(".login"))
    rows = []
    for r in visible_repos():
        pkgs = Package.query.filter_by(repository_id=r.id).count()
        rows.append((r, pkgs, quotas.repo_usage(r)))
    return render_template("repos.html", rows=rows)


def _repo_form_data():
    """Convert the HTML form into the dict expected by services (unchecked checkboxes = False)."""
    f = request.form
    data = {k: f.get(k, "") for k in ("name", "format", "kind", "description", "block_severity",
                                       "upstream_url", "upstream_username", "upstream_password",
                                       "proxy_mode", "proxy_url", "distro", "cache_retention_days", "quota")}
    if "cache_retention_days" not in f:
        data.pop("cache_retention_days")
    if "distro" not in f:
        data.pop("distro")
    if not f.get("proxy_mode"):
        data.pop("proxy_mode")
    for key in ("public", "allow_redeploy", "clear_upstream_password"):
        data[key] = bool(f.get(key))
    return data


@bp.route("/repos/new", methods=["GET", "POST"])
@admin_required
def repo_new():
    if request.method == "POST":
        try:
            repo = services.create_repository(_repo_form_data(), current_user)
            db.session.commit()
            flash(f"Repository {repo.name} created", "success")
            return redirect(url_for(".repo_detail", name=repo.name))
        except services.ValidationError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("repo_form.html", repo=None, upstreams=DEFAULT_UPSTREAMS)


@bp.route("/repos/<name>/edit", methods=["GET", "POST"])
@admin_required
def repo_edit(name):
    repo = Repository.query.filter_by(name=name).first_or_404()
    if request.method == "POST":
        try:
            services.update_repository(repo, _repo_form_data(), current_user)
            db.session.commit()
            flash("Saved", "success")
            return redirect(url_for(".repo_detail", name=name))
        except services.ValidationError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("repo_form.html", repo=repo, upstreams=DEFAULT_UPSTREAMS)


@bp.post("/repos/<name>/delete")
@admin_required
def repo_delete(name):
    repo = Repository.query.filter_by(name=name).first_or_404()
    if request.form.get("confirm") != repo.name:
        flash("Please type the repository name to confirm", "error")
        return redirect(url_for(".repo_edit", name=name))
    services.delete_repository(repo, current_user)
    db.session.commit()
    flash(f"Repository {name} deleted (blobs are removed by 'flask gc')", "success")
    return redirect(url_for(".repos"))


@bp.get("/repos/<name>")
def repo_detail(name):
    repo = _repo_or_404(name)
    q = request.args.get("q", "").strip()
    pq = Package.query.filter_by(repository_id=repo.id)
    if q:
        pq = pq.filter(Package.name.contains(q.lower()) | Package.display_name.contains(q))
    latest = (db.select(Version.id).where(Version.package_id == Package.id)
              .order_by(Version.created_at.desc()).limit(1).correlate(Package).scalar_subquery())
    score = (Version.count_critical * 1_000_000_000 + Version.count_high * 1_000_000
             + Version.count_medium * 1_000 + Version.count_low)
    columns = {
        "name": Package.name,
        "latest": db.select(Version.version).where(Version.id == latest).scalar_subquery(),
        "security": db.select(score).where(Version.id == latest).scalar_subquery(),
        "versions": db.select(func.count(Version.id)).where(Version.package_id == Package.id)
                      .correlate(Package).scalar_subquery(),
        "created": Package.created_at,
        "updated": Package.updated_at,
    }
    pq, sort = apply_sort(pq, columns, "updated",
                          default_dirs={"created": "desc", "updated": "desc", "security": "desc", "versions": "desc"})
    page = pq.paginate(per_page=50, error_out=False)
    deployers = [u for u in User.query.filter(User.role == "deployer", User.active.is_(True)).order_by(User.username)
                 if u.can_deploy_to(repo)]
    from ..cache import cache_usage

    apk_key = None
    if repo.format == "apk" and not repo.is_proxy:
        from .. import signing

        try:
            apk_key = signing.apk_key_name()
        except OSError:
            apk_key = "florepo.rsa.pub"
    return render_template("repo.html", repo=repo, page=page, q=q, sort=sort, deployers=deployers,
                           cache=cache_usage(repo) if repo.is_proxy else None, apk_key_name=apk_key,
                           usage=quotas.status(repo))


# --- packages & versions -------------------------------------------------------

@bp.get("/packages/<int:pid>")
def package_detail(pid):
    pkg = db.get_or_404(Package, pid)
    _repo_or_404(pkg.repository.name)
    return render_template("package.html", pkg=pkg, repo=pkg.repository)


@bp.get("/versions/<int:vid>")
def version_detail(vid):
    ver = db.get_or_404(Version, vid)
    repo = _repo_or_404(ver.package.repository.name)
    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    vulns = sorted(ver.vulnerabilities, key=lambda v: (sev_order.get(v.severity, 9), v.vuln_id))
    pulls = None
    if current_user.is_authenticated and current_user.can_audit:
        pulls = (db.session.query(DownloadEvent.username, func.count(DownloadEvent.id),
                                  func.max(DownloadEvent.created_at))
                 .filter(DownloadEvent.version_id == ver.id)
                 .group_by(DownloadEvent.username).order_by(func.count(DownloadEvent.id).desc()).all())
    return render_template("version.html", ver=ver, pkg=ver.package, repo=repo, vulns=vulns, pulls=pulls)


@bp.get("/versions/<int:vid>/sbom")
def version_sbom(vid):
    ver = db.get_or_404(Version, vid)
    _repo_or_404(ver.package.repository.name)
    if not storage.sbom_exists(ver.sbom_key):
        abort(404)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{ver.package.display_name}-{ver.version}")
    return storage.serve_sbom(ver.sbom_key, download_name=f"{safe}.cdx.json")


@bp.post("/versions/<int:vid>/rescan")
@deployer_required
def version_rescan(vid):
    ver = db.get_or_404(Version, vid)
    if not can_write(ver.package.repository, current_user):
        abort(403)
    ver.request_scan()
    db.session.commit()
    flash("Scan queued", "success")
    return redirect(url_for(".version_detail", vid=vid))


@bp.post("/repos/<name>/cache/purge")
@admin_required
def repo_cache_purge(name):
    from ..cache import purge_repository

    repo = Repository.query.filter_by(name=name).first_or_404()
    if not repo.is_proxy:
        abort(400)
    days = request.form.get("older_than_days", type=int)
    res = purge_repository(repo, older_than_days=days, actor=current_user.username)
    flash(f"Removed {res['versions']} cached versions – disk space is freed by the next garbage collection", "success")
    return redirect(url_for(".repo_detail", name=name))


@bp.post("/repos/<name>/rescan")
@admin_required
def repo_rescan(name):
    repo = Repository.query.filter_by(name=name).first_or_404()
    n = 0
    for pkg in repo.packages:
        for v in pkg.versions:
            v.request_scan()
            n += 1
    db.session.commit()
    flash(f"{n} versions queued for scanning", "success")
    return redirect(url_for(".repo_detail", name=name))


@bp.post("/versions/<int:vid>/delete")
@deployer_required
def version_delete(vid):
    ver = db.get_or_404(Version, vid)
    if not can_write(ver.package.repository, current_user):
        abort(403)
    pid = ver.package_id
    repo, package_gone = services.delete_version(ver, current_user)
    db.session.commit()
    if package_gone:
        return redirect(url_for(".repo_detail", name=repo.name))
    return redirect(url_for(".package_detail", pid=pid))


# --- vulnerabilities ------------------------------------------------------------

@bp.get("/vulnerabilities")
@login_required
def vulnerabilities():
    sev = request.args.get("severity", "")
    q = request.args.get("q", "").strip()
    query = (db.session.query(Vulnerability.vuln_id, func.max(Vulnerability.severity),
                              func.max(Vulnerability.title), func.max(Vulnerability.url),
                              func.count(func.distinct(Vulnerability.version_id)))
             .group_by(Vulnerability.vuln_id))
    if sev in SEVERITIES:
        query = query.filter(Vulnerability.severity == sev)
    if q:
        query = query.filter(or_(Vulnerability.vuln_id.contains(q), Vulnerability.pkg_name.contains(q)))
    rows = query.order_by(func.count(func.distinct(Vulnerability.version_id)).desc()).limit(500).all()
    return render_template("vulnerabilities.html", rows=rows, sev=sev, q=q)


@bp.get("/vulnerabilities/<vuln_id>")
@login_required
def vulnerability_detail(vuln_id):
    findings = (Vulnerability.query.filter_by(vuln_id=vuln_id)
                .join(Version).order_by(Version.created_at.desc()).all())
    if not findings:
        abort(404)
    return render_template("vulnerability.html", vuln_id=vuln_id, findings=findings)


# --- tokens & users -------------------------------------------------------------

@bp.route("/tokens", methods=["GET", "POST"])
@login_required
def tokens():
    new_token = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:120] or "token"
        tok, new_token = ApiToken.issue(current_user, name)
        AuditEvent.log(current_user.username, "token.create", name)
        db.session.commit()
    return render_template("tokens.html", tokens=current_user.tokens, new_token=new_token)


@bp.post("/tokens/<int:tid>/revoke")
@login_required
def token_revoke(tid):
    tok = db.get_or_404(ApiToken, tid)
    if tok.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    AuditEvent.log(current_user.username, "token.revoke", tok.name)
    forget_token(tok.token_hash)
    db.session.delete(tok)
    db.session.commit()
    return redirect(request.referrer or url_for(".tokens"))


@bp.route("/account/password", methods=["POST"])
@login_required
def change_password():
    if not current_user.check_password(request.form.get("current", "")):
        flash("Current password is wrong", "error")
    elif len(request.form.get("new", "")) < 8:
        flash("New password must have at least 8 characters", "error")
    else:
        current_user.set_password(request.form["new"])
        db.session.commit()
        flash("Password changed", "success")
    return redirect(url_for(".tokens"))


@bp.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        try:
            u = services.create_user(request.form.to_dict(), current_user)
            db.session.commit()
            flash(f"User {u.username} created", "success")
        except services.ValidationError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("users.html", users=User.query.order_by(User.username).all(), roles=ROLES)


@bp.route("/users/<int:uid>", methods=["GET", "POST"])
@admin_required
def user_edit(uid):
    u = db.get_or_404(User, uid)
    hosted = Repository.query.filter_by(kind="hosted").order_by(Repository.format, Repository.name).all()
    if request.method == "POST":
        f = request.form
        data = {"active": bool(f.get("active")), "quota": f.get("quota", "")}
        if f.get("quota_mode") == "default":
            data["quota"] = None
        elif f.get("quota_mode") == "unlimited":
            data["quota_bytes"] = 0
            data.pop("quota")
        if not u.is_ldap:
            data.update({"role": f.get("role"), "password": f.get("password"),
                         "restrict_deploy": f.get("deploy_scope") == "selected",
                         "deploy_repos": f.getlist("deploy_repos")})
        try:
            services.update_user(u, data, current_user)
            db.session.commit()
            flash(f"{u.username} updated", "success")
            return redirect(url_for(".users"))
        except services.ValidationError as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return redirect(url_for(".user_edit", uid=uid))
    return render_template("user_form.html", u=u, roles=ROLES, hosted=hosted,
                           selected={r.id for r in u.deploy_repos}, used=quotas.user_usage(u),
                           limit=quotas.user_limit(u), default_quota=quotas.default_user_quota())


DB_INTERVALS = [(0, "manual only"), (1, "hourly"), (3, "every 3 hours"), (6, "every 6 hours"),
                (12, "every 12 hours"), (24, "daily"), (48, "every 2 days"), (168, "weekly")]
RESCAN_INTERVALS = [(0, "never"), (6, "every 6 hours"), (12, "every 12 hours"), (24, "daily"),
                    (72, "every 3 days"), (168, "weekly"), (720, "monthly")]


def _parse_ts(value):
    """Trivy timestamps look like 2026-10-06T06:12:41.123456789Z."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(re.sub(r"(\.\d{6})\d*", r"\1", value).replace("Z", "+00:00")) \
            .astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


@bp.route("/admin/scanner", methods=["GET", "POST"])
@admin_required
def scanner_admin():
    if request.method == "POST":
        f = request.form
        valid_db = {h for h, _ in DB_INTERVALS}
        valid_rescan = {h for h, _ in RESCAN_INTERVALS}
        db_h, rescan_h = f.get("trivy_db_interval_hours", type=int), f.get("rescan_interval_hours", type=int)
        if db_h not in valid_db or rescan_h not in valid_rescan:
            flash("Invalid interval", "error")
        else:
            settings.put("trivy_db_interval_hours", db_h)
            settings.put("rescan_interval_hours", rescan_h)
            settings.put("trivy_java_db", bool(f.get("trivy_java_db")))
            settings.put("rescan_after_db_update", bool(f.get("rescan_after_db_update")))
            AuditEvent.log(current_user.username, "scanner.settings",
                           f"db={db_h}h rescan={rescan_h}h java={bool(f.get('trivy_java_db'))} "
                           f"rescan_after_update={bool(f.get('rescan_after_db_update'))}")
            db.session.commit()
            flash("Scanner settings saved", "success")
        return redirect(url_for(".scanner_admin"))

    info = trivy_info()
    now = utcnow()

    def db_meta(key):
        m = (info or {}).get(key)
        if not m:
            return None
        return {"schema": m.get("Version"), "updated": _parse_ts(m.get("UpdatedAt")),
                "next": _parse_ts(m.get("NextUpdate")), "downloaded": _parse_ts(m.get("DownloadedAt"))}

    vuln_db, java_db = db_meta("VulnerabilityDB"), db_meta("JavaDB")
    beat = settings.get("worker_heartbeat")
    beat = datetime.fromisoformat(beat) if beat else None
    last = settings.get("trivy_db_last_run") or {}
    interval = int(settings.get("trivy_db_interval_hours") or 0)
    next_run = None
    if interval and last.get("at"):
        next_run = datetime.fromisoformat(last["at"]) + timedelta(hours=interval)
    counts = dict(db.session.query(Version.scan_status, func.count(Version.id)).group_by(Version.scan_status).all())
    stale_db = None
    if vuln_db and vuln_db["updated"]:
        stale_db = db.session.query(func.count(Version.id)).filter(
            Version.scan_status == "done", Version.scanned_at < vuln_db["updated"]).scalar()
    failed = (Version.query.filter_by(scan_status="failed").order_by(Version.scanned_at.desc()).limit(10).all())
    return render_template(
        "scanner.html", info=info, vuln_db=vuln_db, java_db=java_db, now=now,
        worker_alive=bool(beat and (now - beat).total_seconds() < 120), heartbeat=beat, workers=worker_list(),
        last=last, history=settings.get("trivy_db_history") or [], next_run=next_run,
        requested=settings.get("trivy_db_update_requested"), running=settings.get("trivy_db_update_running"),
        s={k: settings.get(k) for k in settings.DEFAULTS}, db_intervals=DB_INTERVALS,
        rescan_intervals=RESCAN_INTERVALS, counts=counts, stale_db=stale_db, failed=failed,
        env_db_repo=os.environ.get("TRIVY_DB_REPOSITORY"), clamav=malware.get_config(),
        clamav_info=malware.engine_info() if malware.get_config()["enabled"] else None,
        malware_counts=dict(db.session.query(Version.malware_status, func.count(Version.id))
                            .group_by(Version.malware_status).all()),
        infected=Version.query.filter_by(malware_status="infected").order_by(Version.malware_scanned_at.desc()).limit(10).all(),
        parse_iso=lambda v: datetime.fromisoformat(v) if v else None, parse_ts=_parse_ts,
    )


@bp.post("/admin/scanner/clamav")
@admin_required
def scanner_clamav():
    f = request.form
    try:
        cfg = services.parse_clamav_config({
            "enabled": bool(f.get("enabled")), "host": f.get("host", ""), "port": f.get("port"),
            "max_file_mb": f.get("max_file_mb"), "block_infected": bool(f.get("block_infected")),
            "block_unscanned": bool(f.get("block_unscanned"))}, malware.get_config())
        settings.put("clamav", cfg)
        AuditEvent.log(current_user.username, "clamav.settings",
                       f"enabled={cfg['enabled']} {cfg['host']}:{cfg['port']} block={cfg['block_infected']} "
                       f"hold={cfg['block_unscanned']}")
        db.session.commit()
        malware.forget_policy()
        info = malware.engine_info(cfg) if cfg["enabled"] else None
        if info and not info["ok"]:
            flash(f"Saved – but clamd is not reachable: {info['error']}", "error")
        else:
            flash("Malware scanning settings saved", "success")
    except services.ValidationError as exc:
        flash(str(exc), "error")
    return redirect(url_for(".scanner_admin") + "#clamav")


@bp.post("/admin/scanner/clamav/rescan")
@admin_required
def scanner_clamav_rescan():
    """Queue all versions that were never checked by ClamAV (e.g. after enabling it)."""
    n = db.session.execute(db.update(Version).where(Version.malware_status.in_(["none", "error"]),
                                                    Version.scan_status != "running")
                           .values(scan_status="pending")).rowcount
    AuditEvent.log(current_user.username, "clamav.rescan", f"{n} versions")
    db.session.commit()
    flash(f"{n} versions queued for scanning", "success")
    return redirect(url_for(".scanner_admin") + "#clamav")


@bp.post("/admin/scanner/update")
@admin_required
def scanner_update_now():
    settings.put("trivy_db_update_requested", True)
    AuditEvent.log(current_user.username, "scanner.db_update", "manual")
    db.session.commit()
    flash("DB update requested – the worker runs it within a few seconds", "success")
    return redirect(url_for(".scanner_admin"))


@bp.post("/admin/scanner/rescan")
@admin_required
def scanner_rescan():
    scope = request.form.get("scope")
    q = db.update(Version)
    if scope == "failed":
        q = q.where(Version.scan_status == "failed")
    elif scope == "stale":
        updated = _parse_ts(((trivy_info() or {}).get("VulnerabilityDB") or {}).get("UpdatedAt"))
        if not updated:
            abort(400)
        q = q.where(Version.scan_status == "done", Version.scanned_at < updated)
    else:
        q = q.where(Version.scan_status.in_(["done", "failed", "none"]))
    n = db.session.execute(q.values(scan_status="pending")).rowcount
    AuditEvent.log(current_user.username, "scanner.rescan", f"{scope or 'all'}: {n}")
    db.session.commit()
    flash(f"{n} versions queued for scanning", "success")
    return redirect(url_for(".scanner_admin"))


@bp.route("/admin/notifications", methods=["GET", "POST"])
@admin_required
def notifications_admin():
    if request.method == "POST":
        f = request.form
        try:
            cfg = services.parse_alert_config({
                "enabled": bool(f.get("enabled")), "recipients": f.get("recipients", ""),
                "threshold": f.get("threshold"), "only_new": bool(f.get("only_new")),
                "include_uploads": bool(f.get("include_uploads")), "repos": f.getlist("repos"),
            })
            settings.put("alerts", cfg)
            AuditEvent.log(current_user.username, "alerts.settings",
                           f"enabled={cfg['enabled']} threshold={cfg['threshold']} to={','.join(cfg['recipients'])}")
            db.session.commit()
            flash("Notification settings saved", "success")
        except services.ValidationError as exc:
            flash(str(exc), "error")
        return redirect(url_for(".notifications_admin"))
    q, sort = apply_sort(Notification.query, {
        "time": Notification.created_at, "artifact": Notification.package_name,
        "severity": Notification.max_severity, "trigger": Notification.trigger, "sent": Notification.sent_at,
    }, "time", default_dirs={"time": "desc", "sent": "desc"})
    page = q.paginate(per_page=50, error_out=False)
    return render_template("notifications.html", cfg=notifications.get_config(), page=page, sort=sort,
                           smtp_ok=notifications.smtp_configured(), repos=Repository.query.order_by(Repository.name).all(),
                           pending=Notification.query.filter(Notification.sent_at.is_(None),
                                                             Notification.attempts < notifications.MAX_ATTEMPTS).count())


@bp.post("/admin/notifications/test")
@admin_required
def notifications_test():
    cfg = notifications.get_config()
    to = [x.strip() for x in request.form.get("to", "").split(",") if x.strip()] or cfg["recipients"]
    if not notifications.smtp_configured():
        flash("SMTP is not configured (set SMTP_HOST etc. in the environment)", "error")
    elif not to:
        flash("No recipient given", "error")
    else:
        try:
            notifications.send_mail(to, "[Florepo] Test notification",
                                    "This is a test e-mail from Florepo. Alerting works.")
            AuditEvent.log(current_user.username, "alerts.test", ", ".join(to))
            db.session.commit()
            flash(f"Test e-mail sent to {', '.join(to)}", "success")
        except Exception as exc:
            flash(f"Sending failed: {exc}", "error")
    return redirect(url_for(".notifications_admin"))


@bp.post("/admin/notifications/flush")
@admin_required
def notifications_flush():
    n = notifications.flush_pending(force=True)
    flash(f"{n} queued alerts sent" if n else "Nothing sent – see the error column", "success" if n else "error")
    return redirect(url_for(".notifications_admin"))


@bp.route("/admin/network", methods=["GET", "POST"])
@admin_required
def network_admin():
    if request.method == "POST":
        try:
            cfg = services.parse_network_config(request.form.to_dict(), netproxy.global_config())
            settings.put("outbound_proxy", cfg)
            AuditEvent.log(current_user.username, "network.settings",
                           f"http={netproxy.mask(cfg['http_proxy'])} https={netproxy.mask(cfg['https_proxy'])}")
            db.session.commit()
            flash("Network settings saved", "success")
        except services.ValidationError as exc:
            flash(str(exc), "error")
        return redirect(url_for(".network_admin"))
    proxied = Repository.query.filter_by(kind="proxy").order_by(Repository.name).all()
    return render_template("network.html", cfg=netproxy.global_config(), repos=proxied,
                           test=session_pop_test())


def session_pop_test():
    from flask import session
    return session.pop("network_test", None)


@bp.post("/admin/network/test")
@admin_required
def network_test():
    from flask import session
    session["network_test"] = services.test_connection(request.form.get("url") or "https://pypi.org/simple/",
                                                       request.form.get("repo") or None)
    return redirect(url_for(".network_admin"))


# --- authentication (LDAP / Active Directory) ------------------------------------------------

def _ldap_form():
    f = request.form
    groups, roles, repos = f.getlist("map_group"), f.getlist("map_role"), f.getlist("map_repos")
    data = {k: f.get(k, "") for k in ("server_urls", "bind_dn", "bind_password", "user_base", "user_filter",
                                       "username_attr", "email_attr", "name_attr", "group_mode", "group_base",
                                       "group_filter", "default_role", "sync_minutes", "timeout", "ca_cert")}
    for key in ("enabled", "start_tls", "verify_tls", "clear_bind_password"):
        data[key] = bool(f.get(key))
    data["mappings"] = [{"group": g, "role": r, "repos": p} for g, r, p in zip(groups, roles, repos)]
    return data


@bp.route("/admin/auth", methods=["GET", "POST"])
@admin_required
def auth_admin():
    current = settings.get("ldap") or {}
    if request.method == "POST":
        try:
            cfg = services.parse_ldap_config(_ldap_form(), current)
            settings.put("ldap", cfg)
            AuditEvent.log(current_user.username, "ldap.settings",
                           f"enabled={cfg['enabled']} servers={','.join(cfg['server_urls'])} mappings={len(cfg['mappings'])}")
            db.session.commit()
            flash("Authentication settings saved", "success")
        except services.ValidationError as exc:
            flash(str(exc), "error")
        return redirect(url_for(".auth_admin"))
    from flask import session

    cfg = ldap_auth.get_config()
    ldap_users = User.query.filter_by(auth_source="ldap").order_by(User.username).all()
    return render_template("auth.html", cfg=cfg, presets=ldap_auth.PRESETS, roles=ROLES, ldap_users=ldap_users,
                           group_modes=ldap_auth.GROUP_MODES, test=session.pop("ldap_test", None),
                           last_sync=settings.get("ldap_last_sync"), mask=ldap_auth.SECRET_MASK,
                           hosted=Repository.query.filter_by(kind="hosted").order_by(Repository.name).all())


@bp.post("/admin/auth/test")
@admin_required
def auth_test():
    from flask import session

    try:
        cfg = services.parse_ldap_config(_ldap_form(), settings.get("ldap") or {})
        result = ldap_auth.test(cfg, request.form.get("test_username", "").strip() or None,
                                request.form.get("test_password") or None)
    except services.ValidationError as exc:
        result = {"ok": False, "error": str(exc), "steps": []}
    result["username"] = request.form.get("test_username", "")
    session["ldap_test"] = result
    return redirect(url_for(".auth_admin") + "#test")


@bp.post("/admin/auth/sync")
@admin_required
def auth_sync():
    if not ldap_auth.enabled():
        flash("LDAP is not enabled", "error")
    else:
        s = ldap_auth.sync_all()
        AuditEvent.log(current_user.username, "ldap.sync", f"{s['users']} users, {s['disabled']} disabled")
        db.session.commit()
        flash(f"Synchronized {s['users']} LDAP users ({s['disabled']} disabled)" if s["ok"] else f"Sync failed: {s['error']}",
              "success" if s["ok"] else "error")
    return redirect(url_for(".auth_admin"))


# --- storage & quotas ---------------------------------------------------------------------------

@bp.route("/admin/storage", methods=["GET", "POST"])
@admin_required
def storage_admin():
    if request.method == "POST":
        try:
            values = services.parse_quota_settings(request.form)
            for k, v in values.items():
                settings.put(k, v)
            AuditEvent.log(current_user.username, "quota.settings",
                           f"default user quota={quotas.human(values['quota_default_user_bytes']) if values['quota_default_user_bytes'] else 'unlimited'}")
            db.session.commit()
            quotas.forget()
            flash("Quota settings saved", "success")
        except services.ValidationError as exc:
            flash(str(exc), "error")
        return redirect(url_for(".storage_admin"))
    rows = [(r, quotas.repo_usage(r)) for r in Repository.query.order_by(Repository.name)]
    user_rows = [(u, quotas.user_usage(u), quotas.user_limit(u)) for u in User.query.order_by(User.username)
                 if u.can_deploy]
    check = storage.check() if request.args.get("check") else None
    if check is not None:
        AuditEvent.log(current_user.username, "storage.check", f"{check.get('backend')}: ok={check.get('ok')}")
        db.session.commit()
    return render_template("storage.html", backend=storage.describe(), check=check, rows=rows, user_rows=user_rows,
                           default_quota=quotas.default_user_quota(), total=sum(u for _, u in rows),
                           staging=storage.staging_root())


@bp.get("/audit")
@audit_required
def audit():
    q, sort = apply_sort(AuditEvent.query, {"time": AuditEvent.created_at, "user": AuditEvent.username,
                                            "action": AuditEvent.action, "target": AuditEvent.target},
                         "time", default_dirs={"time": "desc"})
    page = q.paginate(per_page=100, error_out=False)
    return render_template("audit.html", page=page, sort=sort)


@bp.get("/healthz")
def healthz():
    db.session.execute(db.text("SELECT 1"))
    return {"status": "ok"}
