"""Management REST API (JSON) – documented in app/openapi.py and rendered at /docs.

Authentication: `Authorization: Bearer <api token>`, HTTP Basic (user + password/token) or the UI session.
"""
from datetime import datetime
from functools import wraps

from flask import Blueprint, abort, jsonify, request
from sqlalchemy import func, or_

from .. import ldap_auth, malware, metacache, quotas, services, settings, storage
from ..auth import can_read, can_write, forget_token, resolve_identity
from ..extensions import csrf, db
from ..models import (ApiToken, AuditEvent, DownloadEvent, Package, Repository, User, Version,
                      Vulnerability, SEVERITIES)
from ..scanner import trivy_info
from ..worker import workers as worker_list
from ..sorting import apply_sort
from .reports import _filters, _query, usage_items

bp = Blueprint("api", __name__, url_prefix="/api/v1")
csrf.exempt(bp)


class ApiError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


@bp.errorhandler(ApiError)
def _api_error(e):
    resp = jsonify({"error": e.message})
    resp.status_code = e.status
    if e.status == 401:
        resp.headers["WWW-Authenticate"] = 'Bearer realm="Florepo"'
    return resp


@bp.errorhandler(404)
def _not_found(_e):
    return jsonify({"error": "not found"}), 404


@bp.errorhandler(services.ValidationError)
def _validation(e):
    db.session.rollback()
    return jsonify({"error": str(e)}), 400


def require(admin=False, optional=False, audit=False):
    """audit=True: admins and security auditors (read-only endpoints)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = resolve_identity()
            if user is None and not optional:
                raise ApiError(401, "authentication required")
            if admin and not (user and user.is_admin):
                raise ApiError(403, "admin role required")
            if audit and not (user and user.can_audit):
                raise ApiError(403, "admin or auditor role required")
            return fn(user, *a, **kw)
        return wrapper
    return deco


def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "JSON object body required")
    return data


def paginate(query, serialize):
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 50, type=int), 1), 500)
    p = query.paginate(page=page, per_page=per_page, error_out=False)
    return {"items": [serialize(x) for x in p.items], "page": p.page, "per_page": per_page,
            "total": p.total, "pages": p.pages}


def iso(dt):
    return dt.isoformat(timespec="seconds") + "Z" if isinstance(dt, datetime) else None


# --- serializers ------------------------------------------------------------------

def repo_json(r, user=None):
    data = {
        "name": r.name, "format": r.format, "kind": r.kind, "description": r.description,
        "proxy_mode": r.proxy_mode,
        "distro": r.distro, "cache_retention_days": r.cache_retention_days,
        "upstream_url": r.upstream_url, "public": r.public, "allow_redeploy": r.allow_redeploy,
        "block_severity": r.block_severity, "created_at": iso(r.created_at),
        "package_count": Package.query.filter_by(repository_id=r.id).count(),
        "quota_bytes": r.quota_bytes,
    }
    if user is not None:
        data["can_write"] = can_write(r, user) and not r.is_proxy
        data["used_bytes"] = quotas.repo_usage(r)
    if user is not None and user.is_admin:
        data["upstream_username"] = r.upstream_username
        data["upstream_password_set"] = bool(r.upstream_password)
    return data


def scan_json(v):
    return {
        "status": v.scan_status, "scanner": v.scanner, "scanned_at": iso(v.scanned_at), "error": v.scan_error,
        "counts": {s.lower(): getattr(v, f"count_{s.lower()}") for s in SEVERITIES},
        "max_severity": v.max_severity, "blocked": v.is_blocked(),
        "sbom_components": v.component_count, "sbom_available": bool(v.sbom_key),
        "signature_db": (v.meta or {}).get("trivy_db"), "block_reason": v.block_reason(),
        "malware": {"status": v.malware_status, "signature": v.malware_name,
                    "scanned_at": iso(v.malware_scanned_at),
                    "engine": ((v.meta or {}).get("malware") or {}).get("engine")},
    }


def version_json(v, detail=False):
    data = {
        "id": v.id, "package_id": v.package_id, "package": v.package.display_name,
        "repository": v.package.repository.name, "format": v.package.repository.format,
        "version": v.version, "digest": v.digest, "uploaded_by": v.uploaded_by,
        "created_at": iso(v.created_at), "download_count": v.download_count, "scan": scan_json(v),
    }
    if detail:
        data["files"] = [{"filename": f.filename, "path": f.path, "sha256": f.sha256, "size": f.size} for f in v.files]
        data["metadata"] = v.meta or {}
    return data


def package_json(p, detail=False):
    data = {"id": p.id, "repository": p.repository.name, "name": p.display_name,
            "created_at": iso(p.created_at), "updated_at": iso(p.updated_at),
            "version_count": len(p.versions),
            "latest": version_json(p.versions[0]) if p.versions else None}
    if detail:
        data["versions"] = [version_json(v) for v in p.versions]
        if (p.meta or {}).get("dist-tags"):
            data["dist_tags"] = p.meta["dist-tags"]
    return data


def vuln_json(x):
    return {"id": x.vuln_id, "severity": x.severity, "component": x.pkg_name, "component_type": x.pkg_type,
            "installed_version": x.installed_version, "fixed_version": x.fixed_version or None,
            "title": x.title, "url": x.url, "source": x.source}


def user_json(u):
    return {"id": u.id, "username": u.username, "role": u.role, "active": u.active,
            "restrict_deploy": u.restrict_deploy, "deploy_repos": [r.name for r in u.deploy_repos],
            "created_at": iso(u.created_at), "token_count": len(u.tokens),
            "auth_source": u.auth_source, "email": u.email, "display_name": u.display_name,
            "directory_disabled": u.directory_disabled, "last_login_at": iso(u.last_login_at),
            "quota_bytes": u.quota_bytes, "effective_quota_bytes": quotas.user_limit(u),
            "uploaded_bytes": quotas.user_usage(u)}


def token_json(t):
    return {"id": t.id, "name": t.name, "prefix": t.prefix, "created_at": iso(t.created_at),
            "last_used_at": iso(t.last_used_at)}


def event_json(e):
    return {"time": iso(e.created_at), "user": e.username, "format": e.format, "repository": e.repo_name,
            "package": e.package_name, "version": e.version_name, "version_id": e.version_id,
            "file": e.filename, "ip": e.ip, "user_agent": e.user_agent, "cache_hit": e.cache_hit}


# --- lookups with access control ----------------------------------------------------

def get_repo(name, user):
    repo = Repository.query.filter_by(name=name).first()
    if repo is None or not can_read(repo, user):
        raise ApiError(404, "repository not found")
    return repo


def get_version(vid, user):
    v = db.session.get(Version, vid)
    if v is None or not can_read(v.package.repository, user):
        raise ApiError(404, "version not found")
    return v


# --- identity -------------------------------------------------------------------------

@bp.get("/whoami")
@require()
def whoami(user):
    return user_json(user)


# --- repositories -----------------------------------------------------------------------

@bp.get("/repositories")
@require(optional=True)
def list_repositories(user):
    q = Repository.query
    if not user:
        q = q.filter_by(public=True)
    if request.args.get("format"):
        q = q.filter_by(format=request.args["format"])
    if request.args.get("kind"):
        q = q.filter_by(kind=request.args["kind"])
    q, _ = apply_sort(q, {"name": Repository.name, "format": Repository.format,
                          "created": Repository.created_at}, "name", "asc")
    return {"items": [repo_json(r, user) for r in q]}


@bp.post("/repositories")
@require(admin=True)
def create_repository(user):
    repo = services.create_repository(body(), user)
    db.session.commit()
    return repo_json(repo, user), 201


@bp.get("/repositories/<name>")
@require(optional=True)
def get_repository(user, name):
    return repo_json(get_repo(name, user), user)


@bp.patch("/repositories/<name>")
@require(admin=True)
def update_repository(user, name):
    repo = get_repo(name, user)
    services.update_repository(repo, body(), user)
    db.session.commit()
    return repo_json(repo, user)


@bp.delete("/repositories/<name>")
@require(admin=True)
def delete_repository(user, name):
    services.delete_repository(get_repo(name, user), user)
    db.session.commit()
    return "", 204


@bp.get("/repositories/<name>/packages")
@require(optional=True)
def list_packages(user, name):
    repo = get_repo(name, user)
    q = Package.query.filter_by(repository_id=repo.id)
    if request.args.get("q"):
        term = request.args["q"]
        q = q.filter(Package.name.contains(term.lower()) | Package.display_name.contains(term))
    q, _ = apply_sort(q, {"name": Package.name, "created": Package.created_at, "updated": Package.updated_at},
                      "updated", default_dirs={"created": "desc", "updated": "desc"})
    return paginate(q, package_json)


@bp.post("/repositories/<name>/cache/purge")
@require(admin=True)
def purge_repository_cache(user, name):
    from ..cache import purge_repository

    repo = get_repo(name, user)
    if not repo.is_proxy:
        raise ApiError(400, "only proxy repositories have a cache")
    days = (request.get_json(silent=True) or {}).get("older_than_days")
    if days is not None and (not isinstance(days, int) or days < 0):
        raise ApiError(400, "older_than_days must be a non-negative integer (omit to purge everything)")
    res = purge_repository(repo, older_than_days=days, actor=user.username)
    return {"removed_versions": res["versions"], "freed_bytes_approx": res["bytes"]}


@bp.get("/repositories/<name>/cache")
@require(audit=True)
def repository_cache(user, name):
    from ..cache import cache_usage

    repo = get_repo(name, user)
    versions, size = cache_usage(repo)
    return {"repository": repo.name, "versions": versions, "bytes": size,
            "retention_days": repo.cache_retention_days}


@bp.post("/repositories/<name>/scan")
@require(admin=True)
def scan_repository(user, name):
    repo = get_repo(name, user)
    package_ids = db.select(Package.id).where(Package.repository_id == repo.id)
    n = db.session.execute(db.update(Version).where(Version.package_id.in_(package_ids))
                           .values(scan_status="pending", scan_error=None)).rowcount
    AuditEvent.log(user.username, "repo.rescan", f"{repo.name}: {n}")
    db.session.commit()
    return {"queued": n}, 202


# --- packages & versions ---------------------------------------------------------------

@bp.get("/packages/<int:pid>")
@require(optional=True)
def get_package(user, pid):
    p = db.session.get(Package, pid)
    if p is None or not can_read(p.repository, user):
        raise ApiError(404, "package not found")
    return package_json(p, detail=True)


@bp.get("/versions/<int:vid>")
@require(optional=True)
def get_version_detail(user, vid):
    return version_json(get_version(vid, user), detail=True)


@bp.get("/versions/<int:vid>/vulnerabilities")
@require(optional=True)
def get_version_vulns(user, vid):
    v = get_version(vid, user)
    q = Vulnerability.query.filter_by(version_id=v.id)
    if request.args.get("severity"):
        q = q.filter(Vulnerability.severity == request.args["severity"].upper())
    order = {s: i for i, s in enumerate(SEVERITIES)}
    items = sorted(q.all(), key=lambda x: (order.get(x.severity, 9), x.vuln_id))
    return {"version_id": v.id, "scan": scan_json(v), "items": [vuln_json(x) for x in items]}


@bp.get("/versions/<int:vid>/sbom")
@require(optional=True)
def get_version_sbom(user, vid):
    v = get_version(vid, user)
    if not storage.sbom_exists(v.sbom_key):
        raise ApiError(404, "no SBOM available (not scanned yet)")
    return storage.serve_sbom(v.sbom_key)


@bp.post("/versions/<int:vid>/scan")
@require()
def scan_version(user, vid):
    v = get_version(vid, user)
    if not can_write(v.package.repository, user):
        raise ApiError(403, "no write permission for this repository")
    v.request_scan()
    db.session.commit()
    return {"queued": 1}, 202


@bp.delete("/versions/<int:vid>")
@require()
def delete_version(user, vid):
    v = get_version(vid, user)
    if not can_write(v.package.repository, user):
        raise ApiError(403, "no write permission for this repository")
    services.delete_version(v, user)
    db.session.commit()
    return "", 204


# --- vulnerabilities ----------------------------------------------------------------------

@bp.get("/vulnerabilities")
@require()
def list_vulnerabilities(user):
    V = Vulnerability
    q = (db.session.query(V.vuln_id, func.max(V.severity), func.max(V.title), func.max(V.url),
                          func.count(func.distinct(V.version_id))).group_by(V.vuln_id))
    if request.args.get("severity"):
        q = q.filter(V.severity == request.args["severity"].upper())
    if request.args.get("q"):
        q = q.filter(or_(V.vuln_id.contains(request.args["q"]), V.pkg_name.contains(request.args["q"])))
    rows = q.order_by(func.count(func.distinct(V.version_id)).desc()).limit(1000).all()
    return {"items": [{"id": i, "severity": s, "title": t, "url": u, "affected_versions": n}
                      for i, s, t, u, n in rows]}


@bp.get("/vulnerabilities/<vuln_id>")
@require()
def get_vulnerability(user, vuln_id):
    findings = Vulnerability.query.filter_by(vuln_id=vuln_id).all()
    if not findings:
        raise ApiError(404, "vulnerability not found in any artifact")
    return {"id": vuln_id, "severity": findings[0].severity, "title": findings[0].title, "url": findings[0].url,
            "affected": [{**vuln_json(f), "version": version_json(f.version)} for f in findings
                         if can_read(f.version.package.repository, user)]}


# --- reports --------------------------------------------------------------------------------

@bp.get("/reports/downloads")
@require(audit=True)
def report_downloads(user):
    E = DownloadEvent
    q, _ = apply_sort(_query(_filters()), {"time": E.created_at, "user": E.username, "package": E.package_name,
                                           "repo": E.repo_name}, "time", default_dirs={"time": "desc"})
    return paginate(q, event_json)


@bp.get("/reports/usage")
@require(audit=True)
def report_usage(user):
    items = usage_items(_filters())
    return {"items": [{
        "format": i["format"], "repository": i["repo"], "package": i["package"], "version": i["version"],
        "version_id": i["vid"], "downloads": i["pulls"], "users": i["users"], "last_pull": iso(i["last"]),
        "scan": scan_json(i["v"]) if i["v"] else None,
    } for i in items]}


# --- users & tokens -------------------------------------------------------------------------

@bp.get("/users")
@require(audit=True)
def list_users(user):
    return {"items": [user_json(u) for u in User.query.order_by(User.username)]}


@bp.post("/users")
@require(admin=True)
def create_user(user):
    u = services.create_user(body(), user)
    db.session.commit()
    return user_json(u), 201


@bp.patch("/users/<int:uid>")
@require(admin=True)
def update_user(user, uid):
    u = db.session.get(User, uid) or abort(404)
    services.update_user(u, body(), user)
    db.session.commit()
    return user_json(u)


@bp.get("/tokens")
@require()
def list_tokens(user):
    return {"items": [token_json(t) for t in user.tokens]}


@bp.post("/tokens")
@require()
def create_token(user):
    name = (body().get("name") or "api").strip()[:120]
    tok, raw = ApiToken.issue(user, name)
    AuditEvent.log(user.username, "token.create", name)
    db.session.commit()
    return {**token_json(tok), "token": raw}, 201


@bp.delete("/tokens/<int:tid>")
@require()
def delete_token(user, tid):
    tok = db.session.get(ApiToken, tid)
    if tok is None or (tok.user_id != user.id and not user.is_admin):
        raise ApiError(404, "token not found")
    AuditEvent.log(user.username, "token.revoke", tok.name)
    forget_token(tok.token_hash)
    db.session.delete(tok)
    db.session.commit()
    return "", 204


# --- scanner -----------------------------------------------------------------------------------

@bp.get("/scanner")
@require(audit=True)
def scanner_status(user):
    info = trivy_info() or {}
    counts = dict(db.session.query(Version.scan_status, func.count(Version.id)).group_by(Version.scan_status).all())
    return {
        "trivy_version": info.get("Version"),
        "vulnerability_db": info.get("VulnerabilityDB"),
        "java_db": info.get("JavaDB"),
        "worker_heartbeat": settings.get("worker_heartbeat"),
        "workers": worker_list(),
        "last_db_update": settings.get("trivy_db_last_run"),
        "db_update_requested": bool(settings.get("trivy_db_update_requested")),
        "settings": {k: settings.get(k) for k in settings.DEFAULTS},
        "queue": counts,
    }


@bp.put("/scanner/settings")
@require(admin=True)
def scanner_settings(user):
    data = body()
    ints = {"trivy_db_interval_hours", "rescan_interval_hours"}
    for key, value in data.items():
        if key not in settings.DEFAULTS:
            raise ApiError(400, f"unknown setting {key}")
        if key in ints and (not isinstance(value, int) or value < 0):
            raise ApiError(400, f"{key} must be a non-negative integer (hours, 0 = off)")
        settings.put(key, value if key in ints else bool(value))
    AuditEvent.log(user.username, "scanner.settings", str(data)[:500])
    db.session.commit()
    return {"settings": {k: settings.get(k) for k in settings.DEFAULTS}}


@bp.post("/scanner/db-update")
@require(admin=True)
def scanner_db_update(user):
    settings.put("trivy_db_update_requested", True)
    AuditEvent.log(user.username, "scanner.db_update", "api")
    db.session.commit()
    return {"requested": True}, 202


# --- notifications ------------------------------------------------------------------------------

@bp.get("/notifications")
@require(audit=True)
def get_notifications(user):
    from .. import notifications
    from ..models import Notification
    recent = Notification.query.order_by(Notification.created_at.desc()).limit(50).all()
    return {"config": notifications.get_config(), "smtp_configured": notifications.smtp_configured(),
            "history": [{"time": iso(n.created_at), "repository": n.repo_name, "package": n.package_name,
                         "version": n.version_name, "version_id": n.version_id, "trigger": n.trigger,
                         "max_severity": n.max_severity, "findings": n.findings, "sent_at": iso(n.sent_at),
                         "recipients": n.recipients, "error": n.error} for n in recent]}


@bp.put("/notifications")
@require(admin=True)
def put_notifications(user):
    from .. import notifications
    cfg = services.parse_alert_config({**notifications.get_config(), **body()})
    settings.put("alerts", cfg)
    AuditEvent.log(user.username, "alerts.settings", f"enabled={cfg['enabled']} threshold={cfg['threshold']}")
    db.session.commit()
    return {"config": cfg}


@bp.post("/notifications/test")
@require(admin=True)
def test_notification(user):
    from .. import notifications
    to = (request.get_json(silent=True) or {}).get("to") or notifications.get_config()["recipients"]
    to = [to] if isinstance(to, str) else to
    if not notifications.smtp_configured():
        raise ApiError(409, "SMTP is not configured")
    if not to:
        raise ApiError(400, "no recipient")
    try:
        notifications.send_mail(to, "[Florepo] Test notification",
                                "This is a test e-mail from Florepo. Alerting works.")
    except Exception as exc:
        raise ApiError(502, f"sending failed: {exc}")
    return {"sent_to": to}


# --- network (outbound proxy) ----------------------------------------------------------------------

def _network_json():
    from .. import netproxy
    cfg = netproxy.global_config()
    return {"http_proxy": netproxy.mask(cfg["http_proxy"]), "https_proxy": netproxy.mask(cfg["https_proxy"]),
            "no_proxy": cfg["no_proxy"],
            "repositories": [{"name": r.name, "proxy_mode": r.proxy_mode, "proxy_url": netproxy.mask(r.proxy_url)}
                             for r in Repository.query.filter_by(kind="proxy").order_by(Repository.name)]}


@bp.get("/network")
@require(admin=True)
def get_network(user):
    return _network_json()


@bp.put("/network")
@require(admin=True)
def put_network(user):
    from .. import netproxy
    cfg = services.parse_network_config(body(), netproxy.global_config())
    settings.put("outbound_proxy", cfg)
    AuditEvent.log(user.username, "network.settings", f"http={netproxy.mask(cfg['http_proxy'])}")
    db.session.commit()
    return _network_json()


@bp.post("/network/test")
@require(admin=True)
def test_network(user):
    data = request.get_json(silent=True) or {}
    return services.test_connection(data.get("url") or "https://pypi.org/simple/", data.get("repository"))


# --- storage & quotas -----------------------------------------------------------------------------

@bp.get("/storage")
@require(audit=True)
def get_storage(user):
    repos = [{"name": r.name, "format": r.format, "kind": r.kind, "used_bytes": quotas.repo_usage(r),
              "quota_bytes": r.quota_bytes} for r in Repository.query.order_by(Repository.name)]
    out = {**storage.describe(), "default_user_quota_bytes": quotas.default_user_quota(), "repositories": repos,
           "total_bytes": sum(r["used_bytes"] for r in repos),
           "metadata_cache": metacache.info()}
    if request.args.get("check") and user.is_admin:
        out["check"] = storage.check()
    return out


@bp.put("/storage/quotas")
@require(admin=True)
def put_quota_settings(user):
    data = body()
    raw = data["default_user_quota_bytes"] if "default_user_quota_bytes" in data else data.get("default_user_quota")
    values = services.parse_quota_settings({"default_user_quota": raw})
    for k, v in values.items():
        settings.put(k, v)
    AuditEvent.log(user.username, "quota.settings", f"default user quota={values['quota_default_user_bytes']}")
    db.session.commit()
    quotas.forget()
    return {"default_user_quota_bytes": values["quota_default_user_bytes"] or None}


# --- malware scanning (ClamAV) ----------------------------------------------------------------------

def _clamav_json():
    cfg = malware.get_config()
    counts = dict(db.session.query(Version.malware_status, func.count(Version.id)).group_by(Version.malware_status).all())
    return {**cfg, "engine": malware.engine_info(cfg) if cfg["enabled"] else None, "counts": counts}


@bp.get("/clamav")
@require(audit=True)
def get_clamav(user):
    return _clamav_json()


@bp.put("/clamav")
@require(admin=True)
def put_clamav(user):
    current = malware.get_config()
    cfg = services.parse_clamav_config({**current, **body()}, current)
    settings.put("clamav", cfg)
    AuditEvent.log(user.username, "clamav.settings", f"enabled={cfg['enabled']} {cfg['host']}:{cfg['port']}")
    db.session.commit()
    malware.forget_policy()
    return _clamav_json()


# --- LDAP ----------------------------------------------------------------------------------------------------

def _ldap_json():
    cfg = dict(ldap_auth.get_config())
    cfg["bind_password"] = ldap_auth.SECRET_MASK if cfg.get("bind_password") else ""
    cfg["last_sync"] = settings.get("ldap_last_sync")
    cfg["user_count"] = User.query.filter_by(auth_source="ldap").count()
    return cfg


@bp.get("/ldap")
@require(admin=True)
def get_ldap(user):
    return _ldap_json()


@bp.put("/ldap")
@require(admin=True)
def put_ldap(user):
    cfg = services.parse_ldap_config(body(), settings.get("ldap") or {})
    settings.put("ldap", cfg)
    AuditEvent.log(user.username, "ldap.settings", f"enabled={cfg['enabled']} mappings={len(cfg['mappings'])}")
    db.session.commit()
    return _ldap_json()


@bp.post("/ldap/test")
@require(admin=True)
def test_ldap(user):
    data = request.get_json(silent=True) or {}
    cfg = services.parse_ldap_config(data.get("config") or {}, settings.get("ldap") or {})
    return ldap_auth.test(cfg, data.get("username") or None, data.get("password") or None)


@bp.post("/ldap/sync")
@require(admin=True)
def sync_ldap(user):
    if not ldap_auth.enabled():
        raise ApiError(400, "LDAP is not enabled")
    summary = ldap_auth.sync_all()
    AuditEvent.log(user.username, "ldap.sync", f"{summary['users']} users")
    db.session.commit()
    return summary
