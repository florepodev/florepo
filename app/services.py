"""Domain operations shared by the web UI and the REST API (validation + audit logging)."""
import re

from . import netproxy, quotas
from .extensions import db
from .models import (DEFAULT_UPSTREAMS, FORMATS, KINDS, OS_FORMATS, ROLES, SEVERITIES, AuditEvent, DockerBlobLink,
                     DockerManifest, DockerUpload, Repository, User)

REPO_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,80}$")
DOCKER_HUB = "https://registry-1.docker.io"


class ValidationError(ValueError):
    pass


# --- repositories ---------------------------------------------------------------

def apply_repository_settings(repo, data):
    """Apply the mutable settings present in `data` (missing keys are left unchanged)."""
    if "description" in data:
        repo.description = (data["description"] or "").strip()[:255]
    for key in ("public", "allow_redeploy"):
        if key in data:
            setattr(repo, key, bool(data[key]))
    if "block_severity" in data:
        sev = (data["block_severity"] or "").upper() or None
        if sev and sev not in SEVERITIES:
            raise ValidationError(f"block_severity must be one of {', '.join(SEVERITIES)} or empty")
        repo.block_severity = sev
    if "distro" in data and repo.format in OS_FORMATS:
        from .scanner import parse_distro

        value = (data["distro"] or "").strip()
        if value and parse_distro(value) is None:
            raise ValidationError("distro must look like debian:12, ubuntu:24.04, alpine:3.20, rocky:9 or alma:9")
        repo.distro = value or None
    if "cache_retention_days" in data and repo.kind == "proxy":
        raw = data["cache_retention_days"]
        try:
            days = int(raw) if raw not in (None, "") else 0
        except (TypeError, ValueError):
            raise ValidationError("cache_retention_days must be a number of days (0 = keep forever)")
        if not 0 <= days <= 3650:
            raise ValidationError("cache_retention_days must be between 0 and 3650")
        repo.cache_retention_days = days or None
    if "quota" in data or "quota_bytes" in data:
        raw = data["quota_bytes"] if "quota_bytes" in data else data["quota"]
        try:
            repo.quota_bytes = quotas.parse_size(raw)
        except ValueError as exc:
            raise ValidationError(f"quota: {exc}")
    if repo.kind == "proxy":
        if "upstream_url" in data or not repo.upstream_url:
            default = DEFAULT_UPSTREAMS.get(repo.format) or (DOCKER_HUB if repo.format == "docker" else "")
            url = (data.get("upstream_url") or default).strip()
            if not url:
                raise ValidationError(f"upstream_url is required for {repo.format} proxy repositories")
            if not url.startswith(("http://", "https://")):
                raise ValidationError("upstream_url must be an http(s) URL")
            repo.upstream_url = url.rstrip("/")
        if "upstream_username" in data:
            repo.upstream_username = (data["upstream_username"] or "").strip() or None
        if data.get("upstream_password"):
            repo.upstream_password = data["upstream_password"]
        if data.get("clear_upstream_password"):
            repo.upstream_password = None
        if "proxy_mode" in data:
            mode = data["proxy_mode"] or "global"
            if mode not in netproxy.MODES:
                raise ValidationError(f"proxy_mode must be one of {', '.join(netproxy.MODES)}")
            url = (data.get("proxy_url") or "").strip()
            if mode == "custom":
                if not url and not repo.proxy_url:
                    raise ValidationError("proxy_url is required for proxy_mode=custom")
                if url and url != netproxy.mask(repo.proxy_url):  # masked value = unchanged
                    try:
                        repo.proxy_url = netproxy.validate_url(url)
                    except ValueError as exc:
                        raise ValidationError(str(exc))
            else:
                repo.proxy_url = None
            repo.proxy_mode = mode


def create_repository(data, actor):
    name = (data.get("name") or "").strip().lower()
    fmt, kind = data.get("format"), data.get("kind") or "hosted"
    if not REPO_NAME_RE.match(name):
        raise ValidationError("Invalid name (a-z, 0-9, . _ -, max. 64 characters)")
    if fmt not in FORMATS:
        raise ValidationError(f"format must be one of {', '.join(FORMATS)}")
    if kind not in KINDS:
        raise ValidationError(f"kind must be one of {', '.join(KINDS)}")
    if Repository.query.filter_by(name=name).first():
        raise ValidationError("Repository already exists")
    repo = Repository(name=name, format=fmt, kind=kind, allow_redeploy=fmt == "docker")
    apply_repository_settings(repo, data)
    db.session.add(repo)
    AuditEvent.log(actor.username, "repo.create", f"{fmt}/{kind}/{name}")
    return repo


def update_repository(repo, data, actor):
    apply_repository_settings(repo, data)
    AuditEvent.log(actor.username, "repo.update", repo.name)


def delete_repository(repo, actor):
    DockerManifest.query.filter_by(repository_id=repo.id).delete()
    DockerUpload.query.filter_by(repository_id=repo.id).delete()
    DockerBlobLink.query.filter_by(repository_id=repo.id).delete()
    AuditEvent.log(actor.username, "repo.delete", repo.name)
    db.session.delete(repo)


# --- users ------------------------------------------------------------------------

def create_user(data, actor):
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "reader"
    if not USERNAME_RE.match(username):
        raise ValidationError("Invalid username (2-80 characters: letters, digits, . _ -)")
    if len(password) < 8:
        raise ValidationError("Password needs at least 8 characters")
    if role not in ROLES:
        raise ValidationError(f"role must be one of {', '.join(ROLES)}")
    if User.query.filter_by(username=username).first():
        raise ValidationError("User already exists")
    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    extra = {k: data[k] for k in ("restrict_deploy", "deploy_repos", "quota", "quota_bytes") if k in data}
    if extra:
        update_user(user, extra, actor, log=False)
    AuditEvent.log(actor.username, "user.create", f"{username} ({role})")
    return user


def update_user(user, data, actor, log=True):
    """data keys (all optional): role, active, password, restrict_deploy, deploy_repos (names or ids), quota.

    Role and deploy repositories of LDAP users are managed by the group mapping (Administration →
    Authentication) and cannot be changed here."""
    if user.id == actor.id and (data.get("role", user.role) != "admin" or not data.get("active", user.active)):
        raise ValidationError("You cannot demote or disable yourself")
    if "quota" in data or "quota_bytes" in data:
        raw = data["quota_bytes"] if "quota_bytes" in data else data["quota"]
        if raw in (None, ""):
            user.quota_bytes = None  # global default
        else:
            try:
                user.quota_bytes = quotas.parse_size(raw) or 0  # 0 = unlimited
            except ValueError as exc:
                raise ValidationError(f"quota: {exc}")
    if user.is_ldap:
        if data.get("password") or data.get("role", user.role) != user.role:
            raise ValidationError("role and password of LDAP users are managed by the directory (group mapping)")
        data = {k: v for k, v in data.items() if k == "active"}  # deploy repositories come from the mapping too
    if "role" in data:
        if data["role"] not in ROLES:
            raise ValidationError(f"role must be one of {', '.join(ROLES)}")
        user.role = data["role"]
    if "active" in data:
        user.active = bool(data["active"])
    if data.get("password"):
        if len(data["password"]) < 8:
            raise ValidationError("Password too short (at least 8 characters)")
        user.set_password(data["password"])
    if "restrict_deploy" in data:
        user.restrict_deploy = bool(data["restrict_deploy"])
    if "deploy_repos" in data:
        wanted = {str(x) for x in data["deploy_repos"] or []}
        hosted = Repository.query.filter_by(kind="hosted").all()
        repos = [r for r in hosted if str(r.id) in wanted or r.name in wanted]
        unknown = wanted - {str(r.id) for r in repos} - {r.name for r in repos}
        if unknown:
            raise ValidationError(f"Unknown or non-hosted repositories: {', '.join(sorted(unknown))}")
        user.deploy_repos = repos
    if not user.restrict_deploy:
        user.deploy_repos = []
    if log:
        scope = "all" if not user.restrict_deploy else (", ".join(r.name for r in user.deploy_repos) or "none")
        AuditEvent.log(actor.username, "user.update", f"{user.username} role={user.role} deploy={scope}")


# --- notifications --------------------------------------------------------------

EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")


def parse_alert_config(data):
    """Validate the alert rule. recipients may be a list or a comma/semicolon/newline separated string."""
    recipients = data.get("recipients") or []
    if isinstance(recipients, str):
        recipients = re.split(r"[,;\s]+", recipients)
    recipients = [r.strip() for r in recipients if r and r.strip()]
    bad = [r for r in recipients if not EMAIL_RE.match(r)]
    if bad:
        raise ValidationError(f"Invalid e-mail address: {', '.join(bad)}")
    threshold = (data.get("threshold") or "HIGH").upper()
    if threshold not in SEVERITIES[:4]:
        raise ValidationError("threshold must be CRITICAL, HIGH, MEDIUM or LOW")
    repos = [r for r in (data.get("repos") or []) if r]
    unknown = set(repos) - {r.name for r in Repository.query.all()}
    if unknown:
        raise ValidationError(f"Unknown repositories: {', '.join(sorted(unknown))}")
    enabled = bool(data.get("enabled"))
    if enabled and not recipients:
        raise ValidationError("At least one recipient is required to enable alerts")
    return {"enabled": enabled, "recipients": recipients, "threshold": threshold,
            "only_new": bool(data.get("only_new", True)), "include_uploads": bool(data.get("include_uploads")),
            "repos": sorted(repos)}


# --- outbound proxy --------------------------------------------------------------

def parse_network_config(data, current):
    """Validate the global outbound proxy settings. Masked passwords (****) keep the stored value."""
    out = {}
    for key in ("http_proxy", "https_proxy"):
        value = (data.get(key, current.get(key)) or "").strip()
        if value and value == netproxy.mask(current.get(key)):
            value = current.get(key)
        try:
            out[key] = netproxy.validate_url(value)
        except ValueError as exc:
            raise ValidationError(str(exc))
    out["no_proxy"] = ",".join(x.strip() for x in re.split(r"[,\s]+", data.get("no_proxy", current.get("no_proxy")) or "")
                               if x.strip())
    return out


def test_connection(url, repo_name=None):
    """Try an upstream URL with the effective proxy settings (global or of a repository)."""
    import time

    repo = Repository.query.filter_by(name=repo_name).first() if repo_name else None
    proxies, no_proxy = netproxy.resolve(repo)
    via = netproxy.mask(proxies.get("https") or proxies.get("http") or "") or "direct"
    t0 = time.time()
    try:
        r = netproxy.get(url, repo=repo, timeout=15, allow_redirects=True)
        ok = r.status_code < 400
        return {"ok": ok, "url": url, "via": via, "status": r.status_code, "repo": repo_name,
                "ms": round((time.time() - t0) * 1000), "error": None if ok else r.reason}
    except Exception as exc:
        return {"ok": False, "url": url, "via": via, "status": None, "repo": repo_name,
                "ms": round((time.time() - t0) * 1000), "error": str(exc)[:300]}


def delete_version(version, actor):
    """Delete a version (and its package when empty); hosted deb/rpm/apk indexes are regenerated."""
    pkg = version.package
    repo = pkg.repository
    AuditEvent.log(actor.username, "version.delete", f"{repo.name}/{pkg.display_name}@{version.version}")
    db.session.delete(version)
    db.session.flush()
    package_gone = not pkg.versions
    if package_gone:
        db.session.delete(pkg)
        db.session.flush()
    if repo.format in OS_FORMATS and not repo.is_proxy:
        from .blueprints.ospkg import rebuild_indexes

        rebuild_indexes(repo)
    return repo, package_gone


# --- quotas, ClamAV, LDAP -----------------------------------------------------------

def parse_quota_settings(data):
    try:
        return {"quota_default_user_bytes": quotas.parse_size(data.get("default_user_quota")) or 0}
    except ValueError as exc:
        raise ValidationError(f"default user quota: {exc}")


def parse_clamav_config(data, current):
    host = (data.get("host", current.get("host")) or "").strip()
    if not re.match(r"^[A-Za-z0-9.:_-]+$", host or "-"):
        raise ValidationError("ClamAV host must be a host name or IP address")
    try:
        port = int(data.get("port", current.get("port")) or 3310)
        max_mb = int(data.get("max_file_mb", current.get("max_file_mb")) or 0)
    except (TypeError, ValueError):
        raise ValidationError("port and max. file size must be numbers")
    if not 1 <= port <= 65535 or not 0 <= max_mb <= 100_000:
        raise ValidationError("port must be 1-65535, max. file size 0-100000 MB")
    enabled = bool(data.get("enabled"))
    if enabled and not host:
        raise ValidationError("a clamd host is required to enable malware scanning")
    return {"enabled": enabled, "host": host, "port": port, "max_file_mb": max_mb,
            "block_infected": bool(data.get("block_infected")), "block_unscanned": bool(data.get("block_unscanned"))}


def parse_ldap_config(data, current):
    """Validate the LDAP settings. A masked/empty bind password keeps the stored one."""
    from . import ldap_auth

    cfg = {**ldap_auth.DEFAULTS, **current}
    urls = data.get("server_urls", cfg["server_urls"])
    if isinstance(urls, str):
        urls = re.split(r"[\s,;]+", urls)
    urls = [u.strip() for u in urls if u and u.strip()]
    bad = [u for u in urls if not re.match(r"^ldaps?://[A-Za-z0-9.\-\[\]:]+(:\d+)?/?$", u)]
    if bad:
        raise ValidationError(f"Invalid LDAP URL: {', '.join(bad)} (expected ldap://host[:port] or ldaps://host[:port])")
    out = {"server_urls": urls}
    for key in ("bind_dn", "user_base", "user_filter", "username_attr", "email_attr", "name_attr", "group_base",
                "group_filter", "ca_cert"):
        out[key] = (data.get(key, cfg[key]) or "").strip()
    pw = data.get("bind_password")
    out["bind_password"] = cfg["bind_password"] if pw in (None, "", ldap_auth.SECRET_MASK) else pw
    if data.get("clear_bind_password"):
        out["bind_password"] = ""
    for key in ("enabled", "start_tls", "verify_tls"):
        out[key] = bool(data.get(key, cfg[key]))
    mode = data.get("group_mode", cfg["group_mode"])
    if mode not in ldap_auth.GROUP_MODES:
        raise ValidationError(f"group_mode must be one of {', '.join(ldap_auth.GROUP_MODES)}")
    out["group_mode"] = mode
    role = data.get("default_role", cfg["default_role"]) or ""
    if role and role not in ROLES:
        raise ValidationError(f"default_role must be empty or one of {', '.join(ROLES)}")
    out["default_role"] = role
    try:
        out["sync_minutes"] = int(data.get("sync_minutes", cfg["sync_minutes"]) or 0)
        out["timeout"] = max(1, min(int(data.get("timeout", cfg["timeout"]) or 10), 120))
    except (TypeError, ValueError):
        raise ValidationError("sync interval and timeout must be numbers")
    try:
        out["mappings"] = ldap_auth.validate_mappings(data.get("mappings", cfg["mappings"]))
    except ValueError as exc:
        raise ValidationError(str(exc))
    if "{username}" not in out["user_filter"]:
        raise ValidationError("user_filter must contain {username}")
    if out["enabled"]:
        if not urls:
            raise ValidationError("At least one LDAP server URL is required")
        if not out["user_base"]:
            raise ValidationError("user_base (search base DN for users) is required")
        if out["group_mode"] == "search" and "{user_dn}" not in out["group_filter"] and "{username}" not in out["group_filter"]:
            raise ValidationError("group_filter must contain {user_dn} or {username}")
    return out
