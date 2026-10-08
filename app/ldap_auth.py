"""LDAP / Active Directory authentication with group → role mapping.

Login flow (UI, HTTP Basic of package clients, `docker login`):

1. bind with the service account (or anonymously), search the user with `user_filter`
2. bind as the found DN with the given password (empty passwords are rejected – no unauthenticated binds)
3. read the user's groups – `memberof` (memberOf attribute; AD and OpenLDAP with the memberof overlay),
   `ad_nested` (AD LDAP_MATCHING_RULE_IN_CHAIN, includes nested groups) or `search` (group search filter)
4. the first mapping whose group matches (full DN or CN, case-insensitive) decides the role; deployers get
   write access to the union of the repositories of all matching deployer mappings (no list = all repositories)
5. the local account is created / updated (auth_source=ldap, no local password)

Users without a matching group are refused unless `default_role` is set. The leader worker re-checks all
LDAP users every `sync_minutes`: accounts that were removed, disabled in AD or dropped from all mapped groups
are deactivated (`directory_disabled`), which also invalidates their API tokens.
Local accounts (e.g. the bootstrap admin) keep working and are never taken over by LDAP.
"""
import ssl
from datetime import datetime, timedelta

from flask import current_app

from . import settings
from .extensions import db
from .models import ROLES, AuditEvent, Repository, User, utcnow

DEFAULTS = {
    "enabled": False,
    "server_urls": [],  # tried in order: ["ldaps://dc1.corp.example.com", "ldaps://dc2.corp.example.com"]
    "start_tls": False,
    "verify_tls": True,
    "ca_cert": "",  # PEM of the issuing CA (empty = system trust store)
    "bind_dn": "",
    "bind_password": "",
    "user_base": "",
    "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
    "username_attr": "sAMAccountName",
    "email_attr": "mail",
    "name_attr": "displayName",
    "group_mode": "memberof",  # memberof | ad_nested | search
    "group_base": "",
    "group_filter": "(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))",
    "mappings": [],  # [{"group": "CN=florepo-admins,OU=Groups,DC=corp,DC=example,DC=com", "role": "admin", "repos": []}]
    "default_role": "",  # "" = deny users without a mapped group, or one of ROLES
    "sync_minutes": 60,
    "timeout": 10,
}
GROUP_MODES = ["memberof", "ad_nested", "search"]
PRESETS = {
    "ad": {"user_filter": "(&(objectClass=user)(sAMAccountName={username}))", "username_attr": "sAMAccountName",
           "email_attr": "mail", "name_attr": "displayName", "group_mode": "ad_nested"},
    "openldap": {"user_filter": "(&(objectClass=inetOrgPerson)(uid={username}))", "username_attr": "uid",
                 "email_attr": "mail", "name_attr": "cn", "group_mode": "search",
                 "group_filter": "(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))"},
}
AD_ACCOUNTDISABLE = 0x2
SECRET_MASK = "********"


class LdapError(Exception):
    pass


def get_config():
    return {**DEFAULTS, **(settings.get("ldap") or {})}


def enabled():
    cfg = get_config()
    return bool(cfg["enabled"] and cfg["server_urls"])


# --- connection -----------------------------------------------------------------------------------

def _tls(cfg):
    import ldap3

    return ldap3.Tls(validate=ssl.CERT_REQUIRED if cfg["verify_tls"] else ssl.CERT_NONE,
                     ca_certs_data=cfg["ca_cert"] or None)


def _connection(cfg, user=None, password=None):
    """Bound connection or raises LdapError (wrong credentials, server unreachable, TLS problems)."""
    import ldap3
    from ldap3.core.exceptions import LDAPException

    servers = [ldap3.Server(url, use_ssl=url.lower().startswith("ldaps://"), tls=_tls(cfg), get_info=ldap3.NONE,
                            connect_timeout=int(cfg["timeout"])) for url in cfg["server_urls"]]
    pool = ldap3.ServerPool(servers, ldap3.FIRST, active=1, exhaust=True)
    try:
        conn = ldap3.Connection(pool, user=user, password=password, read_only=True, raise_exceptions=False,
                                receive_timeout=int(cfg["timeout"]), auto_referrals=False)
        conn.open()
        if cfg["start_tls"] and not any(u.lower().startswith("ldaps://") for u in cfg["server_urls"]):
            conn.start_tls()
        if not conn.bind():
            desc = (conn.result or {}).get("description") or "bind failed"
            conn.unbind()
            raise LdapError(f"bind as {user or 'anonymous'} failed: {desc}")
        return conn
    except LDAPException as exc:
        raise LdapError(f"LDAP server not reachable: {exc}")


def _escape(value):
    from ldap3.utils.conv import escape_filter_chars

    return escape_filter_chars(value)


def _cn(dn):
    try:
        from ldap3.utils.dn import parse_dn

        return parse_dn(dn)[0][1]
    except Exception:
        return dn.split(",", 1)[0].split("=", 1)[-1]


def _first(attrs, name):
    value = attrs.get(name)
    if isinstance(value, list):
        value = value[0] if value else None
    return value


def _entries(conn):
    return [e for e in (conn.response or []) if e.get("type") == "searchResEntry"]


# --- directory lookups -------------------------------------------------------------------------------

def find_user(cfg, conn, username):
    import ldap3

    flt = cfg["user_filter"].replace("{username}", _escape(username))
    attrs = list({a for a in (cfg["username_attr"], cfg["email_attr"], cfg["name_attr"], "memberOf",
                              "userAccountControl") if a})
    conn.search(cfg["user_base"], flt, ldap3.SUBTREE, attributes=attrs, size_limit=2)
    found = _entries(conn)
    if len(found) != 1:
        return None
    e = found[0]
    return {"dn": e["dn"], "attributes": dict(e.get("attributes") or {})}


def user_groups(cfg, conn, entry, username):
    import ldap3

    mode = cfg["group_mode"]
    if mode == "memberof":
        groups = entry["attributes"].get("memberOf") or []
        return [groups] if isinstance(groups, str) else list(groups)
    if mode == "ad_nested":
        flt = f"(member:1.2.840.113556.1.4.1941:={_escape(entry['dn'])})"
    else:
        flt = cfg["group_filter"].replace("{user_dn}", _escape(entry["dn"])).replace("{username}", _escape(username))
    conn.search(cfg["group_base"] or cfg["user_base"], flt, ldap3.SUBTREE, attributes=["cn"])
    return [e["dn"] for e in _entries(conn)]


def resolve_access(cfg, groups):
    """(role or None, deploy repos (None = all), matched mappings) for a list of group DNs."""
    names = {g.lower() for g in groups} | {_cn(g).lower() for g in groups}
    matched = [m for m in cfg["mappings"] if (m.get("group") or "").strip().lower() in names]
    role = matched[0]["role"] if matched else (cfg["default_role"] or None)
    repos = None
    if role == "deployer":
        rules = [m for m in matched if m["role"] == "deployer"]
        if rules and all(m.get("repos") for m in rules):
            repos = sorted({r for m in rules for r in m["repos"]})
    return role, repos, matched


def _disabled_in_directory(entry):
    try:
        return bool(int(_first(entry["attributes"], "userAccountControl") or 0) & AD_ACCOUNTDISABLE)
    except (TypeError, ValueError):
        return False


def _lookup(cfg, username, password=None):
    """Directory view of a user: {'entry', 'groups', 'role', 'repos', 'matched', 'disabled'} or None if unknown.
    With `password` the user's credentials are verified as well (LdapError if wrong)."""
    svc = _connection(cfg, cfg["bind_dn"] or None, cfg["bind_password"] or None)
    try:
        entry = find_user(cfg, svc, username)
        if entry is None:
            return None
        if password is not None:
            _connection(cfg, entry["dn"], password).unbind()
        groups = user_groups(cfg, svc, entry, username)
    finally:
        svc.unbind()
    role, repos, matched = resolve_access(cfg, groups)
    return {"entry": entry, "groups": groups, "role": role, "repos": repos, "matched": matched,
            "disabled": _disabled_in_directory(entry)}


# --- local accounts ---------------------------------------------------------------------------------------

def canonical_username(cfg, entry, typed):
    return str(_first(entry["attributes"], cfg["username_attr"]) or typed).lower()


def _apply(user, cfg, info, actor="ldap"):
    entry = info["entry"]
    before = (user.role, user.restrict_deploy, tuple(r.name for r in user.deploy_repos), user.directory_disabled)
    user.ldap_dn = entry["dn"][:512]
    user.email = (_first(entry["attributes"], cfg["email_attr"]) or None) if cfg["email_attr"] else None
    user.display_name = (_first(entry["attributes"], cfg["name_attr"]) or None) if cfg["name_attr"] else None
    user.directory_disabled = info["role"] is None or info["disabled"]
    if info["role"]:
        user.role = info["role"]
        user.restrict_deploy = info["repos"] is not None
        user.deploy_repos = (Repository.query.filter(Repository.name.in_(info["repos"]), Repository.kind == "hosted")
                             .all() if info["repos"] else [])
    after = (user.role, user.restrict_deploy, tuple(r.name for r in user.deploy_repos), user.directory_disabled)
    if before != after and user.id:
        AuditEvent.log(actor, "user.ldap_sync", f"{user.username} role={user.role}"
                       + (" disabled" if user.directory_disabled else ""))


def authenticate(username, password):
    """Verify credentials against the directory and return the (provisioned) local User, else None."""
    cfg = get_config()
    if not enabled() or not username or not password:
        return None
    try:
        info = _lookup(cfg, username, password)
    except LdapError as exc:
        current_app.logger.info("LDAP login of %s failed: %s", username, exc)
        return None
    if info is None:
        return None
    name = canonical_username(cfg, info["entry"], username)
    user = User.query.filter_by(username=name).first()
    if user is not None and user.auth_source != "ldap":
        current_app.logger.warning("LDAP login of %s refused: a local account with that name exists", name)
        return None
    if user is None:
        if info["role"] is None or info["disabled"]:
            return None
        user = User(username=name, role=info["role"], auth_source="ldap", password_hash="!ldap")
        db.session.add(user)
        db.session.flush()
        AuditEvent.log("ldap", "user.ldap_provision", f"{name} ({info['role']})")
    _apply(user, cfg, info)
    user.last_login_at = utcnow()
    db.session.commit()
    if user.directory_disabled or not user.active:
        return None
    return user


def sync_all():
    """Re-check all LDAP users against the directory. Returns a summary dict."""
    cfg = get_config()
    users = User.query.filter_by(auth_source="ldap").all()
    summary = {"at": utcnow().isoformat(timespec="seconds"), "users": len(users), "disabled": 0, "ok": True,
               "error": None}
    try:
        for user in users:
            info = _lookup(cfg, user.username)
            if info is None:
                if not user.directory_disabled:
                    AuditEvent.log("ldap", "user.ldap_sync", f"{user.username} not found in directory - disabled")
                user.directory_disabled = True
            else:
                _apply(user, cfg, info)
            summary["disabled"] += int(user.directory_disabled)
        db.session.commit()
    except LdapError as exc:  # directory unreachable: keep the current state
        db.session.rollback()
        summary.update(ok=False, error=str(exc)[:500])
    settings.put("ldap_last_sync", summary)
    db.session.commit()
    return summary


def sync_if_due():
    if not enabled():
        return None
    minutes = int(get_config()["sync_minutes"] or 0)
    if not minutes:
        return None
    last = (settings.get("ldap_last_sync") or {}).get("at")
    if last and datetime.fromisoformat(last) > utcnow() - timedelta(minutes=minutes):
        return None
    summary = sync_all()
    current_app.logger.info("LDAP sync: %s", summary)
    return summary


def test(cfg, username=None, password=None):
    """Diagnostics for the admin page: connection, service bind, user lookup, groups and resulting role."""
    out = {"ok": False, "steps": []}
    try:
        _connection(cfg, cfg["bind_dn"] or None, cfg["bind_password"] or None).unbind()
        out["steps"].append(f"Connected and bound as {cfg['bind_dn'] or 'anonymous'}")
        if username:
            info = _lookup(cfg, username, password or None)
            if info is None:
                out["steps"].append(f"User '{username}' not found (filter {cfg['user_filter']})")
                return out
            out["steps"].append(f"Found {info['entry']['dn']}")
            if password:
                out["steps"].append("Password verified")
            out["groups"] = info["groups"]
            out["role"] = info["role"]
            out["repos"] = info["repos"]
            out["matched"] = [m["group"] for m in info["matched"]]
            out["disabled"] = info["disabled"]
            out["steps"].append(f"{len(info['groups'])} groups, resulting role: {info['role'] or 'none (login denied)'}"
                                + (", account disabled in directory" if info["disabled"] else ""))
        out["ok"] = True
    except LdapError as exc:
        out["error"] = str(exc)
    return out


def validate_mappings(rows):
    out = []
    known = {r.name for r in Repository.query.filter_by(kind="hosted")}
    for row in rows or []:
        group = (row.get("group") or "").strip()
        if not group:
            continue
        role = row.get("role") or "reader"
        if role not in ROLES:
            raise ValueError(f"mapping for {group}: role must be one of {', '.join(ROLES)}")
        repos = row.get("repos") or []
        if isinstance(repos, str):
            repos = [r.strip() for r in repos.replace(";", ",").split(",")]
        repos = sorted({r for r in repos if r})
        unknown = set(repos) - known
        if unknown:
            raise ValueError(f"mapping for {group}: unknown hosted repositories {', '.join(sorted(unknown))}")
        if repos and role != "deployer":
            raise ValueError(f"mapping for {group}: repositories can only be restricted for the deployer role")
        out.append({"group": group, "role": role, "repos": repos})
    return out
