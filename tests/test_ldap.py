"""LDAP / AD authentication against an in-memory ldap3 mock directory."""
import base64

import pytest
from ldap3 import MOCK_SYNC, Connection, Server

from app import ldap_auth, services, settings
from app.extensions import db
from app.models import Repository, User

BASE = "dc=example,dc=com"
SERVER = None


def _dn(rdn):
    return f"{rdn},{BASE}"


@pytest.fixture()
def directory(app, monkeypatch):
    global SERVER
    SERVER = Server("fake-ldap")
    setup = Connection(SERVER, user=_dn("cn=svc"), password="svc-pass", client_strategy=MOCK_SYNC)
    add = setup.strategy.add_entry
    add(_dn("cn=svc"), {"objectClass": ["person"], "cn": "svc", "userPassword": "svc-pass"})
    for uid, groups in (("jdoe", ["florepo-deployers"]), ("sec", ["florepo-auditors", "florepo-deployers"]),
                        ("nogroup", []), ("boss", ["florepo-admins"])):
        add(_dn(f"uid={uid},ou=people"), {
            "objectClass": ["inetOrgPerson"], "uid": uid, "cn": uid.title(), "mail": f"{uid}@example.com",
            "userPassword": f"{uid}-pass", "memberOf": [_dn(f"cn={g},ou=groups") for g in groups]})
    for g in ("florepo-deployers", "florepo-auditors", "florepo-admins"):
        members = [_dn(f"uid={u},ou=people") for u, gs in (("jdoe", ["florepo-deployers"]),
                                                           ("sec", ["florepo-auditors", "florepo-deployers"]),
                                                           ("boss", ["florepo-admins"])) if g in gs]
        add(_dn(f"cn={g},ou=groups"), {"objectClass": ["groupOfNames"], "cn": g, "member": members})
    setup.bind()

    def fake_connection(cfg, user=None, password=None):
        conn = Connection(SERVER, user=user, password=password, client_strategy=MOCK_SYNC, raise_exceptions=False)
        if not conn.bind():
            raise ldap_auth.LdapError(f"bind as {user} failed: invalidCredentials")
        return conn

    monkeypatch.setattr(ldap_auth, "_connection", fake_connection)
    cfg = {"enabled": True, "server_urls": ["ldaps://ldap.example.com"], "bind_dn": _dn("cn=svc"),
           "bind_password": "svc-pass", "user_base": _dn("ou=people"),
           "user_filter": "(&(objectClass=inetOrgPerson)(uid={username}))", "username_attr": "uid",
           "email_attr": "mail", "name_attr": "cn", "group_mode": "memberof",
           "mappings": [{"group": "florepo-admins", "role": "admin", "repos": []},
                        {"group": _dn("cn=florepo-auditors,ou=groups"), "role": "auditor", "repos": []},
                        {"group": "FLOREPO-DEPLOYERS", "role": "deployer", "repos": ["py"]}],
           "default_role": ""}
    with app.app_context():
        settings.put("ldap", cfg)
        db.session.commit()
    return cfg


def basic(user, pw):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


def test_ldap_login_provisions_user_with_mapped_role(app, directory):
    c = app.test_client()
    r = c.get("/api/v1/whoami", headers=basic("jdoe", "jdoe-pass"))
    assert r.status_code == 200, r.data
    me = r.json
    assert me["auth_source"] == "ldap" and me["role"] == "deployer" and me["restrict_deploy"] is True
    assert me["deploy_repos"] == ["py"] and me["email"] == "jdoe@example.com"
    # first matching mapping wins: auditor before deployer
    assert c.get("/api/v1/whoami", headers=basic("sec", "sec-pass")).json["role"] == "auditor"
    assert c.get("/api/v1/whoami", headers=basic("boss", "boss-pass")).json["role"] == "admin"
    # wrong / empty password, unknown user, user without mapped group
    assert c.get("/api/v1/whoami", headers=basic("jdoe", "wrong")).status_code == 401
    assert c.get("/api/v1/whoami", headers=basic("jdoe", "")).status_code == 401
    assert c.get("/api/v1/whoami", headers=basic("ghost", "x")).status_code == 401
    assert c.get("/api/v1/whoami", headers=basic("nogroup", "nogroup-pass")).status_code == 401
    # UI login + permissions: jdoe may publish to py only
    c.post("/login", data={"username": "JDoe", "password": "jdoe-pass"})
    assert c.get("/tokens").status_code == 200
    with app.app_context():
        u = User.query.filter_by(username="jdoe").one()
        assert u.can_deploy_to(Repository.query.filter_by(name="py").one())
        assert not u.can_deploy_to(Repository.query.filter_by(name="js").one())
        assert u.password_hash == "!ldap" and not u.check_password("jdoe-pass")
        assert User.query.filter_by(auth_source="ldap").count() == 3


def test_local_accounts_win_and_default_role(app, directory):
    c = app.test_client()
    # alice is local: her local password works, LDAP is not consulted
    assert c.get("/api/v1/whoami", headers=basic("alice", "alice-pass")).json["auth_source"] == "local"
    with app.app_context():
        settings.put("ldap", {**directory, "default_role": "reader"})
        db.session.commit()
    assert c.get("/api/v1/whoami", headers=basic("nogroup", "nogroup-pass")).json["role"] == "reader"


def test_ldap_sync_disables_removed_users(app, directory):
    c = app.test_client()
    assert c.get("/api/v1/whoami", headers=basic("jdoe", "jdoe-pass")).status_code == 200
    from app import auth
    auth._BASIC_CACHE.clear()
    # jdoe leaves the group
    SERVER.dit[_dn("uid=jdoe,ou=people")]["memberOf"] = []
    with app.app_context():
        summary = ldap_auth.sync_all()
        assert summary["ok"] and summary["users"] == 1 and summary["disabled"] == 1
        u = User.query.filter_by(username="jdoe").one()
        assert u.directory_disabled and not u.is_active
    assert c.get("/api/v1/whoami", headers=basic("jdoe", "jdoe-pass")).status_code == 401


def test_ldap_admin_page_validation_and_test(app, directory):
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    page = c.get("/admin/auth")
    assert page.status_code == 200 and b"Group" in page.data
    res = c.post("/api/v1/ldap/test", json={"username": "sec", "password": "sec-pass"}).json
    assert res["ok"] and res["role"] == "auditor" and len(res["groups"]) == 2
    assert c.get("/api/v1/ldap").json["bind_password"] == ldap_auth.SECRET_MASK
    with app.app_context():
        with pytest.raises(services.ValidationError):
            services.parse_ldap_config({"server_urls": "http://nope"}, {})
        with pytest.raises(services.ValidationError):
            services.parse_ldap_config({"mappings": [{"group": "g", "role": "reader", "repos": "py"}]}, {})
        with pytest.raises(services.ValidationError):
            services.parse_ldap_config({"user_filter": "(uid=x)"}, {})
        kept = services.parse_ldap_config({"bind_password": ldap_auth.SECRET_MASK}, directory)
        assert kept["bind_password"] == "svc-pass"
    # role of LDAP users cannot be changed locally
    assert app.test_client().get("/api/v1/whoami", headers=basic("jdoe", "jdoe-pass")).status_code == 200
    with app.app_context():
        uid = User.query.filter_by(username="jdoe").one().id
    r = c.patch(f"/api/v1/users/{uid}", json={"role": "admin"})
    assert r.status_code == 400 and "managed by the directory" in r.json["error"]
    assert c.get(f"/users/{uid}").status_code == 200
