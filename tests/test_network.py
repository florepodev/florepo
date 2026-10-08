from app import netproxy, settings
from app.extensions import db
from app.models import Repository
from tests.test_api import bearer


def test_resolve_modes_and_no_proxy(app):
    with app.app_context():
        settings.put("outbound_proxy", {"http_proxy": "http://u:secret@proxy:3128", "https_proxy": "",
                                        "no_proxy": "localhost,.corp.example,10.0.0.0/8"})
        db.session.commit()
        glob = Repository(name="g", format="pypi", kind="proxy", proxy_mode="global")
        direct = Repository(name="d", format="pypi", kind="proxy", proxy_mode="none")
        custom = Repository(name="c", format="pypi", kind="proxy", proxy_mode="custom", proxy_url="http://other:8080")
        assert netproxy.resolve(glob)[0] == {"http": "http://u:secret@proxy:3128", "https": "http://u:secret@proxy:3128"}
        assert netproxy.resolve(direct)[0] == {}
        assert netproxy.resolve(custom)[0] == {"http": "http://other:8080", "https": "http://other:8080"}
        assert netproxy.mask("http://u:secret@proxy:3128") == "http://u:****@proxy:3128"
        env = netproxy.subprocess_env({"PATH": "/bin", "https_proxy": "http://stale:1"})
        assert env["HTTPS_PROXY"] == "http://u:secret@proxy:3128" and env["NO_PROXY"].startswith("localhost")

        seen = []
        orig = netproxy._session.request
        netproxy._session.request = lambda m, url, proxies=None, **kw: seen.append((url, proxies))
        try:
            netproxy.get("https://pypi.org/simple/", repo=glob)
            netproxy.get("https://pkg.corp.example/simple/", repo=glob)   # no_proxy domain
            netproxy.get("http://10.1.2.3/x", repo=glob)                  # no_proxy CIDR
            netproxy.get("https://pypi.org/simple/", repo=direct)
        finally:
            netproxy._session.request = orig
        assert seen[0][1]["https"].startswith("http://u:secret@proxy") and seen[1][1] == {} and seen[2][1] == {}
        assert seen[3][1] == {}


def test_network_ui_and_api(app):
    c = app.test_client()
    h = bearer(c)
    r = c.put("/api/v1/network", headers=h, json={"http_proxy": "http://bob:pw@proxy.corp:3128", "no_proxy": "a, b"})
    assert r.status_code == 200 and r.json["http_proxy"] == "http://bob:****@proxy.corp:3128"
    assert r.json["no_proxy"] == "a,b"
    # sending the masked value back keeps the stored password
    c.put("/api/v1/network", headers=h, json={"http_proxy": "http://bob:****@proxy.corp:3128"})
    with app.app_context():
        assert netproxy.global_config()["http_proxy"] == "http://bob:pw@proxy.corp:3128"
    assert c.put("/api/v1/network", headers=h, json={"http_proxy": "proxy:3128"}).status_code == 400

    r = c.post("/api/v1/repositories", headers=h, json={"name": "np", "format": "npm", "kind": "proxy",
                                                        "proxy_mode": "custom", "proxy_url": "http://x:1@p:8080"})
    assert r.status_code == 201 and r.json["proxy_mode"] == "custom"
    assert c.patch("/api/v1/repositories/np", headers=h, json={"proxy_mode": "custom", "proxy_url": ""}).status_code == 200
    with app.app_context():
        assert Repository.query.filter_by(name="np").one().proxy_url == "http://x:1@p:8080"  # unchanged
    assert c.patch("/api/v1/repositories/np", headers=h, json={"proxy_mode": "bogus"}).status_code == 400
    c.patch("/api/v1/repositories/np", headers=h, json={"proxy_mode": "none"})
    with app.app_context():
        repo = Repository.query.filter_by(name="np").one()
        assert repo.proxy_mode == "none" and repo.proxy_url is None

    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    page = c.get("/admin/network")
    assert page.status_code == 200 and b"bob:****@proxy.corp" in page.data and b"pw@" not in page.data
    assert c.get("/repos/np/edit").status_code == 200
    r = c.post("/admin/network", data={"http_proxy": "http://bob:****@proxy.corp:3128", "https_proxy": "",
                                       "no_proxy": "localhost"})
    assert r.status_code == 302
    with app.app_context():
        assert netproxy.global_config()["http_proxy"] == "http://bob:pw@proxy.corp:3128"


def test_upstream_requests_use_repo_proxy(app, monkeypatch):
    """PyPI proxy fetches go through netproxy with the repository's settings."""
    from app.blueprints import pypi

    calls = []

    class Resp:
        status_code = 404

    monkeypatch.setattr(netproxy, "get", lambda url, repo=None, **kw: calls.append((url, repo.name)) or Resp())
    with app.app_context():
        db.session.add(Repository(name="pp", format="pypi", kind="proxy", upstream_url="https://pypi.example"))
        db.session.commit()
    from tests.test_registries import basic
    app.test_client().get("/pypi/pp/simple/nothing/", headers=basic())
    assert calls == [("https://pypi.example/simple/nothing/", "pp")]
    assert pypi.upstream_get.__module__ == "app.blueprints.common"
