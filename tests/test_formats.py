"""Maven, Go, NuGet, Cargo, Helm and generic repositories – hosted flows and proxy caching."""
import hashlib
import io
import json
import struct
import tarfile
import zipfile

import yaml

from app.extensions import db
from app.models import ApiToken, DownloadEvent, Repository, User, Version
from tests.test_registries import basic

ALICE = basic("alice", "alice-pass")


def add_repo(app, **kw):
    kw.setdefault("kind", "hosted")
    with app.app_context():
        db.session.add(Repository(**kw))
        db.session.commit()


def token(app, username="admin"):
    with app.app_context():
        _, raw = ApiToken.issue(User.query.filter_by(username=username).one(), "test")
        db.session.commit()
        return raw


class Resp:
    def __init__(self, status, data=b"", ctype="application/octet-stream"):
        self.status_code, self.content = status, data
        self.raw = io.BytesIO(data)
        self.raw.decode_content = True
        self.headers = {"Content-Type": ctype}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeUpstream:
    def __init__(self, files):
        self.files, self.calls = files, []

    def __call__(self, url, repo=None, **kw):
        self.calls.append(url)
        data = self.files.get(url)
        return Resp(200 if data is not None else 404, data or b"")


def patch_upstream(monkeypatch, files, *modules):
    from app.blueprints import common

    up = FakeUpstream(files)
    monkeypatch.setattr(common, "upstream_get", up)
    for m in modules:
        monkeypatch.setattr(m, "upstream_get", up)
    return up


def zip_bytes(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def tgz_bytes(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# --- Maven ---------------------------------------------------------------------------------------------

POM = b"""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version><name>Demo lib</name>
<dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.16</version></dependency>
<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
</dependencies></project>"""


def test_maven_hosted_deploy_metadata_checksums(app):
    add_repo(app, name="libs", format="maven", allow_redeploy=False)
    c = app.test_client()
    base = "/maven/libs/com/example/demo/1.0.0"
    jar = zip_bytes({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n", "com/example/Demo.class": "x"})
    assert c.put(f"{base}/demo-1.0.0.jar", data=jar, headers=basic()).status_code == 201
    assert c.put(f"{base}/demo-1.0.0.jar.sha1", data=b"ignored", headers=basic()).status_code == 201
    assert c.put(f"{base}/demo-1.0.0.pom", data=POM, headers=basic()).status_code == 201
    assert c.put("/maven/libs/com/example/demo/maven-metadata.xml", data=b"<metadata/>", headers=basic()).status_code == 201
    # releases are immutable
    assert c.put(f"{base}/demo-1.0.0.jar", data=jar, headers=basic()).status_code == 409
    assert c.put(f"{base}/demo-1.0.0.jar", data=jar, headers=ALICE).status_code == 403

    meta = c.get("/maven/libs/com/example/demo/maven-metadata.xml", headers=ALICE)
    assert meta.status_code == 200 and b"<version>1.0.0</version>" in meta.data and b"<release>1.0.0</release>" in meta.data
    sha1 = c.get("/maven/libs/com/example/demo/maven-metadata.xml.sha1", headers=ALICE).data.decode()
    assert sha1 == hashlib.sha1(meta.data).hexdigest()
    assert c.get(f"{base}/demo-1.0.0.jar.sha1", headers=ALICE).data.decode() == hashlib.sha1(jar).hexdigest()
    assert c.get(f"{base}/demo-1.0.0.jar.sha256", headers=ALICE).data.decode() == hashlib.sha256(jar).hexdigest()
    dl = c.get(f"{base}/demo-1.0.0.jar", headers=ALICE)
    assert dl.status_code == 200 and dl.data == jar
    assert c.get(f"{base}/demo-9.jar", headers=ALICE).status_code == 404

    # snapshots can be re-deployed; client-generated version metadata is stored
    snap = "/maven/libs/com/example/demo/1.1-SNAPSHOT"
    for _ in range(2):
        assert c.put(f"{snap}/demo-1.1-20261007.120000-1.jar", data=jar, headers=basic()).status_code == 201
    smeta = b"<metadata><versioning><snapshot><timestamp>20261007.120000</timestamp><buildNumber>1</buildNumber></snapshot></versioning></metadata>"
    assert c.put(f"{snap}/maven-metadata.xml", data=smeta, headers=basic()).status_code == 201
    assert c.get(f"{snap}/maven-metadata.xml", headers=ALICE).data == smeta

    with app.app_context():
        v = Version.query.filter_by(version="1.0.0").one()
        assert v.package.name == "com.example:demo" and v.meta["summary"] == "Demo lib"
        assert v.meta["dependencies"] == [{"name": "org.slf4j:slf4j-api", "version": "2.0.16"}]
        assert v.scan_status == "pending"
        assert DownloadEvent.query.one().filename == "demo-1.0.0.jar"
        from app.scanner import purl
        assert purl("maven", "com.example:demo", "1.0.0") == "pkg:maven/com.example/demo@1.0.0"


def test_maven_proxy_caches_artifacts(app, monkeypatch):
    jar = b"PK-fake-jar"
    meta = b"<metadata><versioning><versions><version>1.0</version><version>2.0</version></versions></versioning></metadata>"
    up = patch_upstream(monkeypatch, {
        "https://repo.example/maven2/org/x/lib/maven-metadata.xml": meta,
        "https://repo.example/maven2/org/x/lib/2.0/lib-2.0.jar": jar,
        "https://repo.example/maven2/org/x/lib/2.0/lib-2.0.pom": POM})
    add_repo(app, name="central", format="maven", kind="proxy", upstream_url="https://repo.example/maven2")
    c = app.test_client()
    for _ in range(2):
        assert c.get("/maven/central/org/x/lib/2.0/lib-2.0.jar", headers=ALICE).data == jar
    assert up.calls.count("https://repo.example/maven2/org/x/lib/2.0/lib-2.0.jar") == 1
    assert c.get("/maven/central/org/x/lib/2.0/lib-2.0.jar.sha1", headers=ALICE).data.decode() == hashlib.sha1(jar).hexdigest()
    assert c.get("/maven/central/org/x/lib/maven-metadata.xml", headers=ALICE).data == meta
    assert c.get("/maven/central/org/x/lib/3.0/lib-3.0.jar", headers=ALICE).status_code == 404
    with app.app_context():
        assert [e.cache_hit for e in DownloadEvent.query.order_by(DownloadEvent.id)] == [False, True]
        v = Version.query.one()
        v.scan_status, v.count_critical = "done", 1
        v.package.repository.block_severity = "HIGH"
        db.session.commit()
    assert c.get("/maven/central/org/x/lib/2.0/lib-2.0.jar", headers=ALICE).status_code == 403
    filtered = c.get("/maven/central/org/x/lib/maven-metadata.xml", headers=ALICE).data
    assert b"<version>1.0</version>" in filtered and b"<version>2.0</version>" not in filtered


# --- Go ---------------------------------------------------------------------------------------------------

def test_go_hosted_upload_and_goproxy_protocol(app):
    add_repo(app, name="gomods", format="go")
    c = app.test_client()
    src = zip_bytes({"go.mod": "module git.example.com/team/Hello\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.14.0\n)\n",
                     "hello.go": "package hello\n", "vendor/x/x.go": "package x\n"})
    url = "/go/gomods/git.example.com/team/!hello/@v/v1.2.0.zip"
    r = c.put(url, data=src, headers=basic())
    assert r.status_code == 201 and r.json["repacked"] is True, r.data
    assert c.put(url, data=src, headers=basic()).status_code == 409
    bad = zip_bytes({"go.mod": "module other/mod\n"})
    assert c.put("/go/gomods/git.example.com/team/!hello/@v/v1.3.0.zip", data=bad, headers=basic()).status_code == 400
    assert c.put("/go/gomods/git.example.com/team/!hello/@v/v2.0.0.zip", data=src, headers=basic()).status_code == 400

    assert c.get("/go/gomods/git.example.com/team/!hello/@v/list", headers=ALICE).data == b"v1.2.0\n"
    info = c.get("/go/gomods/git.example.com/team/!hello/@v/v1.2.0.info", headers=ALICE).json
    assert info["Version"] == "v1.2.0"
    assert c.get("/go/gomods/git.example.com/team/!hello/@latest", headers=ALICE).json["Version"] == "v1.2.0"
    assert b"module git.example.com/team/Hello" in c.get("/go/gomods/git.example.com/team/!hello/@v/v1.2.0.mod", headers=ALICE).data
    z = zipfile.ZipFile(io.BytesIO(c.get(url, headers=ALICE).data))
    assert sorted(z.namelist()) == ["git.example.com/team/Hello@v1.2.0/go.mod", "git.example.com/team/Hello@v1.2.0/hello.go"]
    assert c.get("/go/gomods/git.example.com/team/!hello/@v/v9.9.9.info", headers=ALICE).status_code == 404
    with app.app_context():
        v = Version.query.one()
        assert v.package.name == "git.example.com/team/Hello"
        assert v.meta["dependencies"] == [{"name": "golang.org/x/text", "version": "v0.14.0"}]
        from app.scanner import osv_version
        assert osv_version("go", "v1.2.0") == "1.2.0"


def test_go_proxy(app, monkeypatch):
    from app.blueprints import golang

    modzip = zip_bytes({"rsc.io/quote@v1.5.2/go.mod": "module rsc.io/quote\nrequire rsc.io/sampler v1.3.0\n"})
    up = patch_upstream(monkeypatch, {
        "https://goproxy.example/rsc.io/quote/@v/list": b"v1.5.1\nv1.5.2\n",
        "https://goproxy.example/rsc.io/quote/@v/v1.5.2.info": b'{"Version":"v1.5.2"}',
        "https://goproxy.example/rsc.io/quote/@v/v1.5.2.mod": b"module rsc.io/quote\n",
        "https://goproxy.example/rsc.io/quote/@v/v1.5.2.zip": modzip,
        "https://sum.golang.org/lookup/rsc.io/quote@v1.5.2": b"lookup-ok"}, golang)
    add_repo(app, name="golang", format="go", kind="proxy", upstream_url="https://goproxy.example")
    c = app.test_client()
    assert c.get("/go/golang/rsc.io/quote/@v/list", headers=ALICE).data == b"v1.5.1\nv1.5.2\n"
    for _ in range(2):
        assert c.get("/go/golang/rsc.io/quote/@v/v1.5.2.mod", headers=ALICE).data == b"module rsc.io/quote\n"
        assert c.get("/go/golang/rsc.io/quote/@v/v1.5.2.zip", headers=ALICE).data == modzip
    assert up.calls.count("https://goproxy.example/rsc.io/quote/@v/v1.5.2.zip") == 1
    assert up.calls.count("https://goproxy.example/rsc.io/quote/@v/v1.5.2.mod") == 1  # immutable
    assert c.get("/go/golang/rsc.io/quote/@v/v0.0.1.zip", headers=ALICE).status_code == 404
    assert c.get("/go/golang/sumdb/sum.golang.org/supported", headers=ALICE).status_code == 200
    assert c.get("/go/golang/sumdb/sum.golang.org/lookup/rsc.io/quote@v1.5.2", headers=ALICE).data == b"lookup-ok"
    assert c.get("/go/golang/sumdb/evil.example.com/x", headers=ALICE).status_code == 404
    with app.app_context():
        assert Version.query.one().meta["dependencies"] == [{"name": "rsc.io/sampler", "version": "v1.3.0"}]


# --- NuGet -----------------------------------------------------------------------------------------------------

def make_nupkg(pid="Demo.Lib", version="1.0.0"):
    nuspec = f"""<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>
<id>{pid}</id><version>{version}</version><authors>ACME</authors><description>Demo library</description>
<dependencies><group targetFramework="net8.0"><dependency id="Newtonsoft.Json" version="13.0.3" /></group></dependencies>
</metadata></package>"""
    return zip_bytes({f"{pid}.nuspec": nuspec, f"lib/net8.0/{pid}.dll": "MZ"})


def test_nuget_push_restore_registration_search(app):
    add_repo(app, name="nugets", format="nuget")
    c = app.test_client()
    tok = token(app)
    pkg = make_nupkg()
    r = c.put("/nuget/nugets/api/v2/package", headers={"X-NuGet-ApiKey": tok},
              data={"package": (io.BytesIO(pkg), "Demo.Lib.1.0.0.nupkg")}, content_type="multipart/form-data")
    assert r.status_code == 201, r.data
    assert c.put("/nuget/nugets/api/v2/package", headers={"X-NuGet-ApiKey": tok},
                 data={"package": (io.BytesIO(pkg), "x.nupkg")}, content_type="multipart/form-data").status_code == 409
    assert c.put("/nuget/nugets/api/v2/package", headers={"X-NuGet-ApiKey": "flo_invalid"},
                 data={"package": (io.BytesIO(pkg), "x.nupkg")}, content_type="multipart/form-data").status_code == 401

    idx = c.get("/nuget/nugets/index.json", headers=ALICE).json
    types = {r["@type"] for r in idx["resources"]}
    assert {"PackageBaseAddress/3.0.0", "PackagePublish/2.0.0", "SearchQueryService", "RegistrationsBaseUrl/3.6.0"} <= types
    assert c.get("/nuget/nugets/v3-flatcontainer/demo.lib/index.json", headers=ALICE).json == {"versions": ["1.0.0"]}
    dl = c.get("/nuget/nugets/v3-flatcontainer/demo.lib/1.0.0/demo.lib.1.0.0.nupkg", headers=ALICE)
    assert dl.status_code == 200 and dl.data == pkg
    assert b"<id>Demo.Lib</id>" in c.get("/nuget/nugets/v3-flatcontainer/demo.lib/1.0.0/demo.lib.nuspec", headers=ALICE).data
    reg = c.get("/nuget/nugets/registration/demo.lib/index.json", headers=ALICE).json
    leaf = reg["items"][0]["items"][0]
    assert leaf["catalogEntry"]["id"] == "Demo.Lib"
    assert leaf["catalogEntry"]["dependencyGroups"][0]["dependencies"][0]["id"] == "Newtonsoft.Json"
    assert leaf["packageContent"].endswith("/v3-flatcontainer/demo.lib/1.0.0/demo.lib.1.0.0.nupkg")
    search = c.get("/nuget/nugets/query?q=demo", headers=ALICE).json
    assert search["totalHits"] == 1 and search["data"][0]["id"] == "Demo.Lib"
    assert c.delete("/nuget/nugets/api/v2/package/Demo.Lib/1.0.0", headers={"X-NuGet-ApiKey": tok}).status_code == 204
    assert c.get("/nuget/nugets/v3-flatcontainer/demo.lib/index.json", headers=ALICE).status_code == 404
    from app.blueprints.nuget import normalize_version
    assert normalize_version("1.0") == "1.0.0" and normalize_version("1.0.0.0+abc") == "1.0.0"
    assert normalize_version("2.1.0-Beta.1") == "2.1.0-beta.1"


def test_nuget_proxy_rewrites_urls(app, monkeypatch):
    from app.blueprints import nuget

    service = json.dumps({"version": "3.0.0", "resources": [
        {"@id": "https://up.example/flat/", "@type": "PackageBaseAddress/3.0.0"},
        {"@id": "https://up.example/reg/", "@type": "RegistrationsBaseUrl/3.6.0"},
        {"@id": "https://up.example/search", "@type": "SearchQueryService/3.5.0"}]}).encode()
    reg = json.dumps({"items": [{"@id": "https://up.example/reg/x/index.json#page", "items": [
        {"packageContent": "https://up.example/flat/x/1.0.0/x.1.0.0.nupkg"}]}]}).encode()
    nupkg = make_nupkg("X", "1.0.0")
    up = patch_upstream(monkeypatch, {
        "https://up.example/v3/index.json": service,
        "https://up.example/flat/x/index.json": b'{"versions": ["1.0.0"]}',
        "https://up.example/flat/x/1.0.0/x.1.0.0.nupkg": nupkg,
        "https://up.example/reg/x/index.json": reg}, nuget)
    add_repo(app, name="nuget-org", format="nuget", kind="proxy", upstream_url="https://up.example/v3/index.json")
    c = app.test_client()
    assert c.get("/nuget/nuget-org/v3-flatcontainer/x/index.json", headers=ALICE).json == {"versions": ["1.0.0"]}
    body = c.get("/nuget/nuget-org/registration/x/index.json", headers=ALICE).data.decode()
    assert "up.example" not in body and "http://localhost/nuget/nuget-org/v3-flatcontainer/x/1.0.0/x.1.0.0.nupkg" in body
    for _ in range(2):
        assert c.get("/nuget/nuget-org/v3-flatcontainer/x/1.0.0/x.1.0.0.nupkg", headers=ALICE).data == nupkg
    assert up.calls.count("https://up.example/flat/x/1.0.0/x.1.0.0.nupkg") == 1
    assert "PackagePublish/2.0.0" not in str(c.get("/nuget/nuget-org/index.json", headers=ALICE).json)


# --- Cargo --------------------------------------------------------------------------------------------------

def publish_body(name, version, crate, deps=None, features=None):
    meta = json.dumps({"name": name, "vers": version, "deps": deps or [], "features": features or {},
                       "description": "demo crate", "license": "MIT", "links": None}).encode()
    return struct.pack("<I", len(meta)) + meta + struct.pack("<I", len(crate)) + crate


def test_cargo_publish_sparse_index_download_yank(app):
    add_repo(app, name="crates", format="cargo")
    c = app.test_client()
    tok = token(app)
    auth = {"Authorization": tok}  # cargo sends the bare token
    crate = tgz_bytes({"mycrate-0.1.0/Cargo.toml": b"[package]\nname='mycrate'\n"})
    deps = [{"name": "serde", "version_req": "^1.0", "features": ["derive"], "optional": False,
             "default_features": True, "target": None, "kind": "normal",
             "registry": "https://github.com/rust-lang/crates.io-index"},
            {"name": "rand_core", "explicit_name_in_toml": "rc", "version_req": "^0.6", "features": [],
             "optional": True, "default_features": True, "target": None, "kind": "normal"}]
    r = c.put("/cargo/crates/api/v1/crates/new", data=publish_body("MyCrate", "0.1.0", crate, deps,
                                                                    {"default": ["std"], "std": [], "rng": ["dep:rc"]}),
              headers=auth)
    assert r.status_code == 200 and "errors" not in r.json, r.json
    dup = c.put("/cargo/crates/api/v1/crates/new", data=publish_body("MyCrate", "0.1.0", crate), headers=auth)
    assert "already uploaded" in dup.json["errors"][0]["detail"]

    cfg = c.get("/cargo/crates/index/config.json", headers=ALICE).json
    assert cfg["dl"] == "http://localhost/cargo/crates/api/v1/crates" and cfg["auth-required"] is True
    assert c.get("/cargo/crates/index/config.json").status_code == 401
    line = json.loads(c.get("/cargo/crates/index/my/cr/mycrate", headers=ALICE).data)
    assert line["name"] == "MyCrate" and line["vers"] == "0.1.0" and line["cksum"] == hashlib.sha256(crate).hexdigest()
    assert line["deps"][0] == {"name": "serde", "req": "^1.0", "features": ["derive"], "optional": False,
                               "default_features": True, "target": None, "kind": "normal",
                               "registry": "https://github.com/rust-lang/crates.io-index"}
    assert line["deps"][1]["name"] == "rc" and line["deps"][1]["package"] == "rand_core"
    assert line["features2"] == {"rng": ["dep:rc"]} and line["v"] == 2 and "rng" not in line["features"]
    assert c.get("/cargo/crates/api/v1/crates/MyCrate/0.1.0/download", headers=ALICE).data == crate
    assert c.delete("/cargo/crates/api/v1/crates/MyCrate/0.1.0/yank", headers=auth).json == {"ok": True}
    assert json.loads(c.get("/cargo/crates/index/my/cr/mycrate", headers=ALICE).data)["yanked"] is True
    assert c.put("/cargo/crates/api/v1/crates/MyCrate/0.1.0/unyank", headers=auth).json == {"ok": True}
    found = c.get("/cargo/crates/api/v1/crates?q=myc", headers=ALICE).json
    assert found["meta"]["total"] == 1 and found["crates"][0]["max_version"] == "0.1.0"
    from app.blueprints.cargo import index_path
    assert [index_path(n) for n in ("a", "ab", "abc", "serde")] == ["1/a", "2/ab", "3/a/abc", "se/rd/serde"]


def test_cargo_proxy_verifies_checksum(app, monkeypatch):
    crate = b"crate-bytes"
    entry = {"name": "serde", "vers": "1.0.0", "deps": [], "cksum": hashlib.sha256(crate).hexdigest(), "features": {}}
    bad = {**entry, "vers": "1.0.1", "cksum": "0" * 64}
    up = patch_upstream(monkeypatch, {
        "https://index.example/config.json": b'{"dl": "https://static.example/crates"}',
        "https://index.example/se/rd/serde": (json.dumps(entry) + "\n" + json.dumps(bad) + "\n").encode(),
        "https://static.example/crates/serde/1.0.0/download": crate,
        "https://static.example/crates/serde/1.0.1/download": b"tampered"})
    add_repo(app, name="crates-io", format="cargo", kind="proxy", upstream_url="https://index.example")
    c = app.test_client()
    assert c.get("/cargo/crates-io/index/se/rd/serde", headers=ALICE).status_code == 200
    for _ in range(2):
        assert c.get("/cargo/crates-io/api/v1/crates/serde/1.0.0/download", headers=ALICE).data == crate
    assert up.calls.count("https://static.example/crates/serde/1.0.0/download") == 1
    assert c.get("/cargo/crates-io/api/v1/crates/serde/1.0.1/download", headers=ALICE).status_code == 502
    assert c.get("/cargo/crates-io/api/v1/crates/serde/9.0.0/download", headers=ALICE).status_code == 404


# --- Helm ------------------------------------------------------------------------------------------------------

def make_chart(name="mychart", version="0.1.0"):
    chart = (f"apiVersion: v2\nname: {name}\nversion: {version}\nappVersion: '1.2'\ndescription: Demo chart\n"
             "dependencies:\n  - name: redis\n    version: 18.0.0\n    repository: oci://registry-1.docker.io/bitnamicharts\n").encode()
    return tgz_bytes({f"{name}/Chart.yaml": chart, f"{name}/values.yaml": b"replicas: 1\n"})


def test_helm_upload_index_download_delete(app):
    add_repo(app, name="charts", format="helm", allow_redeploy=False)
    c = app.test_client()
    chart = make_chart()
    r = c.post("/helm/charts/api/charts", data=chart, headers=basic())
    assert r.status_code == 201 and r.json["saved"] is True
    assert c.post("/helm/charts/api/charts", data=chart, headers=basic()).status_code == 409
    # curl --data-binary sends application/x-www-form-urlencoded - the body must not be parsed as a form
    assert c.put("/helm/charts/upload", data=make_chart(version="0.2.0"), headers=basic(),
                 content_type="application/x-www-form-urlencoded").status_code == 201
    assert c.post("/helm/charts/api/charts", data=b"not a chart", headers=basic()).status_code == 400

    index = yaml.safe_load(c.get("/helm/charts/index.yaml", headers=ALICE).data)
    entries = index["entries"]["mychart"]
    assert {e["version"] for e in entries} == {"0.1.0", "0.2.0"}
    e = next(e for e in entries if e["version"] == "0.1.0")
    assert e["urls"] == ["http://localhost/helm/charts/charts/mychart-0.1.0.tgz"]
    assert e["digest"] == hashlib.sha256(chart).hexdigest() and e["appVersion"] == "1.2"
    assert c.get("/helm/charts/charts/mychart-0.1.0.tgz", headers=ALICE).data == chart
    assert c.delete("/helm/charts/api/charts/mychart/0.1.0", headers=basic()).json == {"deleted": True}
    index = yaml.safe_load(c.get("/helm/charts/index.yaml", headers=ALICE).data)
    assert [e["version"] for e in index["entries"]["mychart"]] == ["0.2.0"]
    with app.app_context():
        v = Version.query.one()
        assert v.meta["dependencies"] == [{"name": "redis", "version": "18.0.0"}]


def test_helm_proxy_rewrites_index(app, monkeypatch):
    chart = make_chart("nginx", "1.0.0")
    index = yaml.safe_dump({"apiVersion": "v1", "entries": {"nginx": [
        {"name": "nginx", "version": "1.0.0", "urls": ["charts/nginx-1.0.0.tgz"]},
        {"name": "nginx", "version": "0.9.0", "urls": ["https://cdn.example/nginx-0.9.0.tgz"]}]}}).encode()
    up = patch_upstream(monkeypatch, {"https://charts.example/index.yaml": index,
                                      "https://charts.example/charts/nginx-1.0.0.tgz": chart})
    add_repo(app, name="upstream-charts", format="helm", kind="proxy", upstream_url="https://charts.example")
    c = app.test_client()
    doc = yaml.safe_load(c.get("/helm/upstream-charts/index.yaml", headers=ALICE).data)
    assert {e["urls"][0] for e in doc["entries"]["nginx"]} == {
        "http://localhost/helm/upstream-charts/charts/nginx-1.0.0.tgz",
        "http://localhost/helm/upstream-charts/charts/nginx-0.9.0.tgz"}
    for _ in range(2):
        assert c.get("/helm/upstream-charts/charts/nginx-1.0.0.tgz", headers=ALICE).data == chart
    assert up.calls.count("https://charts.example/charts/nginx-1.0.0.tgz") == 1
    assert up.calls.count("https://charts.example/index.yaml") == 1


# --- generic ---------------------------------------------------------------------------------------------------

def test_generic_upload_download_listing_delete(app, monkeypatch):
    add_repo(app, name="files", format="generic", allow_redeploy=False)
    c = app.test_client()
    data = b"\x7fELF binary"
    url = "/generic/files/tools/mytool/1.4.0/mytool-linux-amd64"
    r = c.put(url, data=data, headers=basic())
    assert r.status_code == 201 and r.json["package"] == "tools/mytool" and r.json["version"] == "1.4.0"
    assert c.put(url, data=data, headers=basic()).status_code == 409
    assert c.put("/generic/files/onlyfile.bin", data=data, headers=basic()).status_code == 400
    assert c.put("/generic/files/a/1/b.bin", data=data,
                 headers={**basic(), "X-Checksum-Sha256": "0" * 64}).status_code == 400
    assert c.put("/generic/files/a/../../etc/passwd", data=data, headers=basic()).status_code in (400, 404)
    assert c.get(url, headers=ALICE).data == data
    assert c.get(url + ".sha256", headers=ALICE).data.decode().strip() == hashlib.sha256(data).hexdigest()
    assert c.get(url + ".md5", headers=ALICE).data.decode().strip() == hashlib.md5(data).hexdigest()
    listing = c.get("/generic/files/tools/", headers=ALICE).json
    assert [f["path"] for f in listing["files"]] == ["tools/mytool/1.4.0/mytool-linux-amd64"]
    assert c.delete(url, headers=ALICE).status_code == 403
    assert c.delete(url, headers=basic()).status_code == 204
    assert c.get(url, headers=ALICE).status_code == 404
    with app.app_context():
        assert Version.query.count() == 0

    # proxy for an arbitrary HTTP file server
    up = patch_upstream(monkeypatch, {"https://dl.example/releases/v1/tool.tar.gz": b"tarball"})
    add_repo(app, name="downloads", format="generic", kind="proxy", upstream_url="https://dl.example/releases")
    for _ in range(2):
        assert c.get("/generic/downloads/v1/tool.tar.gz", headers=ALICE).data == b"tarball"
    assert up.calls == ["https://dl.example/releases/v1/tool.tar.gz"]
    assert c.put("/generic/downloads/a/b/c", data=b"x", headers=basic()).status_code == 405


def test_new_formats_in_ui_and_api(app):
    for fmt in ("maven", "go", "nuget", "cargo", "helm", "generic"):
        add_repo(app, name=f"r-{fmt}", format=fmt)
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    for fmt in ("maven", "go", "nuget", "cargo", "helm", "generic"):
        page = c.get(f"/repos/r-{fmt}")
        assert page.status_code == 200, fmt
    assert c.get("/repos/new").status_code == 200
    r = c.post("/api/v1/repositories", json={"name": "gen-proxy", "format": "generic", "kind": "proxy"})
    assert r.status_code == 400 and "upstream_url is required" in r.json["error"]
    r = c.post("/api/v1/repositories", json={"name": "mvn-proxy", "format": "maven", "kind": "proxy"})
    assert r.status_code == 201 and r.json["upstream_url"] == "https://repo1.maven.org/maven2"
    assert c.get("/docs/guides").status_code == 200
