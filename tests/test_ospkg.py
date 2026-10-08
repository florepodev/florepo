"""Debian / RPM / Alpine repositories: hosted uploads + signed indexes, proxy caching, scanning, retention."""
import base64
import gzip
import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
from datetime import timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app import ospkg, scanner
from app.extensions import db
from app.models import ArtifactFile, DownloadEvent, RepoFile, Repository, Version, utcnow
from tests.test_registries import basic


# --- test package builders ---------------------------------------------------------------------

def _tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_deb(name="hello-florepo", version="1.0-1", arch="amd64", source=None):
    control = (f"Package: {name}\nVersion: {version}\nArchitecture: {arch}\nMaintainer: QA <qa@example.com>\n"
               "Installed-Size: 4\n" + (f"Source: {source}\n" if source else "") +
               "Description: test package\n long description line\n").encode()
    members = [("debian-binary", b"2.0\n"),
               ("control.tar.gz", gzip.compress(_tar({"./control": control}))),
               ("data.tar.gz", gzip.compress(_tar({f"./usr/share/doc/{name}/README": b"hi\n"})))]
    out = b"!<arch>\n"
    for fname, data in members:
        out += f"{fname:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode() + data
        if len(data) % 2:
            out += b"\n"
    return out


def make_apk(name="hello-florepo", version="1.0-r0", arch="x86_64"):
    pkginfo = (f"pkgname = {name}\npkgver = {version}\narch = {arch}\nsize = 42\npkgdesc = test package\n"
               f"url = https://example.com\nlicense = MIT\norigin = {name}\ndepend = musl\n").encode()
    # like abuild: control segment = tar member(s) without end-of-archive blocks
    control = gzip.compress(ospkg._tar_member(".PKGINFO", pkginfo, end_of_archive=False))
    data = gzip.compress(_tar({"usr/share/hello/README": b"hi\n"}))
    return control + data, control


def make_rpm(tmp, name="hello-florepo", version="1.0", release="1"):
    spec = os.path.join(tmp, "hello.spec")
    with open(spec, "w") as f:
        f.write(f"Name: {name}\nVersion: {version}\nRelease: {release}\nSummary: test package\nLicense: MIT\n"
                f"BuildArch: noarch\n%description\ntest\n%install\nmkdir -p %{{buildroot}}/usr/share/{name}\n"
                f"echo hi > %{{buildroot}}/usr/share/{name}/README\n%files\n/usr/share/{name}/README\n")
    subprocess.run(["rpmbuild", "-bb", "--define", f"_topdir {tmp}", spec], check=True, capture_output=True)
    path = os.path.join(tmp, "RPMS", "noarch", f"{name}-{version}-{release}.noarch.rpm")
    return open(path, "rb").read(), os.path.basename(path)


def add_repo(app, **kw):
    with app.app_context():
        db.session.add(Repository(**kw))
        db.session.commit()


# --- hosted ------------------------------------------------------------------------------------------

def test_deb_hosted_upload_signed_index_and_download(app):
    add_repo(app, name="deb-local", format="deb", kind="hosted")
    c = app.test_client()
    deb = make_deb(source="hello-src")
    r = c.put("/deb/deb-local/upload/hello-florepo_1.0-1_amd64.deb?distribution=stable", data=deb, headers=basic())
    assert r.status_code == 201, r.data
    assert r.json["path"] == "pool/main/h/hello-src/hello-florepo_1.0-1_amd64.deb"
    assert c.put("/deb/deb-local/upload/hello-florepo_1.0-1_amd64.deb", data=deb, headers=basic()).status_code == 409
    assert c.put("/deb/deb-local/upload/x.deb", data=deb, headers=basic("alice", "alice-pass")).status_code == 403
    assert c.put("/deb/deb-local/upload/x.deb", data=b"nope", headers=basic()).status_code == 400

    packages = c.get("/deb/deb-local/dists/stable/main/binary-amd64/Packages", headers=basic()).data.decode()
    assert "Package: hello-florepo" in packages and "Filename: pool/main/h/hello-src/hello-florepo_1.0-1_amd64.deb" in packages
    assert f"SHA256: {hashlib.sha256(deb).hexdigest()}" in packages and "Source: hello-src" in packages
    gz = c.get("/deb/deb-local/dists/stable/main/binary-amd64/Packages.gz", headers=basic()).data
    assert gzip.decompress(gz).decode() == packages
    release = c.get("/deb/deb-local/dists/stable/Release", headers=basic()).data.decode()
    assert "Architectures: amd64" in release and hashlib.sha256(packages.encode()).hexdigest() in release

    # InRelease is a valid clearsigned document for the published key
    inrelease = c.get("/deb/deb-local/dists/stable/InRelease", headers=basic()).data
    key = c.get("/deb/deb-local/key.gpg", headers=basic()).data
    with tempfile.TemporaryDirectory() as home:
        subprocess.run(["gpg", "--homedir", home, "--batch", "--import"], input=key, check=True, capture_output=True)
        ok = subprocess.run(["gpg", "--homedir", home, "--batch", "--verify"], input=inrelease, capture_output=True)
        assert ok.returncode == 0, ok.stderr
    assert c.get("/deb/deb-local/key.asc", headers=basic()).data.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK")

    got = c.get("/deb/deb-local/pool/main/h/hello-src/hello-florepo_1.0-1_amd64.deb", headers=basic("alice", "alice-pass"))
    assert got.status_code == 200 and got.data == deb
    with app.app_context():
        assert DownloadEvent.query.one().package_name == "hello-florepo"
        v = Version.query.one()
        assert v.version == "1.0-1" and v.scan_status == "pending"

    # deleting the version regenerates the index
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    with app.app_context():
        vid = Version.query.one().id
    c.post(f"/versions/{vid}/delete")
    assert b"hello-florepo" not in c.get("/deb/deb-local/dists/stable/main/binary-amd64/Packages", headers=basic()).data


def test_apk_hosted_upload_and_signed_index(app):
    add_repo(app, name="apk-local", format="apk", kind="hosted")
    c = app.test_client()
    apk, control = make_apk()
    r = c.put("/apk/apk-local/upload/hello-florepo-1.0-r0.apk?branch=v3.20", data=apk, headers=basic())
    assert r.status_code == 201, r.data
    assert r.json["path"] == "v3.20/main/x86_64/hello-florepo-1.0-r0.apk"
    index = c.get("/apk/apk-local/v3.20/main/x86_64/APKINDEX.tar.gz", headers=basic()).data
    (sig_raw, sig_tar), (ctl_raw, ctl_tar) = [(raw, out) for raw, out in ospkg._gzip_members(index)]
    sig_member = tarfile.open(fileobj=io.BytesIO(sig_tar + b"\0" * 1024)).getmembers()[0]
    keyname = sig_member.name.removeprefix(".SIGN.RSA256.")
    signature = tarfile.open(fileobj=io.BytesIO(sig_tar + b"\0" * 1024)).extractfile(sig_member).read()
    pub = c.get(f"/apk/apk-local/keys/{keyname}", headers=basic()).data
    serialization.load_pem_public_key(pub).verify(signature, ctl_raw, padding.PKCS1v15(), hashes.SHA256())
    entries = tarfile.open(fileobj=io.BytesIO(ctl_tar)).extractfile("APKINDEX").read().decode()
    checksum = "Q1" + base64.b64encode(hashlib.sha1(control).digest()).decode()
    assert f"C:{checksum}" in entries and "P:hello-florepo" in entries and "V:1.0-r0" in entries
    assert f"S:{len(apk)}" in entries and "D:musl" in entries
    assert c.get("/apk/apk-local/key.rsa.pub", headers=basic()).data == pub


def test_rpm_hosted_upload_repodata(app, tmp_path):
    add_repo(app, name="rpm-local", format="rpm", kind="hosted")
    c = app.test_client()
    rpm, filename = make_rpm(str(tmp_path))
    r = c.put(f"/rpm/rpm-local/upload/{filename}", data=rpm, headers=basic())
    assert r.status_code == 201, r.data
    assert r.json["name"] == "hello-florepo" and r.json["version"] == "1.0-1" and r.json["arch"] == "noarch"
    repomd = c.get("/rpm/rpm-local/repodata/repomd.xml", headers=basic())
    assert repomd.status_code == 200 and b"primary" in repomd.data
    primary = [line for line in repomd.data.decode().split('"') if line.endswith("primary.xml.gz")][0]
    xml = gzip.decompress(c.get(f"/rpm/rpm-local/{primary}", headers=basic()).data).decode()
    assert "<name>hello-florepo</name>" in xml and 'href="packages/hello-florepo-1.0-1.noarch.rpm"' in xml
    asc = c.get("/rpm/rpm-local/repodata/repomd.xml.asc", headers=basic()).data
    key = c.get("/rpm/rpm-local/key.asc", headers=basic()).data
    with tempfile.TemporaryDirectory() as home:
        subprocess.run(["gpg", "--homedir", home, "--batch", "--import"], input=key, check=True, capture_output=True)
        with open(os.path.join(home, "repomd.xml"), "wb") as f:
            f.write(repomd.data)
        with open(os.path.join(home, "repomd.xml.asc"), "wb") as f:
            f.write(asc)
        ok = subprocess.run(["gpg", "--homedir", home, "--batch", "--verify", os.path.join(home, "repomd.xml.asc"),
                             os.path.join(home, "repomd.xml")], capture_output=True)
        assert ok.returncode == 0, ok.stderr
    assert c.get("/rpm/rpm-local/packages/hello-florepo-1.0-1.noarch.rpm", headers=basic()).data == rpm


# --- proxy ------------------------------------------------------------------------------------------

class FakeUpstream:
    def __init__(self, files):
        self.files, self.calls = files, []

    def __call__(self, url, repo=None, **kw):
        self.calls.append(url)
        data = self.files.get(url)
        return _Resp(200 if data is not None else 404, data or b"")


class _Resp:
    def __init__(self, status, data):
        self.status_code, self.raw = status, io.BytesIO(data)
        self.raw.decode_content = True

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_deb_proxy_caching_scan_sbom_and_policy(app, monkeypatch):
    from app.blueprints import ospkg as bp

    deb = make_deb("libfoo1", "1.2-3", source="foo")
    up = FakeUpstream({"http://up.example/debian/dists/bookworm/InRelease": b"signed-release",
                       "http://up.example/debian/pool/main/f/foo/libfoo1_1.2-3_amd64.deb": deb})
    monkeypatch.setattr(bp, "upstream_get", up)
    add_repo(app, name="debian", format="deb", kind="proxy", upstream_url="http://up.example/debian")
    c = app.test_client()
    for _ in range(2):
        r = c.get("/deb/debian/dists/bookworm/InRelease", headers=basic())
        assert r.status_code == 200 and r.data == b"signed-release"
    assert up.calls.count("http://up.example/debian/dists/bookworm/InRelease") == 1  # metadata TTL cache
    assert c.get("/deb/debian/dists/bookworm/Missing", headers=basic()).status_code == 404

    path = "/deb/debian/pool/main/f/foo/libfoo1_1.2-3_amd64.deb"
    assert c.get(path, headers=basic("alice", "alice-pass")).data == deb
    assert c.get(path, headers=basic("alice", "alice-pass")).data == deb
    assert up.calls.count("http://up.example/debian/pool/main/f/foo/libfoo1_1.2-3_amd64.deb") == 1
    with app.app_context():
        events = DownloadEvent.query.order_by(DownloadEvent.id).all()
        assert [e.cache_hit for e in events] == [False, True]
        v = Version.query.one()
        assert v.package.name == "libfoo1" and v.files[0].meta["info"]["source"] == "foo"
        assert scanner.infer_distro(v) == ("debian", "12")  # from the requested suite (bookworm)
        sbom_path = scanner.build_os_sbom(v, ("debian", "12"), tempfile.mkdtemp())
        sbom = open(sbom_path).read()
        assert "pkg:deb/debian/libfoo1@1.2-3?arch=amd64&distro=debian-12" in sbom and '"operating-system"' in sbom
        v.scan_status, v.count_critical = "done", 1
        v.package.repository.block_severity = "CRITICAL"
        db.session.commit()
    assert c.get(path, headers=basic()).status_code == 403


def test_distro_parsing_and_inference(app):
    assert scanner.parse_distro("debian:12") == ("debian", "12")
    assert scanner.parse_distro("AlmaLinux 9") == ("alma", "9")
    assert scanner.parse_distro("alpine:v3.20") == ("alpine", "3.20")
    assert scanner.parse_distro("windows:11") is None
    with app.app_context():
        repo = Repository(name="x", format="apk", kind="proxy")
        db.session.add(repo)
        db.session.flush()
        from app.blueprints.common import get_or_create_package, get_or_create_version
        v, _ = get_or_create_version(get_or_create_package(repo, "busybox"), "1.36.1-r29")
        v.files.append(ArtifactFile(filename="busybox-1.36.1-r29.apk", path="v3.20/main/x86_64/busybox-1.36.1-r29.apk",
                                    sha256="0" * 64, size=1))
        assert scanner.infer_distro(v) == ("alpine", "3.20")
        repo.format, repo.upstream_url = "rpm", "https://dl.rockylinux.org/pub/rocky"
        v.version = "3.0.7-27.el9"
        assert scanner.infer_distro(v) == ("rocky", "9")
        repo.distro = "alma:9"
        assert scanner.infer_distro(v) == ("alma", "9")
        db.session.rollback()


def test_repository_settings_validation(app):
    from tests.test_api import bearer
    c = app.test_client()
    h = bearer(c)
    r = c.post("/api/v1/repositories", headers=h, json={"name": "deb-proxy", "format": "deb", "kind": "proxy",
                                                        "distro": "debian:12", "cache_retention_days": 30})
    assert r.status_code == 201 and r.json["upstream_url"] == "http://deb.debian.org/debian"
    assert r.json["distro"] == "debian:12" and r.json["cache_retention_days"] == 30
    assert c.patch("/api/v1/repositories/deb-proxy", headers=h, json={"distro": "beos:5"}).status_code == 400
    assert c.patch("/api/v1/repositories/deb-proxy", headers=h, json={"cache_retention_days": -1}).status_code == 400
    assert c.patch("/api/v1/repositories/deb-proxy", headers=h, json={"cache_retention_days": 0}).json[
        "cache_retention_days"] is None
    c.post("/login", data={"username": "admin", "password": "admin-pass"})
    for url in ["/repos/deb-proxy", "/repos/deb-proxy/edit", "/repos/new", "/docs"]:
        assert c.get(url).status_code == 200, url


# --- retention ---------------------------------------------------------------------------------------

def test_cache_retention_and_purge(app, monkeypatch):
    from app import cache
    from app.blueprints import ospkg as bp

    files = {f"http://up.example/alpine/v3.20/main/x86_64/pkg{i}-1.0-r0.apk": make_apk(f"pkg{i}")[0] for i in range(3)}
    monkeypatch.setattr(bp, "upstream_get", FakeUpstream(files))
    add_repo(app, name="alpine", format="apk", kind="proxy", upstream_url="http://up.example/alpine",
             cache_retention_days=7)
    c = app.test_client()
    for i in range(3):
        assert c.get(f"/apk/alpine/v3.20/main/x86_64/pkg{i}-1.0-r0.apk", headers=basic()).status_code == 200
    with app.app_context():
        old, recent, never = (Version.query.join(Version.package).filter_by(name=f"pkg{i}").one() for i in range(3))
        old.last_accessed_at = utcnow() - timedelta(days=10)
        recent.last_accessed_at = utcnow() - timedelta(days=2)
        never.created_at = utcnow() - timedelta(days=30)
        old_blob = old.files[0].sha256
        db.session.commit()
        result = cache.evict_expired()
        assert result == {"alpine": {"versions": 2, "bytes": result["alpine"]["bytes"]}}
        assert [v.package.name for v in Version.query] == ["pkg1"]
        removed, freed, _ = cache.collect_garbage(min_age_seconds=0)
        assert removed >= 2 and freed > 0
        from app import storage
        assert not storage.blob_exists(old_blob)
        assert cache.cache_usage(Repository.query.filter_by(name="alpine").one())[0] == 1

    from tests.test_api import bearer
    h = bearer(c)
    r = c.post("/api/v1/repositories/alpine/cache/purge", headers=h, json={})
    assert r.status_code == 200 and r.json["removed_versions"] == 1
    assert c.get("/api/v1/repositories/alpine/cache", headers=h).json["versions"] == 0
    assert c.post("/api/v1/repositories/py/cache/purge", headers=h, json={}).status_code == 400


def test_worker_records_last_access(app):
    from app.worker import aggregate_download_counts

    add_repo(app, name="deb-local", format="deb", kind="hosted")
    c = app.test_client()
    c.put("/deb/deb-local/upload/hello-florepo_1.0-1_amd64.deb", data=make_deb(), headers=basic())
    with app.app_context():
        aggregate_download_counts()
    c.get("/deb/deb-local/pool/main/h/hello-florepo/hello-florepo_1.0-1_amd64.deb", headers=basic())
    with app.app_context():
        aggregate_download_counts()
        v = Version.query.one()
        assert v.download_count == 1 and v.last_accessed_at is not None
        assert RepoFile.query.count() >= 4  # Packages, Packages.gz x arches, Release, InRelease, Release.gpg


def test_upload_without_filename_uses_canonical_name(app):
    """curl --upload-file x.deb 'https://host/deb/repo/upload/?distribution=stable' sends no file name."""
    add_repo(app, name="deb-local", format="deb", kind="hosted")
    add_repo(app, name="apk-local", format="apk", kind="hosted")
    c = app.test_client()
    r = c.put("/deb/deb-local/upload/?distribution=stable", data=make_deb("noname", "1:2.0-1"), headers=basic())
    assert r.status_code == 201 and r.json["path"] == "pool/main/n/noname/noname_2.0-1_amd64.deb", r.data
    r = c.put("/apk/apk-local/upload/?branch=v3.20", data=make_apk("noname", "2.0-r1", "noarch")[0], headers=basic())
    assert r.status_code == 201 and r.json["path"] == "v3.20/main/noarch/noname-2.0-r1.apk", r.data
    assert c.put("/apk/apk-local/upload/bad.txt", data=b"x", headers=basic()).status_code == 400
