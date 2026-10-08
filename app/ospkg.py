"""Debian (.deb), RPM (.rpm) and Alpine (.apk) packages: metadata parsing and repository indexes."""
import base64
import gzip
import hashlib
import io
import lzma
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zlib
from datetime import datetime, timezone
from email.utils import format_datetime
from urllib.parse import unquote

import zstandard

from . import signing, storage

SUFFIXES = {"deb": (".deb", ".udeb", ".ddeb"), "rpm": (".rpm",), "apk": (".apk",)}
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~%:-]*$")
DEFAULT_ARCHES = {"deb": ["amd64", "arm64"], "apk": ["x86_64", "aarch64"]}


class PackageError(ValueError):
    pass


def is_package(fmt, path):
    return path.lower().endswith(SUFFIXES[fmt])


def is_immutable_metadata(fmt, path):
    """Content-addressed metadata never changes and can be cached without TTL."""
    if "/by-hash/" in path:
        return True
    return fmt == "rpm" and "/repodata/" in f"/{path}" and not path.endswith(("repomd.xml", "repomd.xml.asc",
                                                                              "repomd.xml.key"))


# --- identity from file names (used before the file is parsed) -------------------------------

def parse_filename(fmt, filename, path=""):
    """Return (name, version, arch) or None."""
    if fmt == "deb":
        m = re.match(r"^([^_]+)_([^_]+)_([^_.]+)\.(?:u|d)?deb$", filename)
        return (m.group(1), unquote(m.group(2)), m.group(3)) if m else None
    if fmt == "rpm":
        m = re.match(r"^(.+)-([^-]+)-([^-]+)\.([^.]+)\.rpm$", filename)
        return (m.group(1), f"{m.group(2)}-{m.group(3)}", m.group(4)) if m else None
    m = re.match(r"^(.+)-([^-]+-r\d+)\.apk$", filename)
    if not m:
        return None
    parts = path.strip("/").split("/")
    return m.group(1), m.group(2), parts[-2] if len(parts) >= 2 else "noarch"


# --- parsing -----------------------------------------------------------------------------------

def _rfc822(text):
    """Parse a Debian control paragraph, preserving field order and continuation lines."""
    fields, key = {}, None
    for line in text.splitlines():
        if not line.strip() and fields:
            break
        if line[:1] in (" ", "\t") and key:
            fields[key] += "\n" + line
        elif ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            fields[key] = value.strip()
    return fields


def read_deb(path):
    """Return the control fields of a .deb (ar archive with control.tar.{gz,xz,zst,})."""
    with open(path, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            raise PackageError("not a Debian package (ar archive expected)")
        while True:
            header = f.read(60)
            if len(header) < 60:
                break
            name = header[:16].decode(errors="replace").strip().rstrip("/")
            size = int(header[48:58].decode().strip())
            data = f.read(size)
            if size % 2:
                f.read(1)
            if not name.startswith("control.tar"):
                continue
            if name.endswith(".gz"):
                data = gzip.decompress(data)
            elif name.endswith(".xz"):
                data = lzma.decompress(data)
            elif name.endswith(".zst"):
                data = zstandard.ZstdDecompressor().decompressobj().decompress(data)
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for member in tf.getmembers():
                    if member.name.lstrip("./") == "control":
                        return _rfc822(tf.extractfile(member).read().decode("utf-8", "replace"))
    raise PackageError("control file not found in .deb")


RPM_TAGS = ["NAME", "EPOCHNUM", "VERSION", "RELEASE", "ARCH", "SUMMARY", "LICENSE", "SOURCERPM", "URL", "SIZE"]


def read_rpm(path):
    qf = "\x1f".join(f"%{{{t}}}" for t in RPM_TAGS)  # ASCII unit separator, cannot occur in tag values
    proc = subprocess.run(["rpm", "-qp", "--nosignature", "--nodigest", "--qf", qf, path],
                          capture_output=True, timeout=60)
    if proc.returncode != 0:
        raise PackageError(f"not a valid RPM: {proc.stderr.decode(errors='replace')[-200:]}")
    values = proc.stdout.decode("utf-8", "replace").split("\x1f")
    return dict(zip(RPM_TAGS, values))


def _gzip_members(data):
    members = []
    while data:
        d = zlib.decompressobj(31)
        out = d.decompress(data)
        consumed = len(data) - len(d.unused_data)
        members.append((data[:consumed], out))
        data = d.unused_data
    return members


def read_apk(path):
    """Return (.PKGINFO fields, Q1 checksum of the control segment)."""
    data = open(path, "rb").read()
    try:
        members = _gzip_members(data)
    except zlib.error as exc:
        raise PackageError(f"not a valid apk: {exc}")
    for raw, out in members:
        try:
            with tarfile.open(fileobj=io.BytesIO(out)) as tf:
                info = tf.extractfile(".PKGINFO") if ".PKGINFO" in tf.getnames() else None
                if info is None:
                    continue
                fields = {}
                for line in info.read().decode("utf-8", "replace").splitlines():
                    if line.startswith("#") or " = " not in line:
                        continue
                    k, _, v = line.partition(" = ")
                    fields.setdefault(k.strip(), []).append(v.strip())
                return fields, "Q1" + base64.b64encode(hashlib.sha1(raw).digest()).decode()
        except tarfile.TarError:
            continue
    raise PackageError(".PKGINFO not found in apk")


def package_info(fmt, path):
    """Normalized metadata: name, version, arch, source, source_version, summary, license, url, fields."""
    if fmt == "deb":
        c = read_deb(path)
        if not c.get("Package") or not c.get("Version"):
            raise PackageError("control file without Package/Version")
        src, _, src_ver = (c.get("Source") or c["Package"]).partition(" ")
        return {"name": c["Package"], "version": c["Version"], "arch": c.get("Architecture", "all"),
                "source": src, "source_version": src_ver.strip("()") or c["Version"],
                "summary": (c.get("Description") or "").split("\n")[0], "license": None,
                "url": c.get("Homepage"), "fields": c}
    if fmt == "rpm":
        r = read_rpm(path)
        epoch = r["EPOCHNUM"] if r["EPOCHNUM"] not in ("", "0", "(none)") else ""
        version = f"{epoch + ':' if epoch else ''}{r['VERSION']}-{r['RELEASE']}"
        srpm = r.get("SOURCERPM") or ""
        m = re.match(r"^(.+)-[^-]+-[^-]+\.src\.rpm$", srpm)
        return {"name": r["NAME"], "version": version, "arch": r["ARCH"], "source": m.group(1) if m else r["NAME"],
                "source_version": version, "epoch": epoch, "summary": r["SUMMARY"], "license": r["LICENSE"],
                "url": r["URL"] if r["URL"] != "(none)" else None, "fields": r}
    fields, checksum = read_apk(path)
    first = {k: v[0] for k, v in fields.items()}
    if not first.get("pkgname") or not first.get("pkgver"):
        raise PackageError(".PKGINFO without pkgname/pkgver")
    return {"name": first["pkgname"], "version": first["pkgver"], "arch": first.get("arch", "noarch"),
            "source": first.get("origin", first["pkgname"]), "source_version": first["pkgver"],
            "summary": first.get("pkgdesc"), "license": first.get("license"), "url": first.get("url"),
            "fields": fields, "checksum": checksum}


def canonical_filename(fmt, info):
    """Conventional file name of a package (used when an upload has no file name)."""
    version = info["version"]
    if fmt == "deb":
        return f"{info['name']}_{version.split(':', 1)[-1]}_{info['arch']}.deb"
    if fmt == "rpm":
        return f"{info['name']}-{version.split(':', 1)[-1]}.{info['arch']}.rpm"
    return f"{info['name']}-{version}.apk"


def file_hashes(blob_path):
    md5, sha1 = hashlib.md5(), hashlib.sha1()
    with open(blob_path, "rb") as f:
        for chunk in iter(lambda: f.read(storage.CHUNK), b""):
            md5.update(chunk)
            sha1.update(chunk)
    return md5.hexdigest(), sha1.hexdigest()


def hosted_path(fmt, info, filename, args):
    """Repository path of an uploaded package (args: query parameters of the upload)."""
    if fmt == "deb":
        comp = args.get("component") or "main"
        src = info["source"]
        prefix = src[:4] if src.startswith("lib") else src[:1]
        return f"pool/{comp}/{prefix}/{src}/{filename}"
    if fmt == "rpm":
        return f"packages/{filename}"
    branch = args.get("branch") or "latest"
    reponame = args.get("repository") or "main"
    return f"{branch}/{reponame}/{info['arch']}/{filename}"


# --- index generation (hosted repositories) ---------------------------------------------------

def _deb_entry(f):
    c = dict((f.meta or {}).get("info", {}).get("fields") or {})
    for k in ("Filename", "Size", "MD5sum", "SHA1", "SHA256"):
        c.pop(k, None)
    lines = [f"Package: {c.pop('Package')}"] + [f"{k}: {v}" for k, v in c.items()]
    lines += [f"Filename: {f.path}", f"Size: {f.size}", f"MD5sum: {f.meta['md5']}", f"SHA1: {f.meta['sha1']}",
              f"SHA256: {f.sha256}"]
    return "\n".join(lines) + "\n"


def build_deb(repo, files):
    out = {}
    dists = {}
    for f in files:
        m = f.meta or {}
        dists.setdefault(m.get("distribution", "stable"), {}).setdefault(m.get("component", "main"), []).append(f)
    for dist, comps in dists.items():
        arches = sorted({(f.meta.get("info") or {}).get("arch") for fs in comps.values() for f in fs} - {"all", None})
        arches = arches or DEFAULT_ARCHES["deb"]
        index_files = {}
        for comp, fs in comps.items():
            for arch in arches:
                entries = [_deb_entry(f) for f in sorted(fs, key=lambda x: x.path)
                           if (f.meta.get("info") or {}).get("arch") in (arch, "all")]
                text = "\n".join(entries).encode()
                base = f"{comp}/binary-{arch}/Packages"
                index_files[base] = text
                index_files[base + ".gz"] = gzip.compress(text, mtime=0)
        now = format_datetime(datetime.now(timezone.utc), usegmt=True)
        release = ["Origin: Florepo", f"Label: {repo.name}", f"Suite: {dist}", f"Codename: {dist}",
                   f"Date: {now}", f"Architectures: {' '.join(arches)}", f"Components: {' '.join(sorted(comps))}",
                   f"Description: Florepo repository {repo.name}"]
        for algo, title in (("md5", "MD5Sum"), ("sha1", "SHA1"), ("sha256", "SHA256")):
            release.append(f"{title}:")
            for rel, data in sorted(index_files.items()):
                release.append(f" {hashlib.new(algo, data).hexdigest()} {len(data):>16} {rel}")
        release_bytes = ("\n".join(release) + "\n").encode()
        for rel, data in index_files.items():
            out[f"dists/{dist}/{rel}"] = data
        out[f"dists/{dist}/Release"] = release_bytes
        out[f"dists/{dist}/InRelease"] = signing.gpg_clearsign(release_bytes)
        out[f"dists/{dist}/Release.gpg"] = signing.gpg_detach_sign(release_bytes)
    return out


def build_rpm(repo, files):
    if not files:
        return {}
    with tempfile.TemporaryDirectory(dir=storage.tmp_dir()) as work:
        for f in files:
            storage.export_blob(f.sha256, os.path.join(work, f.path))
        proc = subprocess.run(["createrepo_c", "--quiet", "--no-database", "--general-compress-type=gz", work],
                              capture_output=True, timeout=600)
        if proc.returncode != 0:
            raise RuntimeError(f"createrepo_c failed: {proc.stderr.decode(errors='replace')[-500:]}")
        out = {}
        for name in os.listdir(os.path.join(work, "repodata")):
            out[f"repodata/{name}"] = open(os.path.join(work, "repodata", name), "rb").read()
        out["repodata/repomd.xml.asc"] = signing.gpg_detach_sign(out["repodata/repomd.xml"])
        return out


def _apk_entry(f):
    i = (f.meta or {}).get("info") or {}
    fields = i.get("fields") or {}

    def one(key):
        return (fields.get(key) or [None])[0]

    lines = [f"C:{i['checksum']}", f"P:{i['name']}", f"V:{i['version']}", f"A:{i['arch']}", f"S:{f.size}",
             f"I:{one('size') or 0}", f"T:{one('pkgdesc') or ''}", f"U:{one('url') or ''}", f"L:{one('license') or ''}"]
    for key, tag in (("origin", "o"), ("maintainer", "m"), ("builddate", "t"), ("commit", "c")):
        if one(key):
            lines.append(f"{tag}:{one(key)}")
    for key, tag in (("depend", "D"), ("provides", "p"), ("install_if", "i")):
        if fields.get(key):
            lines.append(f"{tag}:{' '.join(fields[key])}")
    return "\n".join(lines) + "\n"


def _tar_member(name, data, end_of_archive=True):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), 0o644, 0
    buf = info.tobuf(format=tarfile.USTAR_FORMAT) + data + b"\0" * ((512 - len(data) % 512) % 512)
    return buf + (b"\0" * 1024 if end_of_archive else b"")


def build_apk(repo, files):
    out = {}
    groups = {}
    for f in files:
        branch, reponame = f.path.split("/")[:2]
        groups.setdefault((branch, reponame), []).append(f)
    for (branch, reponame), fs in groups.items():
        arches = sorted({(f.meta.get("info") or {}).get("arch") for f in fs} - {"noarch", None}) or DEFAULT_ARCHES["apk"]
        for arch in arches:
            entries = [_apk_entry(f) for f in sorted(fs, key=lambda x: x.path)
                       if (f.meta.get("info") or {}).get("arch") in (arch, "noarch")]
            index = "\n".join(entries).encode() + b"\n"
            desc = f"{repo.name} {branch}/{reponame}".encode()
            control = gzip.compress(_tar_member("DESCRIPTION", desc, False) + _tar_member("APKINDEX", index), mtime=0)
            sig_name, sig = signing.apk_sign(control)
            signature = gzip.compress(_tar_member(sig_name, sig, end_of_archive=False), mtime=0)
            out[f"{branch}/{reponame}/{arch}/APKINDEX.tar.gz"] = signature + control
    return out


BUILDERS = {"deb": build_deb, "rpm": build_rpm, "apk": build_apk}


def ensure_tools():
    missing = [t for t in ("gpg", "rpm", "createrepo_c") if shutil.which(t) is None]
    return missing
