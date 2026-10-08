"""Vulnerability scanning and SBOM generation.

* Trivy (if installed) scans docker images (as OCI layout) and extracted pypi/npm artifacts
  and its report is converted into a CycloneDX SBOM.
* OSV.dev is queried for the pypi/npm package itself (works without Trivy as well).
* Without Trivy, a minimal CycloneDX SBOM is built from the package metadata.
"""
import json
import re
import os
import shutil
import subprocess
import tarfile
import tempfile
import uuid
from urllib.parse import quote
import zipfile
from datetime import datetime, timezone

from flask import current_app

from . import netproxy, storage
from .docker_upstream import INDEX_TYPES, Upstream
from .extensions import db
from .models import OS_FORMATS, SEVERITIES, DockerManifest, Version, Vulnerability, utcnow

OSV_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "go": "Go", "nuget": "NuGet", "cargo": "crates.io"}
OSV_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}


class ScanError(Exception):
    pass


def trivy_available():
    return shutil.which(current_app.config["TRIVY_PATH"]) is not None


def trivy_info():
    """`trivy version` incl. vulnerability/Java DB metadata of our cache dir (None if trivy is missing)."""
    if not trivy_available():
        return None
    try:
        out = subprocess.run([current_app.config["TRIVY_PATH"], "version", "--format", "json",
                              "--cache-dir", current_app.config["TRIVY_CACHE_DIR"]],
                             capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout)
    except Exception:
        return None


def trivy_version():
    info = trivy_info()
    return info.get("Version", "unknown") if info else None


def _db_present(kind):
    sub = {"vuln": "db", "java": "java-db"}[kind]
    return os.path.exists(os.path.join(current_app.config["TRIVY_CACHE_DIR"], sub, "metadata.json"))


def update_trivy_db(java=True):
    """Download the vulnerability DB (and optionally the Java DB). Returns a log dict."""
    cfg = current_app.config
    base = [cfg["TRIVY_PATH"], "image", "--cache-dir", cfg["TRIVY_CACHE_DIR"], "--quiet"]
    started = utcnow()
    result = {"at": started.isoformat(timespec="seconds"), "ok": True, "error": None, "steps": []}
    steps = [("vuln", "--download-db-only")] + ([("java", "--download-java-db-only")] if java else [])
    for name, flag in steps:
        try:
            _run(base + [flag], 1800)
            result["steps"].append(name)
        except (ScanError, subprocess.TimeoutExpired) as exc:
            result["ok"] = False
            result["error"] = f"{name}: {exc}"[:2000]
            break
    result["duration_s"] = round((utcnow() - started).total_seconds(), 1)
    info = trivy_info() or {}
    result["db_updated_at"] = (info.get("VulnerabilityDB") or {}).get("UpdatedAt")
    return result


def purl(fmt, name, version):
    if fmt == "pypi":
        return f"pkg:pypi/{name}@{version}"
    if fmt == "npm":
        return f"pkg:npm/{name.replace('@', '%40')}@{version}"
    if fmt in ("deb", "rpm", "apk"):
        return f"pkg:{fmt}/{name}@{quote(version, safe='')}"
    if fmt == "maven":
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{group}/{artifact}@{quote(version, safe='')}"
    if fmt == "go":
        return f"pkg:golang/{name}@{version}"
    if fmt == "nuget":
        return f"pkg:nuget/{name}@{version}"
    if fmt == "cargo":
        return f"pkg:cargo/{name}@{version}"
    if fmt == "helm":
        return f"pkg:helm/{name}@{version}"
    if fmt == "generic":
        return f"pkg:generic/{quote(name, safe='/')}@{quote(version, safe='')}"
    return f"pkg:oci/{name.split('/')[-1]}@{version}"


# --- preparing scan targets ---------------------------------------------------

def _safe_extract_zip(path, dest):
    with zipfile.ZipFile(path) as zf:
        for member in zf.infolist():
            target = os.path.realpath(os.path.join(dest, member.filename))
            if not target.startswith(os.path.realpath(dest) + os.sep):
                continue
            zf.extract(member, dest)


def _safe_extract_tar(path, dest):
    with tarfile.open(path, "r:*") as tf:
        tf.extractall(dest, filter="data")


ZIP_SUFFIXES = (".whl", ".zip", ".nupkg", ".snupkg")
TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".crate")
JAR_SUFFIXES = (".jar", ".war", ".ear", ".aar", ".hpi", ".jpi")  # analysed as-is by Trivy's Java analyzer
# Trivy target type per format: lock files / go.mod are only analysed in "fs" mode
TRIVY_MODE = {"go": "fs", "cargo": "fs", "nuget": "fs"}


def prepare_package(version, work):
    """Lay out a version's files for Trivy: archives are extracted, Java archives and other files copied."""
    fmt = version.package.repository.format
    root = os.path.join(work, "rootfs")
    os.makedirs(root)
    for i, f in enumerate(version.files):
        low = f.filename.lower()
        safe = re.sub(r"[^A-Za-z0-9._+-]", "_", f.filename)
        if low.endswith(JAR_SUFFIXES):
            storage.export_blob(f.sha256, os.path.join(root, f"{i}", safe))
            continue
        if fmt == "maven":
            continue  # poms, checksums, signatures, sources ...
        kind = "zip" if low.endswith(ZIP_SUFFIXES) else "tar" if low.endswith(TAR_SUFFIXES) else None
        if kind is None:
            if fmt == "generic":  # e.g. Go/Rust binaries with embedded dependency information
                storage.export_blob(f.sha256, os.path.join(root, f"{i}", safe))
            continue
        dest = os.path.join(root, f"{i}", safe + ".d")
        os.makedirs(dest)
        with storage.local_file(f.sha256) as src:
            try:
                if kind == "zip":
                    _safe_extract_zip(src, dest)
                else:
                    _safe_extract_tar(src, dest)
            except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
                if fmt in ("generic", "helm"):
                    storage.export_blob(f.sha256, os.path.join(root, f"{i}", safe))
                    continue
                raise ScanError(f"cannot extract {f.filename}: {exc}")
    return root


def _ensure_manifest(repo, image, digest):
    m = DockerManifest.query.filter_by(repository_id=repo.id, image=image, digest=digest).first()
    if m is None and repo.is_proxy:
        m = Upstream(repo).fetch_manifest(image, digest)
        db.session.commit()
    if m is None:
        raise ScanError(f"manifest {digest} not found")
    return m


def _ensure_blob(repo, image, digest):
    if not storage.blob_exists(digest):
        if not repo.is_proxy:
            raise ScanError(f"blob {digest} missing")
        Upstream(repo).fetch_blob(image, digest)


def image_blobs(version):
    """(manifest, [manifest, config and layer digests – all present in the store], platform) of the image
    platform that is scanned (amd64, else the first real platform of a multi-arch index)."""
    repo = version.package.repository
    image = version.package.name
    m = _ensure_manifest(repo, image, version.digest)
    platform = None
    if m.media_type in INDEX_TYPES:
        index = json.loads(storage.read_blob(m.digest))
        candidates = [c for c in index.get("manifests", [])
                      if c.get("platform", {}).get("os") not in (None, "unknown")]
        chosen = next((c for c in candidates if c["platform"].get("architecture") == "amd64"), None)
        chosen = chosen or (candidates[0] if candidates else None)
        if chosen is None:
            raise ScanError("no scannable platform in image index")
        platform = f"{chosen['platform']['os']}/{chosen['platform']['architecture']}"
        m = _ensure_manifest(repo, image, chosen["digest"])
    doc = json.loads(storage.read_blob(m.digest))
    digests = [m.digest, doc["config"]["digest"]] + [
        layer["digest"] for layer in doc.get("layers", []) if "foreign" not in layer.get("mediaType", "")
    ]
    for d in digests:
        _ensure_blob(repo, image, d)
    return m, digests, platform


def prepare_oci_layout(version, work):
    """Assemble an OCI image layout from stored blobs so Trivy can scan it offline."""
    m, digests, platform = image_blobs(version)
    layout = os.path.join(work, "oci")
    for d in digests:
        storage.export_blob(d, os.path.join(layout, "blobs", "sha256", d.split(":", 1)[1]))
    with open(os.path.join(layout, "oci-layout"), "w") as f:
        json.dump({"imageLayoutVersion": "1.0.0"}, f)
    with open(os.path.join(layout, "index.json"), "w") as f:
        json.dump({"schemaVersion": 2, "manifests": [{
            "mediaType": m.media_type, "digest": m.digest, "size": m.size,
            "annotations": {"org.opencontainers.image.ref.name": version.version},
        }]}, f)
    return layout, platform


# --- trivy --------------------------------------------------------------------

def _run(cmd, timeout):
    env = netproxy.subprocess_env()  # outbound proxy for Trivy DB downloads
    env.setdefault("TRIVY_NO_PROGRESS", "true")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    if proc.returncode != 0:
        raise ScanError(f"{' '.join(cmd[:2])} failed: {proc.stderr.strip()[-2000:]}")
    return proc


def run_trivy(mode, target, work):
    cfg = current_app.config
    trivy = cfg["TRIVY_PATH"]
    report = os.path.join(work, "report.json")
    sbom = os.path.join(work, "sbom.cdx.json")
    cmd = [trivy, mode, "--cache-dir", cfg["TRIVY_CACHE_DIR"], "--format", "json", "--list-all-pkgs",
           "--scanners", "vuln", "--quiet", "--timeout", f"{cfg['TRIVY_TIMEOUT']}s", "--output", report,
           # in-memory analysis cache: parallel workers would serialize on the shared on-disk cache lock
           "--cache-backend", "memory"]
    # DB updates are scheduled by the worker (scanner admin page); scans use the local DB only
    if _db_present("vuln"):
        cmd.append("--skip-db-update")
    if _db_present("java"):
        cmd.append("--skip-java-db-update")
    cmd += ["--input", target] if mode == "image" else [target]
    _run(cmd, cfg["TRIVY_TIMEOUT"] + 60)
    _run([trivy, "convert", "--format", "cyclonedx", "--output", sbom, report], 300)
    with open(report) as f:
        data = json.load(f)
    with open(sbom, "rb") as f:
        sbom_bytes = f.read()

    findings = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            findings.append({
                "vuln_id": v.get("VulnerabilityID"),
                "pkg_name": v.get("PkgName"),
                "pkg_type": result.get("Type"),
                "installed_version": v.get("InstalledVersion"),
                "fixed_version": v.get("FixedVersion"),
                "severity": (v.get("Severity") or "UNKNOWN").upper(),
                "title": v.get("Title") or (v.get("Description") or "")[:300],
                "url": v.get("PrimaryURL"),
                "aliases": [],
                "source": "trivy",
            })
    return findings, sbom_bytes


# --- OSV ----------------------------------------------------------------------

def _osv_fixed(vuln, name):
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def osv_version(fmt, version):
    """OSV expects Go module versions without the leading 'v' and without +incompatible."""
    if fmt == "go":
        return version[1:].split("+")[0] if version.startswith("v") else version
    return version


def query_osv(fmt, name, version):
    cfg = current_app.config
    r = netproxy.request("POST", cfg["OSV_URL"], json={
        "package": {"name": name, "ecosystem": OSV_ECOSYSTEM[fmt]}, "version": version}, timeout=30)
    r.raise_for_status()
    findings = []
    for v in r.json().get("vulns", []):
        sev = OSV_SEVERITY.get(str(v.get("database_specific", {}).get("severity", "")).upper(), "UNKNOWN")
        aliases = v.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), None)
        findings.append({
            "vuln_id": cve or v["id"],
            "pkg_name": name,
            "pkg_type": fmt,
            "installed_version": version,
            "fixed_version": _osv_fixed(v, name),
            "severity": sev,
            "title": v.get("summary") or (v.get("details") or "")[:300],
            "url": f"https://osv.dev/vulnerability/{v['id']}",
            "aliases": aliases + [v["id"]],
            "source": "osv",
        })
    return findings


# --- SBOM ---------------------------------------------------------------------

def minimal_sbom(version):
    pkg = version.package
    fmt = pkg.repository.format
    components = []
    meta = version.meta or {}
    if fmt == "pypi":
        for req in meta.get("requires_dist", []):
            components.append({"type": "library", "name": req.split(";")[0].strip(), "scope": "required"})
    elif fmt == "npm":
        for dep, rng in ((meta.get("manifest") or {}).get("dependencies") or {}).items():
            components.append({"type": "library", "name": dep, "version": rng, "purl": f"pkg:npm/{dep}"})
    else:  # maven / go / nuget / cargo / helm: [{"name", "version"}] collected at upload or caching time
        for dep in meta.get("dependencies") or []:
            comp = {"type": "library", "name": dep["name"]}
            if dep.get("version"):
                comp["version"] = dep["version"]
            if fmt in ("go", "cargo", "nuget", "maven", "helm") and dep.get("version"):
                comp["purl"] = purl(fmt, dep["name"], dep["version"])
            components.append(comp)
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "florepo"}]},
            "component": _root_component(version),
        },
        "components": components,
    }
    return json.dumps(doc, indent=2).encode()


def _root_component(version):
    pkg = version.package
    fmt = pkg.repository.format
    comp = {
        "type": "container" if fmt == "docker" else "library",
        "bom-ref": purl(fmt, pkg.display_name, version.version),
        "name": pkg.display_name,
        "version": version.version,
        "purl": purl(fmt, pkg.display_name, version.version),
    }
    if fmt == "docker" and version.digest:
        comp["hashes"] = [{"alg": "SHA-256", "content": version.digest.split(":", 1)[1]}]
    elif version.files:
        comp["hashes"] = [{"alg": "SHA-256", "content": version.files[0].sha256}]
    return comp


def _annotate_sbom(sbom_bytes, version, extra_vulns):
    """Make the SBOM describe the artifact itself and add OSV-only findings."""
    doc = json.loads(sbom_bytes)
    root = _root_component(version)
    meta = doc.setdefault("metadata", {})
    old = meta.get("component") or {}
    if old.get("bom-ref"):
        root["bom-ref"] = old["bom-ref"]  # keep dependency graph references intact
    meta["component"] = {**old, **root}
    if extra_vulns:
        vulns = doc.setdefault("vulnerabilities", [])
        for f in extra_vulns:
            vulns.append({
                "id": f["vuln_id"],
                "source": {"name": "OSV", "url": f["url"]},
                "ratings": [{"severity": f["severity"].lower()}],
                "description": f["title"],
                "affects": [{"ref": root["bom-ref"]}],
            })
    return json.dumps(doc, indent=2).encode(), len(doc.get("components", []))


# --- OS packages (deb / rpm / apk) ---------------------------------------------------

# Trivy OS families
DISTRO_FAMILIES = {"debian", "ubuntu", "alpine", "rocky", "alma", "centos", "redhat", "oracle", "amazon",
                   "opensuse.leap", "sles", "photon", "azurelinux", "wolfi", "chainguard"}
DISTRO_ALIASES = {"almalinux": "alma", "rhel": "redhat", "rockylinux": "rocky", "ol": "oracle",
                  "amazonlinux": "amazon", "suse": "sles"}
CODENAMES = {"buster": ("debian", "10"), "bullseye": ("debian", "11"), "bookworm": ("debian", "12"),
             "trixie": ("debian", "13"), "forky": ("debian", "14"), "focal": ("ubuntu", "20.04"),
             "jammy": ("ubuntu", "22.04"), "noble": ("ubuntu", "24.04"), "oracular": ("ubuntu", "24.10"),
             "plucky": ("ubuntu", "25.04"), "questing": ("ubuntu", "25.10")}
RPM_HOSTS = {"rockylinux": "rocky", "almalinux": "alma", "centos": "centos", "redhat": "redhat",
             "oracle": "oracle", "amazonlinux": "amazon", "amazonaws": "amazon"}


def parse_distro(value):
    """'debian:12' / 'Debian 12' / 'almalinux-9' -> ('debian', '12') or None."""
    m = re.match(r"^\s*([A-Za-z][A-Za-z.]*)[\s:/-]+v?([\d.]+|edge)\s*$", value or "")
    if not m:
        return None
    family = DISTRO_ALIASES.get(m.group(1).lower(), m.group(1).lower())
    return (family, m.group(2)) if family in DISTRO_FAMILIES else None


def infer_distro(version):
    """Distribution for vulnerability matching: repository setting, else derived from paths/versions."""
    repo = version.package.repository
    if repo.distro:
        return parse_distro(repo.distro)
    paths = [f.path or "" for f in version.files]
    if repo.format == "apk":
        for p in paths:
            m = re.match(r"^v(\d+\.\d+)/", p)
            if m:
                return "alpine", m.group(1)
        return None
    if repo.format == "rpm":
        m = re.search(r"\.el(\d+)", version.version)
        host = (repo.upstream_url or "").lower()
        family = next((fam for key, fam in RPM_HOSTS.items() if key in host), None)
        return (family, m.group(1)) if m and family else None
    m = re.search(r"[+~]deb(\d+)", version.version)
    if m:
        return "debian", m.group(1)
    m = re.search(r"~(\d{2}\.\d{2})", version.version)
    if m and "ubuntu" in version.version:
        return "ubuntu", m.group(1)
    from . import settings  # suites requested through a Debian proxy, e.g. ['bookworm']
    suites = {CODENAMES[s] for s in (settings.get(f"deb_suites:{repo.id}") or []) if s in CODENAMES}
    return suites.pop() if len(suites) == 1 else None


def build_os_sbom(version, distro, work):
    family, release = distro
    fmt = version.package.repository.format
    comps, refs = [{"type": "operating-system", "bom-ref": "os", "name": family, "version": release}], []
    for f in version.files:
        info = (f.meta or {}).get("info") or {}
        name, ver, arch = info.get("name") or version.package.name, info.get("version") or version.version, info.get("arch")
        if fmt == "deb":
            p = f"pkg:deb/{family}/{name}@{quote(ver, safe='')}?arch={arch}&distro={family}-{release}"
        elif fmt == "apk":
            p = f"pkg:apk/{family}/{name}@{quote(ver, safe='')}?arch={arch}&distro={release}"
        else:
            epoch, _, plain = ver.rpartition(":")
            p = f"pkg:rpm/{family}/{name}@{plain}?arch={arch}" + (f"&epoch={epoch}" if epoch else "") + \
                f"&distro={family}-{release}"
        if any(c.get("purl") == p for c in comps):
            continue
        props = [{"name": "aquasecurity:trivy:PkgType", "value": family},
                 {"name": "aquasecurity:trivy:SrcName", "value": info.get("source") or name},
                 {"name": "aquasecurity:trivy:SrcVersion", "value": (info.get("source_version") or ver).rpartition(":")[2]}]
        if fmt == "rpm" and info.get("epoch"):
            props.append({"name": "aquasecurity:trivy:SrcEpoch", "value": str(info["epoch"])})
        ref = f"pkg{len(refs)}"
        refs.append(ref)
        comps.append({"type": "library", "bom-ref": ref, "name": name, "version": ver, "purl": p, "properties": props})
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
           "metadata": {"component": {"type": "application", "bom-ref": "root", "name": version.package.name,
                                      "version": version.version}},
           "components": comps,
           "dependencies": [{"ref": "root", "dependsOn": ["os"]}, {"ref": "os", "dependsOn": refs}]}
    path = os.path.join(work, "input.cdx.json")
    with open(path, "w") as f:
        json.dump(doc, f)
    return path


# --- orchestration ------------------------------------------------------------

def _trivy_label():
    """e.g. '0.74.0' – also remembers the DB timestamp used for this scan."""
    info = trivy_info() or {}
    _trivy_label.db = (info.get("VulnerabilityDB") or {}).get("UpdatedAt")
    return info.get("Version", "")


def scan_version(version: Version):
    repo = version.package.repository
    fmt = repo.format
    findings, sbom_bytes, scanners = [], None, []
    platform = None
    trivy_error = None

    with tempfile.TemporaryDirectory(dir=storage.tmp_dir()) as work:
        if trivy_available():
            try:
                if fmt == "docker":
                    target, platform = prepare_oci_layout(version, work)
                    findings, sbom_bytes = run_trivy("image", target, work)
                elif fmt in OS_FORMATS:
                    distro = infer_distro(version)
                    if distro is None:
                        raise ScanError("unknown distribution - set it in the repository settings "
                                        "(e.g. debian:12, alpine:3.20, rocky:9) to enable vulnerability scanning")
                    findings, sbom_bytes = run_trivy("sbom", build_os_sbom(version, distro, work), work)
                    platform = f"{distro[0]} {distro[1]}"
                else:
                    target = prepare_package(version, work)
                    findings, sbom_bytes = run_trivy(TRIVY_MODE.get(fmt, "rootfs"), target, work)
                scanners.append(f"trivy {_trivy_label()}")
            except (ScanError, subprocess.TimeoutExpired) as exc:
                trivy_error = str(exc)
        elif fmt == "docker" or fmt in OS_FORMATS:
            trivy_error = f"trivy is not installed - {fmt} packages cannot be scanned"

    osv_findings = []
    if fmt in OSV_ECOSYSTEM and current_app.config["OSV_ENABLED"]:
        try:
            osv_findings = query_osv(fmt, version.package.display_name, osv_version(fmt, version.version))
            scanners.append("osv.dev")
        except Exception as exc:
            current_app.logger.warning("OSV query failed: %s", exc)

    # merge, de-duplicating OSV findings already reported by trivy
    known = {(f["vuln_id"], (f["pkg_name"] or "").lower()) for f in findings}
    extra = []
    for f in osv_findings:
        ids = {f["vuln_id"], *f["aliases"]}
        if not any((i, f["pkg_name"].lower()) in known for i in ids):
            extra.append(f)
    findings += extra

    if not scanners:
        raise ScanError(trivy_error or "no scanner available")

    if sbom_bytes is None:
        sbom_bytes = minimal_sbom(version)
    sbom_bytes, components = _annotate_sbom(sbom_bytes, version, extra)

    Vulnerability.query.filter_by(version_id=version.id).delete()
    seen = set()
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        key = (f["vuln_id"], f["pkg_name"], f["installed_version"])
        if key in seen:
            continue
        seen.add(key)
        sev = f["severity"] if f["severity"] in counts else "UNKNOWN"
        counts[sev] += 1
        db.session.add(Vulnerability(
            version_id=version.id, vuln_id=f["vuln_id"][:64], pkg_name=(f["pkg_name"] or "")[:255],
            pkg_type=(f["pkg_type"] or "")[:64], installed_version=(f["installed_version"] or "")[:128],
            fixed_version=(f["fixed_version"] or "")[:255], severity=sev, title=f["title"],
            url=(f["url"] or "")[:512], source=f["source"],
        ))
    for sev, n in counts.items():
        setattr(version, f"count_{sev.lower()}", n)
    version.sbom_key = storage.write_sbom(version.id, sbom_bytes)
    version.component_count = components
    version.scanner = ", ".join(scanners)[:64]
    version.scanned_at = utcnow()
    version.scan_status = "done"
    version.scan_error = trivy_error
    extra_meta = {"scanned_platform": platform} if platform else {}
    if scanners and scanners[0].startswith("trivy"):
        extra_meta["trivy_db"] = getattr(_trivy_label, "db", None)
    if extra_meta:
        version.meta = {**(version.meta or {}), **extra_meta}
