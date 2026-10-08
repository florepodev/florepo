import hashlib
import secrets
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # UNKNOWN=0 ... CRITICAL=4

FORMATS = ["docker", "pypi", "npm", "maven", "go", "nuget", "cargo", "helm", "generic", "deb", "rpm", "apk"]
OS_FORMATS = ["deb", "rpm", "apk"]
FORMAT_LABELS = {"docker": "Docker / OCI", "pypi": "PyPI", "npm": "npm", "maven": "Maven / Gradle", "go": "Go modules",
                 "nuget": "NuGet", "cargo": "Cargo (Rust)", "helm": "Helm charts", "generic": "Generic files",
                 "deb": "Debian / Ubuntu (apt)", "rpm": "RPM (dnf / yum)", "apk": "Alpine (apk)"}
AUTH_SOURCES = ["local", "ldap"]
MALWARE_STATES = ["none", "clean", "infected", "error"]
KINDS = ["hosted", "proxy"]
# auditor: read-only view of everything incl. private repositories, reports, audit log and SBOMs – but no
# package downloads through the client protocols and no changes
ROLES = ["reader", "deployer", "auditor", "admin"]

DEFAULT_UPSTREAMS = {
    "pypi": "https://pypi.org",
    "npm": "https://registry.npmjs.org",
    "deb": "http://deb.debian.org/debian",
    "rpm": "https://dl.rockylinux.org/pub/rocky",
    "apk": "https://dl-cdn.alpinelinux.org/alpine",
    "maven": "https://repo1.maven.org/maven2",
    "go": "https://proxy.golang.org",
    "nuget": "https://api.nuget.org/v3/index.json",
    "cargo": "https://index.crates.io",
    "helm": "https://prometheus-community.github.io/helm-charts",
}


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


user_deploy_repos = db.Table(
    "user_deploy_repos",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True),
    db.Column("repository_id", db.Integer, db.ForeignKey("repository.id", ondelete="CASCADE"), primary_key=True),
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="reader")
    active = db.Column(db.Boolean, nullable=False, default=True)
    # deployers: False = may publish to every hosted repo, True = only to `deploy_repos`
    restrict_deploy = db.Column(db.Boolean, nullable=False, default=False)
    # local = password stored here, ldap = authenticated against the directory (role/repos synced from groups)
    auth_source = db.Column(db.String(16), nullable=False, default="local", server_default="local")
    ldap_dn = db.Column(db.String(512))
    email = db.Column(db.String(255))
    display_name = db.Column(db.String(255))
    # set by LDAP login/sync when the directory account is gone, disabled or no longer in a mapped group
    directory_disabled = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    quota_bytes = db.Column(db.BigInteger)  # max. bytes uploaded by this user (None = global default, 0 = unlimited)
    last_login_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow)

    tokens = db.relationship("ApiToken", backref="user", cascade="all, delete-orphan")
    deploy_repos = db.relationship("Repository", secondary=user_deploy_repos, lazy="select",
                                   order_by="Repository.name")

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    @property
    def is_active(self):
        return self.active and not self.directory_disabled

    @property
    def is_ldap(self):
        return self.auth_source == "ldap"

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_auditor(self):
        return self.role == "auditor"

    @property
    def can_audit(self):
        """May see reports, the audit log and all users' activity."""
        return self.role in ("auditor", "admin")

    @property
    def can_deploy(self):
        """May publish to at least some repository (see can_deploy_to for a specific one)."""
        return self.role in ("deployer", "admin")

    def can_deploy_to(self, repo):
        if self.role == "admin":
            return True
        if self.role != "deployer":
            return False
        return not self.restrict_deploy or any(r.id == repo.id for r in self.deploy_repos)


TOKEN_PREFIX = "flo_"


def is_token(value):
    return bool(value) and value.startswith(TOKEN_PREFIX)


class ApiToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    prefix = db.Column(db.String(16), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_used_at = db.Column(db.DateTime)

    @staticmethod
    def hash(raw):
        return hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def issue(cls, user, name):
        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        tok = cls(user=user, name=name, prefix=raw[:12], token_hash=cls.hash(raw))
        db.session.add(tok)
        return tok, raw

    @classmethod
    def lookup(cls, raw):
        if not is_token(raw):
            return None
        return cls.query.filter_by(token_hash=cls.hash(raw)).first()


class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False, index=True)
    format = db.Column(db.String(16), nullable=False)
    kind = db.Column(db.String(16), nullable=False, default="hosted")
    upstream_url = db.Column(db.String(255))
    # optional credentials for the upstream (e.g. Docker Hub rate limits, private mirrors)
    upstream_username = db.Column(db.String(255))
    upstream_password = db.Column(db.String(512))
    # outbound connection of proxy repositories: global (Administration → Network) | none (direct) | custom
    proxy_mode = db.Column(db.String(16), nullable=False, default="global", server_default="global")
    proxy_url = db.Column(db.String(512))
    # OS package repositories: distribution used for vulnerability matching, e.g. debian:12, alpine:3.20, rocky:9
    distro = db.Column(db.String(32))
    # proxy repositories: delete cached artifacts not requested for this many days (None/0 = keep forever)
    cache_retention_days = db.Column(db.Integer)
    # hosted: max. stored bytes (uploads beyond are rejected), proxy: cache size limit (LRU eviction). None = unlimited
    quota_bytes = db.Column(db.BigInteger)
    description = db.Column(db.String(255), default="")
    public = db.Column(db.Boolean, nullable=False, default=False)
    # Block downloads of versions having at least one finding >= this severity (None = never block)
    block_severity = db.Column(db.String(16))
    allow_redeploy = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    packages = db.relationship("Package", backref="repository", cascade="all, delete-orphan")

    @property
    def is_proxy(self):
        return self.kind == "proxy"


class Package(db.Model):
    __table_args__ = (db.UniqueConstraint("repository_id", "name"),)
    id = db.Column(db.Integer, primary_key=True)
    repository_id = db.Column(db.Integer, db.ForeignKey("repository.id"), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)  # normalized name / image name
    display_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    # npm: dist-tags etc.
    meta = db.Column(db.JSON, default=dict)

    versions = db.relationship(
        "Version", backref="package", cascade="all, delete-orphan", order_by="Version.created_at.desc()"
    )


class Version(db.Model):
    __table_args__ = (db.UniqueConstraint("package_id", "version"),)
    id = db.Column(db.Integer, primary_key=True)
    package_id = db.Column(db.Integer, db.ForeignKey("package.id"), nullable=False, index=True)
    version = db.Column(db.String(128), nullable=False)  # docker: tag
    digest = db.Column(db.String(100))  # docker: manifest digest
    meta = db.Column(db.JSON, default=dict)
    uploaded_by = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    download_count = db.Column(db.Integer, nullable=False, default=0)
    last_accessed_at = db.Column(db.DateTime, index=True)  # last pull (aggregated by the worker)

    # scan state
    scan_status = db.Column(db.String(16), nullable=False, default="none", index=True)
    scan_worker = db.Column(db.String(128))  # worker currently scanning this version (several workers may run)
    scan_started_at = db.Column(db.DateTime)
    scan_error = db.Column(db.Text)
    scanned_at = db.Column(db.DateTime)
    scanner = db.Column(db.String(64))
    count_critical = db.Column(db.Integer, nullable=False, default=0)
    count_high = db.Column(db.Integer, nullable=False, default=0)
    count_medium = db.Column(db.Integer, nullable=False, default=0)
    count_low = db.Column(db.Integer, nullable=False, default=0)
    count_unknown = db.Column(db.Integer, nullable=False, default=0)
    sbom_key = db.Column(db.String(255))
    component_count = db.Column(db.Integer, nullable=False, default=0)

    # ClamAV malware scan
    malware_status = db.Column(db.String(16), nullable=False, default="none", server_default="none", index=True)
    malware_name = db.Column(db.String(255))  # signature(s) found
    malware_scanned_at = db.Column(db.DateTime)

    files = db.relationship("ArtifactFile", backref="version", cascade="all, delete-orphan")
    vulnerabilities = db.relationship("Vulnerability", backref="version", cascade="all, delete-orphan")

    @property
    def total_vulns(self):
        return self.count_critical + self.count_high + self.count_medium + self.count_low + self.count_unknown

    @property
    def max_severity(self):
        for sev in SEVERITIES:
            if getattr(self, f"count_{sev.lower()}"):
                return sev
        return None

    def is_blocked(self):
        return self.block_reason() is not None

    def block_reason(self):
        """None or why downloads are refused: 'malware', 'unscanned' or 'severity'."""
        from . import malware

        if malware.blocks(self):
            return "malware" if self.malware_status == "infected" else "unscanned"
        return "severity" if self._severity_blocked() else None

    def _severity_blocked(self):
        sev = self.package.repository.block_severity
        # the last completed scan keeps applying while a re-scan is queued / running or a re-scan failed
        if not sev or (self.scanned_at is None and self.scan_status != "done"):
            return False
        threshold = SEVERITY_RANK[sev]
        return any(
            getattr(self, f"count_{s.lower()}") and SEVERITY_RANK[s] >= threshold for s in SEVERITIES
        )

    def request_scan(self):
        self.scan_status = "pending"
        self.scan_error = None


class ArtifactFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_id = db.Column(db.Integer, db.ForeignKey("version.id"), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    # OS package repositories: path inside the repository (e.g. pool/main/o/openssl/libssl3_3.0.15-1_amd64.deb)
    path = db.Column(db.String(512), index=True)
    sha256 = db.Column(db.String(64), nullable=False)
    size = db.Column(db.BigInteger, nullable=False, default=0)
    content_type = db.Column(db.String(128))
    meta = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=utcnow)


class DockerManifest(db.Model):
    __table_args__ = (db.UniqueConstraint("repository_id", "image", "digest"),)
    id = db.Column(db.Integer, primary_key=True)
    repository_id = db.Column(db.Integer, db.ForeignKey("repository.id"), nullable=False, index=True)
    image = db.Column(db.String(255), nullable=False)
    digest = db.Column(db.String(100), nullable=False)
    media_type = db.Column(db.String(255), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    # image manifests: {digest: size} of config + layers (storage accounting for quotas), None = not yet known
    blobs = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=utcnow)


class DockerBlobLink(db.Model):
    """Blobs are stored once (content addressed) but only served through repositories they belong to:
    uploaded / mounted into the repository or referenced by one of its manifests."""
    repository_id = db.Column(db.Integer, db.ForeignKey("repository.id", ondelete="CASCADE"), primary_key=True)
    digest = db.Column(db.String(100), primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow)


class DockerUpload(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    repository_id = db.Column(db.Integer, db.ForeignKey("repository.id"), nullable=False)
    image = db.Column(db.String(255), nullable=False)
    size = db.Column(db.BigInteger, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=utcnow)


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_id = db.Column(db.Integer, db.ForeignKey("version.id"), nullable=False, index=True)
    vuln_id = db.Column(db.String(64), nullable=False, index=True)
    pkg_name = db.Column(db.String(255))
    pkg_type = db.Column(db.String(64))
    installed_version = db.Column(db.String(128))
    fixed_version = db.Column(db.String(255))
    severity = db.Column(db.String(16), nullable=False, default="UNKNOWN")
    title = db.Column(db.Text)
    url = db.Column(db.String(512))
    source = db.Column(db.String(32))


class DownloadEvent(db.Model):
    """One row per package pull – the base for usage reporting ("who pulled what")."""
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    repository_id = db.Column(db.Integer, db.ForeignKey("repository.id", ondelete="SET NULL"), index=True)
    package_id = db.Column(db.Integer, db.ForeignKey("package.id", ondelete="SET NULL"), index=True)
    version_id = db.Column(db.Integer, db.ForeignKey("version.id", ondelete="SET NULL"), index=True)
    # denormalized so reports survive deletions and stay cheap to query
    format = db.Column(db.String(16))
    repo_name = db.Column(db.String(64))
    package_name = db.Column(db.String(255))
    version_name = db.Column(db.String(128))
    filename = db.Column(db.String(255))
    username = db.Column(db.String(80), index=True)  # "anonymous" if unauthenticated
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    cache_hit = db.Column(db.Boolean)  # proxy repos: served from cache?

    version = db.relationship("Version")


class Notification(db.Model):
    """A queued/sent security alert for one version (several are batched into one e-mail)."""
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    version_id = db.Column(db.Integer, db.ForeignKey("version.id", ondelete="SET NULL"), index=True)
    repo_name = db.Column(db.String(64))
    package_name = db.Column(db.String(255))
    version_name = db.Column(db.String(128))
    trigger = db.Column(db.String(16))  # rescan | upload
    max_severity = db.Column(db.String(16))
    findings = db.Column(db.JSON, default=list)  # [{id, severity, component, installed, fixed, title}]
    recipients = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    error = db.Column(db.Text)


class Setting(db.Model):
    """Runtime-editable settings and small pieces of shared state (web <-> worker)."""
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.JSON)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    username = db.Column(db.String(80))
    action = db.Column(db.String(64), nullable=False)
    target = db.Column(db.String(512))

    @classmethod
    def log(cls, username, action, target):
        db.session.add(cls(username=username, action=action, target=target))


class RepoFile(db.Model):
    """Metadata files of OS package repositories: cached upstream indexes (Release, Packages, repomd.xml,
    APKINDEX.tar.gz, …) of proxy repositories and generated, signed indexes of hosted repositories."""
    __table_args__ = (db.UniqueConstraint("repository_id", "path"),)
    id = db.Column(db.Integer, primary_key=True)
    repository_id = db.Column(db.Integer, db.ForeignKey("repository.id", ondelete="CASCADE"), nullable=False,
                              index=True)
    path = db.Column(db.String(512), nullable=False)
    digest = db.Column(db.String(100), nullable=False)
    size = db.Column(db.BigInteger, nullable=False, default=0)
    content_type = db.Column(db.String(128))
    fetched_at = db.Column(db.DateTime, default=utcnow)


# --- change tracking for the metadata cache (app/metacache.py) ------------------------------------------
from sqlalchemy import event as _event, select as _select, update as _update  # noqa: E402
from sqlalchemy.orm import Session as _Session  # noqa: E402


@_event.listens_for(_Session, "after_flush")
def _touch_packages(session, _ctx):
    """Every change of a version or file (upload, delete, scan result, malware verdict, yank, ...) bumps
    Package.updated_at in the same transaction – the metadata cache keys its documents on that value."""
    package_ids, version_ids = set(), set()
    for obj in (*session.new, *session.deleted, *(o for o in session.dirty if session.is_modified(o))):
        if isinstance(obj, Version):
            if obj.package_id:
                package_ids.add(obj.package_id)
        elif isinstance(obj, ArtifactFile) and obj.version_id:
            version_ids.add(obj.version_id)
    conn = session.connection()
    if version_ids:
        package_ids |= set(conn.execute(_select(Version.package_id).where(Version.id.in_(version_ids))).scalars())
    if package_ids:
        conn.execute(_update(Package.__table__).where(Package.__table__.c.id.in_(package_ids))
                     .values(updated_at=utcnow()))
