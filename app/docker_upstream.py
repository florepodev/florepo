"""Client for upstream OCI registries (Docker Hub, GHCR, Quay, ...) used by docker proxy repos."""
import hashlib
import json
import re
import threading
import time

from flask import current_app

from . import netproxy, storage
from .extensions import db
from .models import DockerManifest, utcnow

MANIFEST_TYPES = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
]
INDEX_TYPES = MANIFEST_TYPES[:2]

DOCKER_HUB = "https://registry-1.docker.io"

_tokens: dict[tuple, tuple[str, float]] = {}
_lock = threading.Lock()


def _parse_challenge(header):
    scheme, _, rest = header.partition(" ")
    params = dict(re.findall(r'(\w+)="([^"]*)"', rest))
    return scheme.lower(), params


class Upstream:
    def __init__(self, repo):
        self.repo = repo
        self.base = (repo.upstream_url or DOCKER_HUB).rstrip("/")
        if self.base in ("https://docker.io", "https://index.docker.io", "https://hub.docker.com"):
            self.base = DOCKER_HUB
        self.auth = (repo.upstream_username, repo.upstream_password) if repo.upstream_username else None
        self.timeout = current_app.config["UPSTREAM_TIMEOUT"]

    def image_name(self, image):
        if self.base == DOCKER_HUB and "/" not in image:
            return f"library/{image}"
        return image

    def _token(self, params):
        key = (self.base, params.get("scope"), self.auth[0] if self.auth else None)
        with _lock:
            hit = _tokens.get(key)
            if hit and hit[1] > time.time():
                return hit[0]
        q = {k: params[k] for k in ("service", "scope") if k in params}
        r = netproxy.get(params["realm"], repo=self.repo, params=q, auth=self.auth, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        tok = data.get("token") or data.get("access_token")
        ttl = max(int(data.get("expires_in", 60)) - 10, 20)
        with _lock:
            _tokens[key] = (tok, time.time() + ttl)
        return tok

    def request(self, method, image, path, headers=None, stream=False):
        url = f"{self.base}/v2/{self.image_name(image)}/{path}"
        headers = dict(headers or {})
        r = netproxy.request(method, url, repo=self.repo, headers=headers, stream=stream, timeout=self.timeout)
        if r.status_code == 401 and "WWW-Authenticate" in r.headers:
            scheme, params = _parse_challenge(r.headers["WWW-Authenticate"])
            r.close()
            if scheme == "bearer" and "realm" in params:
                params.setdefault("scope", f"repository:{self.image_name(image)}:pull")
                headers["Authorization"] = f"Bearer {self._token(params)}"
                r = netproxy.request(method, url, repo=self.repo, headers=headers, stream=stream, timeout=self.timeout)
            elif scheme == "basic" and self.auth:
                r = netproxy.request(method, url, repo=self.repo, headers=headers, stream=stream, auth=self.auth,
                                     timeout=self.timeout)
        return r

    # --- manifests ---------------------------------------------------------

    def head_manifest(self, image, reference):
        r = self.request("HEAD", image, f"manifests/{reference}", {"Accept": ", ".join(MANIFEST_TYPES)})
        if r.status_code != 200:
            return None
        return r.headers.get("Docker-Content-Digest")

    def fetch_manifest(self, image, reference):
        """Fetch a manifest, verify and cache it. Returns DockerManifest or None (404)."""
        r = self.request("GET", image, f"manifests/{reference}", {"Accept": ", ".join(MANIFEST_TYPES)})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        body = r.content
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        if reference.startswith("sha256:") and reference != digest:
            raise ValueError("upstream manifest digest mismatch")
        media_type = r.headers.get("Content-Type", "").split(";")[0] or json.loads(body).get("mediaType")
        return cache_manifest(self.repo, image, digest, media_type, body)

    # --- blobs ---------------------------------------------------------------

    def open_blob(self, image, digest):
        r = self.request("GET", image, f"blobs/{digest}", stream=True)
        if r.status_code != 200:
            r.close()
            return None
        return r

    def fetch_blob(self, image, digest):
        """Download a blob fully into the store (used by the scanner)."""
        r = self.open_blob(image, digest)
        if r is None:
            raise FileNotFoundError(digest)
        with r:
            r.raw.decode_content = True
            got, _ = storage.store_stream(r.raw)
        if got != digest:
            raise ValueError("upstream blob digest mismatch")


def cache_manifest(repo, image, digest, media_type, body):
    storage.store_bytes(body)
    m = DockerManifest.query.filter_by(repository_id=repo.id, image=image, digest=digest).first()
    if m is None:
        from .quotas import blobs_of

        try:
            blobs = blobs_of(json.loads(body))
        except ValueError:
            blobs = {}
        m = DockerManifest(repository_id=repo.id, image=image, digest=digest,
                           media_type=media_type, size=len(body), blobs=blobs)
        db.session.add(m)
        db.session.flush()
        link_blobs(repo.id, [digest, *blobs])
    return m


# --- repository <-> blob membership -------------------------------------------------------------

def link_blobs(repo_id, digests):
    """Record that `digests` belong to a repository (idempotent, safe against concurrent pushes)."""
    from .models import DockerBlobLink

    digests = sorted({d for d in digests if d})
    if not digests:
        return
    rows = [{"repository_id": repo_id, "digest": d, "created_at": utcnow()} for d in digests]
    dialect = db.engine.dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    db.session.execute(insert(DockerBlobLink).values(rows).on_conflict_do_nothing())


def blob_linked(repo, digest):
    """May `digest` be served through `repo`? Manifests stored before links existed are linked on first use."""
    from . import settings
    from .models import DockerBlobLink

    if db.session.get(DockerBlobLink, (repo.id, digest)) is not None:
        return True
    key = f"docker_links_backfilled:{repo.id}"
    if settings.get(key):
        return False
    from .quotas import manifest_blobs

    for m in DockerManifest.query.filter_by(repository_id=repo.id):
        link_blobs(repo.id, [m.digest, *manifest_blobs(m)])
    settings.put(key, True)
    db.session.commit()
    return db.session.get(DockerBlobLink, (repo.id, digest)) is not None


def tee_blob(resp, digest):
    """Stream an upstream blob to the client while writing it into the cache."""
    sp = storage.Spool()  # bound to the backend now - the generator runs outside the app context

    def generate():
        with sp:
            try:
                for chunk in resp.iter_content(storage.CHUNK):
                    sp.write(chunk)
                    yield chunk
            finally:
                resp.close()
            if sp.close().digest == digest:
                sp.commit()

    return generate()
