"""Content-addressed blob storage for all artifact formats.

Backends (STORAGE_BACKEND):

* ``fs`` (default) – a directory (STORAGE_PATH). Works on local disks and on shared network file systems
  (NFS, SMB/CIFS, CephFS, ...) mounted into the containers: blobs are written to a temporary file in the same
  file system and atomically renamed into place.
* ``s3`` – any S3 compatible object store (AWS S3, MinIO, Ceph RGW, Garage, Wasabi, ...). Blobs and SBOMs are
  stored as objects; uploads are staged on local disk (STAGING_PATH) first so their digest can be verified.

Keys: ``blobs/sha256/<2 hex>/<64 hex>`` and ``sboms/<version id>.cdx.json``.

Serving: behind nginx (ACCEL_REDIRECT) the app only answers with an internal redirect and nginx streams the
file – from disk (fs) or from the object store (s3, S3_SERVE=proxy). S3_SERVE=redirect sends clients a
short-lived pre-signed URL instead, S3_SERVE=stream streams through Python (development without nginx).
"""
import contextlib
import hashlib
import io
import os
import shutil
import tempfile
import threading
import time
from urllib.parse import quote, urlsplit

from flask import Response, current_app, request, send_file, stream_with_context

CHUNK = 1024 * 1024
FILE_MODE = 0o644  # readable by nginx (X-Accel-Redirect), mkstemp defaults to 0600
HEX = set("0123456789abcdef")


# --- keys ------------------------------------------------------------------------------------------

def blob_key(digest):
    """digest: 'sha256:<hex>' or bare hex."""
    algo, _, hexd = digest.partition(":") if ":" in digest else ("sha256", "", digest)
    if algo != "sha256" or len(hexd) != 64 or not set(hexd) <= HEX:
        raise ValueError("unsupported digest")
    return f"blobs/sha256/{hexd[:2]}/{hexd}"


def sbom_key_path(key):
    if "/" in key or ".." in key:
        raise ValueError("invalid sbom key")
    return f"sboms/{key}"


# --- local staging -------------------------------------------------------------------------------------

def staging_root():
    cfg = current_app.config
    return cfg.get("STAGING_PATH") or cfg["STORAGE_PATH"]


def tmp_dir():
    """Local scratch space (uploads in progress, scanner work directories)."""
    d = os.path.join(staging_root(), "tmp")
    os.makedirs(d, exist_ok=True)
    return d


class Spool:
    """A file being written to the local staging area while its digest is computed.

    `commit()` moves it into the blob store; leaving the context without commit discards it.
    Create it inside the app context; it can then be used without one (e.g. in a streamed response)."""

    def __init__(self):
        self._backend = backend()
        fd, self.path = tempfile.mkstemp(dir=tmp_dir())
        self._f = os.fdopen(fd, "wb")
        self._h = hashlib.sha256()
        self.size = 0
        self.digest = None
        self.committed = False

    def write(self, chunk):
        self._h.update(chunk)
        self.size += len(chunk)
        self._f.write(chunk)

    def close(self):
        if not self._f.closed:
            self._f.close()
            self.digest = "sha256:" + self._h.hexdigest()
        return self

    def commit(self):
        self.close()
        self._backend.put_file(self.path, blob_key(self.digest))
        self.committed = True
        return self.digest, self.size

    def discard(self):
        self.close()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if not self.committed:
            self.discard()


def spool_stream(stream):
    """Copy a stream into a closed Spool (digest/size known, not yet stored). Use as context manager."""
    sp = Spool()
    try:
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            sp.write(chunk)
        return sp.close()
    except BaseException:
        sp.discard()
        raise


def store_stream(stream):
    """Write a stream into the blob store. Returns (digest, size)."""
    with spool_stream(stream) as sp:
        return sp.commit()


def store_bytes(data):
    return store_stream(io.BytesIO(data))


# --- backend facade ------------------------------------------------------------------------------------

def blob_exists(digest):
    try:
        return backend().exists(blob_key(digest))
    except ValueError:
        return False


def blob_size(digest):
    return backend().size(blob_key(digest))


def read_blob(digest):
    return backend().read(blob_key(digest))


def open_blob(digest):
    """Readable file-like object (close it after use)."""
    return backend().open(blob_key(digest))


def delete_blob(digest):
    backend().delete(blob_key(digest))


def export_blob(digest, dst):
    """Place a copy of a blob at a local path (hard link where possible)."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    backend().export(blob_key(digest), dst)


@contextlib.contextmanager
def local_file(digest):
    """Path of a local file with the blob's content for tools that need one (rpm, gpg, archive readers)."""
    path = backend().local_path(blob_key(digest))
    if path:
        yield path
        return
    fd, tmp = tempfile.mkstemp(dir=tmp_dir())
    os.close(fd)
    try:
        backend().export(blob_key(digest), tmp)
        yield tmp
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def iter_blobs():
    """(digest, size, mtime) of all stored blobs."""
    for key, size, mtime in backend().iter("blobs/sha256/"):
        name = key.rsplit("/", 1)[-1]
        if len(name) == 64 and set(name) <= HEX:
            yield f"sha256:{name}", size, mtime


# --- chunked uploads (docker) – always on local staging -----------------------------------------

def upload_path(upload_id):
    d = os.path.join(staging_root(), "uploads")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, upload_id)


def append_upload(upload_id, stream):
    with open(upload_path(upload_id), "ab") as f:
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            f.write(chunk)
    return os.path.getsize(upload_path(upload_id))


def upload_size(upload_id):
    p = upload_path(upload_id)
    return os.path.getsize(p) if os.path.exists(p) else 0


def finish_upload(upload_id, expected_digest):
    """Verify digest and move the upload into the blob store. Returns size or raises ValueError."""
    src = upload_path(upload_id)
    if not os.path.exists(src):
        open(src, "wb").close()
    h = hashlib.sha256()
    with open(src, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    actual = "sha256:" + h.hexdigest()
    if actual != expected_digest:
        os.unlink(src)
        raise ValueError(f"digest mismatch: got {actual}")
    size = os.path.getsize(src)
    backend().put_file(src, blob_key(actual))
    return size


def delete_upload(upload_id):
    with contextlib.suppress(FileNotFoundError):
        os.unlink(upload_path(upload_id))


# --- SBOMs -------------------------------------------------------------------------------------------

def write_sbom(version_id, data: bytes):
    key = f"{version_id}.cdx.json"
    backend().put_bytes(data, sbom_key_path(key))
    return key


def sbom_exists(key):
    try:
        return bool(key) and backend().exists(sbom_key_path(key))
    except ValueError:
        return False


def read_sbom(key):
    return backend().read(sbom_key_path(key))


def serve_sbom(key, download_name=None):
    return backend().serve(sbom_key_path(key), mimetype="application/vnd.cyclonedx+json",
                           download_name=download_name, as_attachment=bool(download_name))


# --- serving -------------------------------------------------------------------------------------------

def serve_blob(digest, mimetype="application/octet-stream", download_name=None, as_attachment=False,
               etag=None, headers=None):
    return backend().serve(blob_key(digest), mimetype=mimetype, download_name=download_name,
                           as_attachment=as_attachment, etag=etag or digest.split(":")[-1], headers=headers)


def _disposition(download_name, as_attachment):
    if not download_name:
        return None
    return f'{"attachment" if as_attachment else "inline"}; filename="{download_name}"'


# --- file system backend (local disk, NFS, ...) ----------------------------------------------------

class FSBackend:
    name = "fs"

    def __init__(self, root):
        self.root = root

    def describe(self):
        return {"backend": "fs", "location": self.root}

    def _p(self, key):
        return os.path.join(self.root, *key.split("/"))

    def local_path(self, key):
        p = self._p(key)
        return p if os.path.isfile(p) else None

    def exists(self, key):
        return os.path.isfile(self._p(key))

    def size(self, key):
        return os.path.getsize(self._p(key))

    def put_file(self, src, key):
        dest = self._p(key)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.exists(dest):
            os.unlink(src)
            return
        os.chmod(src, FILE_MODE)
        try:
            os.replace(src, dest)  # atomic within one file system
        except OSError:  # staging on another file system (STAGING_PATH): copy, then rename
            tmp = dest + f".{os.getpid()}.tmp"
            shutil.copyfile(src, tmp)
            os.chmod(tmp, FILE_MODE)
            os.replace(tmp, dest)
            os.unlink(src)

    def put_bytes(self, data, key):
        dest = self._p(key)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + f".{os.getpid()}.{threading.get_ident()}.tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.chmod(tmp, FILE_MODE)
        os.replace(tmp, dest)

    def read(self, key):
        with open(self._p(key), "rb") as f:
            return f.read()

    def open(self, key):
        return open(self._p(key), "rb")

    def export(self, key, dst):
        src = self._p(key)
        if not os.path.isfile(src):
            raise FileNotFoundError(key)
        if os.path.exists(dst):
            os.unlink(dst)
        try:
            os.link(src, dst)
        except OSError:
            shutil.copyfile(src, dst)

    def delete(self, key):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._p(key))

    def iter(self, prefix):
        base = self._p(prefix.rstrip("/"))
        for dirpath, _, files in os.walk(base):
            for fn in files:
                path = os.path.join(dirpath, fn)
                try:
                    st = os.stat(path)
                except FileNotFoundError:
                    continue
                rel = os.path.relpath(path, self.root).replace(os.sep, "/")
                yield rel, st.st_size, st.st_mtime

    def serve(self, key, mimetype="application/octet-stream", download_name=None, as_attachment=False,
              etag=None, headers=None):
        cfg = current_app.config
        if cfg["ACCEL_REDIRECT"]:
            resp = Response(status=200, mimetype=mimetype)
            resp.headers["X-Accel-Redirect"] = f"{cfg['ACCEL_PREFIX']}/{key}"
            disp = _disposition(download_name, as_attachment)
            if disp:
                resp.headers["Content-Disposition"] = disp
        else:
            resp = send_file(self._p(key), mimetype=mimetype, download_name=download_name,
                             as_attachment=as_attachment, conditional=True, etag=etag)
        if headers:
            resp.headers.update(headers)
        return resp

    def check(self):
        probe = f"tmp/.probe-{os.getpid()}"
        self.put_bytes(b"ok", probe)
        ok = self.read(probe) == b"ok"
        self.delete(probe)
        usage = shutil.disk_usage(self.root)
        return {"ok": ok, "free_bytes": usage.free, "total_bytes": usage.total}


# --- S3 backend ------------------------------------------------------------------------------------------

class S3Backend:
    """S3 compatible object storage via boto3. Existence/size lookups are cached briefly (blobs are immutable)."""
    name = "s3"
    CACHE_TTL = 60

    def __init__(self, cfg):
        import boto3
        from botocore.config import Config as BotoConfig

        self.bucket = cfg["S3_BUCKET"]
        if not self.bucket:
            raise RuntimeError("STORAGE_BACKEND=s3 requires S3_BUCKET")
        self.prefix = (cfg["S3_PREFIX"] or "").strip("/")
        self.endpoint = cfg["S3_ENDPOINT_URL"] or None
        self.serve_mode = cfg["S3_SERVE"]
        self.presign_expires = cfg["S3_PRESIGN_EXPIRES"]
        style = cfg["S3_ADDRESSING_STYLE"]
        if style == "auto" and self.endpoint:
            style = "path"  # MinIO, Ceph, Garage, ... rarely have wildcard DNS for virtual-hosted buckets
        boto_cfg = BotoConfig(
            region_name=cfg["S3_REGION"] or None,
            signature_version="s3v4",
            s3={"addressing_style": style},
            retries={"max_attempts": 5, "mode": "standard"},
            max_pool_connections=int(cfg["S3_MAX_CONNECTIONS"]),
            # the outbound HTTP proxy (Administration -> Network) is for upstream registries, not the object store
            proxies=None if cfg["S3_USE_PROXY"] else {"http": "", "https": ""},
        )
        verify = cfg["S3_CA_BUNDLE"] or cfg["S3_VERIFY_TLS"]
        self.client = boto3.session.Session().client(
            "s3", endpoint_url=self.endpoint, aws_access_key_id=cfg["S3_ACCESS_KEY_ID"] or None,
            aws_secret_access_key=cfg["S3_SECRET_ACCESS_KEY"] or None, config=boto_cfg, verify=verify)
        from boto3.s3.transfer import TransferConfig

        self.transfer = TransferConfig(multipart_threshold=64 * CHUNK, multipart_chunksize=64 * CHUNK,
                                       max_concurrency=4, use_threads=True)
        self._cache: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def describe(self):
        return {"backend": "s3", "location": f"s3://{self.bucket}/{self.prefix}".rstrip("/"),
                "endpoint": self.endpoint or "AWS", "serve": self.serve_mode}

    def _k(self, key):
        return f"{self.prefix}/{key}" if self.prefix else key

    def _remember(self, key, size):
        with self._lock:
            if len(self._cache) > 200_000:
                self._cache.clear()
            self._cache[key] = (size, time.time() + self.CACHE_TTL)

    def _head(self, key):
        with self._lock:
            hit = self._cache.get(key)
        if hit and hit[1] > time.time():
            return hit[0]
        from botocore.exceptions import ClientError

        try:
            size = self.client.head_object(Bucket=self.bucket, Key=self._k(key))["ContentLength"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                return None
            raise
        self._remember(key, size)
        return size

    def local_path(self, key):
        return None

    def exists(self, key):
        return self._head(key) is not None

    def size(self, key):
        size = self._head(key)
        if size is None:
            raise FileNotFoundError(key)
        return size

    def put_file(self, src, key):
        try:
            if key.startswith("blobs/") and self.exists(key):
                return  # content addressed: same key = same bytes
            size = os.path.getsize(src)
            self.client.upload_file(src, self.bucket, self._k(key), Config=self.transfer)
            self._remember(key, size)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(src)

    def put_bytes(self, data, key):
        self.client.put_object(Bucket=self.bucket, Key=self._k(key), Body=data)
        self._remember(key, len(data))

    def read(self, key):
        from botocore.exceptions import ClientError

        try:
            return self.client.get_object(Bucket=self.bucket, Key=self._k(key))["Body"].read()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey"):
                raise FileNotFoundError(key)
            raise

    def open(self, key):
        return self.client.get_object(Bucket=self.bucket, Key=self._k(key))["Body"]

    def export(self, key, dst):
        self.client.download_file(self.bucket, self._k(key), dst, Config=self.transfer)

    def delete(self, key):
        self.client.delete_object(Bucket=self.bucket, Key=self._k(key))
        with self._lock:
            self._cache.pop(key, None)

    def iter(self, prefix):
        pager = self.client.get_paginator("list_objects_v2")
        strip = len(self.prefix) + 1 if self.prefix else 0
        for page in pager.paginate(Bucket=self.bucket, Prefix=self._k(prefix)):
            for obj in page.get("Contents", []):
                yield obj["Key"][strip:], obj["Size"], obj["LastModified"].timestamp()

    def presign(self, key, mimetype=None, disposition=None, method="get_object"):
        params = {"Bucket": self.bucket, "Key": self._k(key)}
        if mimetype:
            params["ResponseContentType"] = mimetype
        if disposition:
            params["ResponseContentDisposition"] = disposition
        return self.client.generate_presigned_url(method, Params=params, ExpiresIn=self.presign_expires)

    def serve(self, key, mimetype="application/octet-stream", download_name=None, as_attachment=False,
              etag=None, headers=None):
        cfg = current_app.config
        disp = _disposition(download_name, as_attachment)
        mode = self.serve_mode
        if mode == "proxy" and not cfg["ACCEL_REDIRECT"]:
            mode = "stream"  # nginx is required for proxy mode
        if mode == "redirect":
            resp = Response(status=307, headers={"Location": self.presign(key, mimetype, disp)})
        elif mode == "proxy":
            # nginx fetches the pre-signed URL itself (location /_s3/ in docker/nginx.conf)
            u = urlsplit(self.presign(key, mimetype, disp))
            resp = Response(status=200, mimetype=mimetype)
            resp.headers["X-Accel-Redirect"] = f"/_s3/{u.scheme}/{u.netloc}{quote(u.path)}?{u.query}"
        else:
            resp = self._stream(key, mimetype, disp, etag)
        if headers:
            resp.headers.update(headers)
        return resp

    def _stream(self, key, mimetype, disp, etag):
        from botocore.exceptions import ClientError

        args = {"Bucket": self.bucket, "Key": self._k(key)}
        rng = request.headers.get("Range")
        if rng:
            args["Range"] = rng
        try:
            obj = self.client.get_object(**args)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidRange":
                return Response(status=416)
            if code in ("404", "NoSuchKey"):
                return Response("not found\n", 404)
            raise
        body = obj["Body"]

        def generate():
            try:
                yield from body.iter_chunks(CHUNK)
            finally:
                body.close()

        resp = Response(stream_with_context(generate()), status=206 if rng else 200, mimetype=mimetype,
                        direct_passthrough=True)
        resp.headers["Content-Length"] = str(obj["ContentLength"])
        resp.headers["Accept-Ranges"] = "bytes"
        if rng and obj.get("ContentRange"):
            resp.headers["Content-Range"] = obj["ContentRange"]
        if etag:
            resp.set_etag(etag)
        if disp:
            resp.headers["Content-Disposition"] = disp
        return resp

    def check(self):
        probe = f"tmp/.probe-{os.getpid()}"
        self.put_bytes(b"ok", probe)
        ok = self.read(probe) == b"ok"
        self.delete(probe)
        return {"ok": ok}


# --- backend selection ------------------------------------------------------------------------------------

_backends: dict[tuple, object] = {}
_backends_lock = threading.Lock()


def backend():
    cfg = current_app.config
    kind = (cfg.get("STORAGE_BACKEND") or "fs").lower()
    ident = (kind, cfg["STORAGE_PATH"], cfg.get("S3_BUCKET"), cfg.get("S3_ENDPOINT_URL"), cfg.get("S3_PREFIX"))
    b = _backends.get(ident)
    if b is None:
        with _backends_lock:
            b = _backends.get(ident)
            if b is None:
                if kind == "s3":
                    b = S3Backend(cfg)
                elif kind == "fs":
                    b = FSBackend(cfg["STORAGE_PATH"])
                else:
                    raise RuntimeError(f"unknown STORAGE_BACKEND {kind!r} (fs or s3)")
                _backends[ident] = b
    return b


def describe():
    return backend().describe()


def check():
    try:
        return {**backend().describe(), **backend().check()}
    except Exception as exc:
        return {**backend().describe(), "ok": False, "error": str(exc)[:500]}


def copy_from_directory(path, log=print):
    """Copy blobs and SBOMs of a file system storage directory into the configured backend (migration)."""
    target = backend()
    copied = skipped = 0
    for sub in ("blobs/sha256", "sboms"):
        base = os.path.join(path, *sub.split("/"))
        for dirpath, _, files in os.walk(base):
            for fn in files:
                src = os.path.join(dirpath, fn)
                key = os.path.relpath(src, path).replace(os.sep, "/")
                if key.endswith(".tmp"):
                    continue
                if target.exists(key):
                    skipped += 1
                    continue
                fd, tmp = tempfile.mkstemp(dir=tmp_dir())
                os.close(fd)
                shutil.copyfile(src, tmp)
                target.put_file(tmp, key)
                copied += 1
                if copied % 500 == 0:
                    log(f"  {copied} objects copied ...")
    return copied, skipped
