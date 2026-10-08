"""Signing keys of hosted OS package repositories.

* GPG key (RSA 3072) – signs Debian `InRelease` / `Release.gpg` and RPM `repomd.xml.asc`.
* RSA key – signs Alpine `APKINDEX.tar.gz` (abuild compatible, `.SIGN.RSA256.<keyname>`).

Keys are generated once (web container start, `init-db`) and stored under KEYS_PATH (default /data/keys).
"""
import fcntl
import hashlib
import os
import subprocess
from contextlib import contextmanager

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import current_app

GPG_UID = "Florepo repository signing key"


def keys_dir():
    path = current_app.config["KEYS_PATH"]
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


@contextmanager
def _locked():
    with open(os.path.join(keys_dir(), ".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


# --- GPG ---------------------------------------------------------------------------

def _gnupg_home():
    home = os.path.join(keys_dir(), "gnupg")
    os.makedirs(home, mode=0o700, exist_ok=True)
    return home


def _gpg(*args, data=None):
    cmd = ["gpg", "--homedir", _gnupg_home(), "--batch", "--yes", "--no-tty", "--pinentry-mode", "loopback",
           "--passphrase", "", *args]
    proc = subprocess.run(cmd, input=data, capture_output=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"gpg {' '.join(args[:2])} failed: {proc.stderr.decode(errors='replace')[-500:]}")
    return proc.stdout


def gpg_fingerprint():
    out = _gpg("--with-colons", "--list-secret-keys").decode()
    for line in out.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    return None


def ensure_gpg_key():
    with _locked():
        fpr = gpg_fingerprint()
        if fpr is None:
            _gpg("--quick-generate-key", GPG_UID, "rsa3072", "sign", "never")
            fpr = gpg_fingerprint()
            current_app.logger.info("generated repository signing key %s", fpr)
        return fpr


def gpg_public_key(armor=True):
    ensure_gpg_key()
    return _gpg(*(["--armor"] if armor else []), "--export", gpg_fingerprint())


def gpg_clearsign(data: bytes) -> bytes:
    return _gpg("--digest-algo", "SHA256", "--local-user", ensure_gpg_key(), "--clearsign", data=data)


def gpg_detach_sign(data: bytes) -> bytes:
    return _gpg("--digest-algo", "SHA256", "--local-user", ensure_gpg_key(), "--armor", "--detach-sign", data=data)


# --- Alpine (RSA) -------------------------------------------------------------------------

def _apk_paths():
    d = os.path.join(keys_dir(), "apk")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return os.path.join(d, "private.pem"), os.path.join(d, "public.pem")


def ensure_apk_key():
    priv_path, pub_path = _apk_paths()
    with _locked():
        if not os.path.exists(priv_path):
            key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            with open(priv_path, "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
            os.chmod(priv_path, 0o600)
            with open(pub_path, "wb") as f:
                f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
            current_app.logger.info("generated Alpine repository signing key %s", apk_key_name())
    return priv_path, pub_path


def apk_public_key():
    return open(ensure_apk_key()[1], "rb").read()


def apk_key_name():
    """File name clients install into /etc/apk/keys/ (must match the signature name)."""
    pub = open(_apk_paths()[1], "rb").read()
    return f"florepo-{hashlib.sha256(pub).hexdigest()[:8]}.rsa.pub"


def apk_sign(data: bytes):
    """Return (signature file name, signature) for an APKINDEX control stream."""
    priv_path, _ = ensure_apk_key()
    key = serialization.load_pem_private_key(open(priv_path, "rb").read(), password=None)
    sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return f".SIGN.RSA256.{apk_key_name()}", sig


def ensure_keys():
    ensure_gpg_key()
    ensure_apk_key()
