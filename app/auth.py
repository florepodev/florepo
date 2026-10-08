"""Authentication helpers shared by the UI and the package-manager APIs.

Clients authenticate with HTTP Basic (username + password or API token) or
`Authorization: Bearer <token>` (npm). The browser UI uses a session cookie.
"""
import base64
import hashlib
import hmac
import time

from flask import g, request
from flask_login import current_user

from .extensions import db
from .models import ApiToken, User, is_token, utcnow

# Password hashing is deliberately slow; docker push issues dozens of requests,
# so successful Basic credentials are cached briefly (keyed by a hash, never plaintext).
_BASIC_CACHE: dict[str, tuple[int, float]] = {}
_BASIC_TTL = 120


# Token -> user id, cached briefly so hot paths (docker layer pulls, npm installs) skip the token lookup.
# Revocations take effect within _TOKEN_TTL seconds on other worker processes (immediately on this one).
_TOKEN_CACHE: dict[str, tuple[int, float]] = {}
_TOKEN_TTL = 60


def forget_token(raw_or_hash):
    _TOKEN_CACHE.pop(raw_or_hash if len(raw_or_hash) == 64 else ApiToken.hash(raw_or_hash), None)


def _from_token(raw):
    key = ApiToken.hash(raw)
    hit = _TOKEN_CACHE.get(key)
    if hit and hit[1] > time.time():
        user = db.session.get(User, hit[0])
        if user and user.is_active:
            return user
    tok = ApiToken.query.filter_by(token_hash=key).first() if is_token(raw) else None
    if tok and tok.user.is_active:
        if not tok.last_used_at or (utcnow() - tok.last_used_at).total_seconds() > 300:
            tok.last_used_at = utcnow()
            db.session.commit()
        if len(_TOKEN_CACHE) > 5000:
            _TOKEN_CACHE.clear()
        _TOKEN_CACHE[key] = (tok.user_id, time.time() + _TOKEN_TTL)
        return tok.user
    return None


def _from_basic(username, password):
    if is_token(password):
        user = _from_token(password)
        if user and (not username or username == user.username or username == "token"):
            return user
        return None
    key = hashlib.sha256(f"{username}\x00{password}".encode()).hexdigest()
    hit = _BASIC_CACHE.get(key)
    if hit and hit[1] > time.time():
        user = db.session.get(User, hit[0])
        if user and user.is_active:
            return user
    user = authenticate_password(username, password)
    if user:
        if len(_BASIC_CACHE) > 1000:
            _BASIC_CACHE.clear()
        _BASIC_CACHE[key] = (user.id, time.time() + _BASIC_TTL)
        return user
    return None


def resolve_identity():
    """Return the authenticated User for this request or None."""
    if "identity" in g:
        return g.identity
    user = None
    if current_user and current_user.is_authenticated:
        user = current_user._get_current_object()
    else:
        header = request.headers.get("Authorization", "")
        scheme, _, value = header.partition(" ")
        scheme = scheme.lower()
        if scheme == "basic":
            try:
                decoded = base64.b64decode(value).decode("utf-8")
                username, _, password = decoded.partition(":")
                user = _from_basic(username, password)
            except (ValueError, UnicodeDecodeError):
                user = None
        elif scheme == "bearer":
            user = _from_token(value.strip())
        elif is_token(header.strip()):  # cargo sends the bare token as Authorization header
            user = _from_token(header.strip())
        elif is_token(request.headers.get("X-NuGet-ApiKey", "")):  # dotnet nuget push -k <token>
            user = _from_token(request.headers["X-NuGet-ApiKey"])
    g.identity = user
    return user


def authenticate_password(username, password):
    """Local accounts are checked against their password hash; LDAP accounts and unknown names against the
    directory (if LDAP is enabled – see ldap_auth)."""
    user = User.query.filter_by(username=username).first()
    if user is None or user.auth_source == "ldap":
        from . import ldap_auth

        if ldap_auth.enabled():
            return ldap_auth.authenticate(username, password)
        return None
    if user.is_active and user.check_password(password):
        user.last_login_at = utcnow()
        db.session.commit()
        return user
    # constant-ish time on unknown users
    hmac.compare_digest("a", "b")
    return None


def can_read(repo, user):
    """May see the repository and its metadata (UI, API, SBOMs)."""
    return bool(repo.public or user)


def can_download(repo, user):
    """May fetch packages through the client protocols (docker, pip, npm, apt, dnf, apk). Auditors may not."""
    return can_read(repo, user) and not (user and user.is_auditor)


def can_write(repo, user):
    return bool(user and user.can_deploy_to(repo))
