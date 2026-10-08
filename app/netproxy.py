"""Outbound HTTP(S) proxy for all upstream traffic (proxy repositories, OSV.dev, Trivy DB downloads).

The global setting is editable under Administration → Network (defaults: HTTP_PROXY / HTTPS_PROXY / NO_PROXY
environment variables). Each proxy repository can use the global proxy, connect directly or use its own proxy.
"""
import os
import re

import requests
from requests.utils import should_bypass_proxies

from . import settings

MODES = ["global", "none", "custom"]
DEFAULT_NO_PROXY = "localhost,127.0.0.1,::1"

# One pooled session for all upstream requests. trust_env is off so that only the configured proxy applies.
_session = requests.Session()
_session.trust_env = False
_adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=64)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)


def _env(name):
    return os.environ.get(name) or os.environ.get(name.lower()) or ""


def global_config():
    cfg = settings.get("outbound_proxy")
    if cfg is None:
        cfg = {"http_proxy": _env("HTTP_PROXY"), "https_proxy": _env("HTTPS_PROXY"),
               "no_proxy": _env("NO_PROXY") or DEFAULT_NO_PROXY}
    return {"http_proxy": cfg.get("http_proxy") or "", "https_proxy": cfg.get("https_proxy") or "",
            "no_proxy": cfg.get("no_proxy") or ""}


def mask(url):
    """http://user:secret@proxy:3128 -> http://user:****@proxy:3128"""
    return re.sub(r"(://[^:/@]+:)[^@]*@", r"\1****@", url or "")


def validate_url(url):
    if url and not re.match(r"^(https?|socks5h?)://[^\s/]+", url):
        raise ValueError(f"Invalid proxy URL: {mask(url)} (expected http://host:port)")
    return url


def resolve(repo=None):
    """Return (proxies dict for requests, no_proxy string) for a repository (or global traffic)."""
    mode = getattr(repo, "proxy_mode", None) or "global"
    if mode == "none":
        return {}, ""
    if mode == "custom" and getattr(repo, "proxy_url", None):
        return {"http": repo.proxy_url, "https": repo.proxy_url}, ""
    cfg = global_config()
    proxies = {k: v for k, v in (("http", cfg["http_proxy"]), ("https", cfg["https_proxy"] or cfg["http_proxy"])) if v}
    return proxies, cfg["no_proxy"]


def request(method, url, repo=None, **kwargs):
    proxies, no_proxy = resolve(repo)
    if proxies and no_proxy and should_bypass_proxies(url, no_proxy=no_proxy):
        proxies = {}
    from . import __version__

    kwargs["headers"] = dict(kwargs.get("headers") or {})
    kwargs["headers"].setdefault("User-Agent", f"florepo/{__version__}")
    return _session.request(method, url, proxies=proxies, **kwargs)


def get(url, repo=None, **kwargs):
    return request("GET", url, repo=repo, **kwargs)


def subprocess_env(base=None):
    """Environment for external tools (Trivy) honouring the global proxy."""
    env = dict(base or os.environ)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        env.pop(key, None)
    cfg = global_config()
    if cfg["http_proxy"]:
        env["HTTP_PROXY"] = env["http_proxy"] = cfg["http_proxy"]
    if cfg["https_proxy"] or cfg["http_proxy"]:
        env["HTTPS_PROXY"] = env["https_proxy"] = cfg["https_proxy"] or cfg["http_proxy"]
    if cfg["no_proxy"]:
        env["NO_PROXY"] = env["no_proxy"] = cfg["no_proxy"]
    return env
