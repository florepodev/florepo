"""In-app API documentation rendered from the OpenAPI spec."""
from urllib.parse import urlparse

from flask import Blueprint, jsonify, render_template

from ..openapi import build_spec
from .common import base_url

bp = Blueprint("docs", __name__)

METHOD_ORDER = ["get", "post", "put", "patch", "delete"]


@bp.get("/api/openapi.json")
def openapi_json():
    return jsonify(build_spec(base_url()))


@bp.get("/docs/guides")
def guides():
    """Setup guides with copy-ready examples for every client and option, filled with this instance's values."""
    from .. import __version__
    from ..models import Repository

    url = urlparse(base_url())
    names = {}
    for r in Repository.query.order_by(Repository.name):
        names.setdefault((r.format, r.kind), r.name)

    def repo(fmt, kind, fallback):
        return names.get((fmt, kind), fallback)

    apk_key = "florepo-xxxxxxxx.rsa.pub"
    try:
        from .. import signing
        apk_key = signing.apk_key_name()
    except Exception:
        pass
    ctx = {
        "base": base_url(), "host": url.netloc, "scheme": url.scheme, "version": __version__, "apk_key": apk_key,
        "r": {
            "docker": repo("docker", "hosted", "docker"), "dockerhub": repo("docker", "proxy", "dockerhub"),
            "pypi": repo("pypi", "hosted", "pypi-local"), "pypi_proxy": repo("pypi", "proxy", "pypi-remote"),
            "npm": repo("npm", "hosted", "npm-local"), "npm_proxy": repo("npm", "proxy", "npm-remote"),
            "deb": repo("deb", "hosted", "debian-local"), "deb_proxy": repo("deb", "proxy", "debian-remote"),
            "rpm": repo("rpm", "hosted", "rpm-local"), "rpm_proxy": repo("rpm", "proxy", "rocky-remote"),
            "apk": repo("apk", "hosted", "alpine-local"), "apk_proxy": repo("apk", "proxy", "alpine-remote"),
            "maven": repo("maven", "hosted", "libs"), "maven_proxy": repo("maven", "proxy", "maven-central"),
            "go": repo("go", "hosted", "gomods"), "go_proxy": repo("go", "proxy", "golang"),
            "nuget": repo("nuget", "hosted", "nugets"), "nuget_proxy": repo("nuget", "proxy", "nuget-org"),
            "cargo": repo("cargo", "hosted", "crates"), "cargo_proxy": repo("cargo", "proxy", "crates-io"),
            "helm": repo("helm", "hosted", "charts"), "helm_proxy": repo("helm", "proxy", "helm-remote"),
            "generic": repo("generic", "hosted", "files"), "generic_proxy": repo("generic", "proxy", "downloads"),
        },
    }
    return render_template("guides.html", **ctx)


@bp.get("/docs")
def index():
    spec = build_spec(base_url())
    url = urlparse(base_url())
    fill = {"base": base_url(), "host": url.netloc, "scheme": url.scheme}
    groups = {t["name"]: [] for t in spec["tags"]}
    for path, ops in spec["paths"].items():
        for method in sorted(ops, key=METHOD_ORDER.index):
            op = ops[method]
            example = op.get("x-example")
            if example:
                for k, v in fill.items():
                    example = example.replace("{" + k + "}", v)
            groups[op["tags"][0]].append({"method": method, "path": path, "op": op, "example": example})
    return render_template("docs.html", spec=spec, groups=groups)
