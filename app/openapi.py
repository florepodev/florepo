"""OpenAPI 3.1 description of the management REST API and the package-manager endpoints.

Served at /api/openapi.json and rendered as the in-app documentation at /docs.
"""
from . import __version__

JSON = "application/json"


def _p(name, where="query", desc="", required=False, schema=None):
    return {"name": name, "in": where, "description": desc, "required": required or where == "path",
            "schema": schema or {"type": "string"}}


def _op(summary, desc="", params=None, body=None, responses=None, auth="user", tag=None, example=None):
    op = {"summary": summary, "description": desc, "parameters": params or [],
          "responses": responses or {"200": {"description": "OK"}},
          "x-auth": auth}  # none | optional | user | deployer | admin
    if body:
        op["requestBody"] = {"required": True, "content": {JSON: {"schema": body}}}
    if tag:
        op["tags"] = [tag]
    if example:
        op["x-example"] = example
    return op


PAGE = [_p("page", schema={"type": "integer", "default": 1}),
        _p("per_page", schema={"type": "integer", "default": 50, "maximum": 500})]
REPORT_FILTERS = [_p("days", desc="Period in days, 0 = all time", schema={"type": "integer", "default": 30}),
                  _p("repo", desc="Repository name"), _p("fmt", desc="repository format, e.g. docker, maven, nuget"),
                  _p("user", desc="Username"), _p("q", desc="Package name contains")]

REPO_SETTINGS = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "public": {"type": "boolean", "description": "Anonymous read access"},
        "allow_redeploy": {"type": "boolean", "description": "Allow overwriting versions/tags"},
        "block_severity": {"type": ["string", "null"], "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", None],
                           "description": "Block downloads with findings of this severity or above"},
        "upstream_url": {"type": "string", "description": "Proxy repositories only"},
        "upstream_username": {"type": "string"},
        "upstream_password": {"type": "string", "writeOnly": True},
        "proxy_mode": {"enum": ["global", "none", "custom"], "description": "Proxy repositories: outbound connection"},
        "proxy_url": {"type": "string", "description": "proxy_mode=custom: http://user:pass@host:port"},
        "distro": {"type": "string", "description": "deb/rpm/apk: distribution for scanning, e.g. debian:12, alpine:3.20, rocky:9"},
        "cache_retention_days": {"type": "integer", "description": "Proxy: delete cached artifacts not requested for N days (0 = forever)"},
        "quota": {"type": ["string", "null"], "description": "Hosted: max. stored size (uploads beyond it get HTTP 413), proxy: cache size limit (LRU eviction). Examples: 500M, 20G, 1T; empty = unlimited"},
        "quota_bytes": {"type": ["integer", "null"], "description": "Same as quota, in bytes"},
    },
}
REPO_CREATE = {
    "type": "object", "required": ["name", "format"],
    "properties": {"name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"},
                   "format": {"enum": ["docker", "pypi", "npm", "maven", "go", "nuget", "cargo", "helm", "generic", "deb", "rpm", "apk"]},
                   "kind": {"enum": ["hosted", "proxy"], "default": "hosted"},
                   **REPO_SETTINGS["properties"]},
}
USER_UPDATE = {
    "type": "object",
    "properties": {"role": {"enum": ["reader", "deployer", "auditor", "admin"], "description": "not for LDAP users (group mapping)"}, "active": {"type": "boolean"},
                   "quota": {"type": ["string", "null"], "description": "Upload quota, e.g. 10G; null = global default"},
                   "quota_bytes": {"type": ["integer", "null"], "description": "Upload quota in bytes, 0 = unlimited, null = global default"},
                   "password": {"type": "string", "minLength": 8, "writeOnly": True},
                   "restrict_deploy": {"type": "boolean",
                                       "description": "Deployers: only publish to deploy_repos"},
                   "deploy_repos": {"type": "array", "items": {"type": "string"},
                                    "description": "Hosted repository names (or ids)"}},
}
ALERT_RULE = {
    "type": "object",
    "properties": {"enabled": {"type": "boolean"},
                   "recipients": {"type": "array", "items": {"type": "string"}},
                   "threshold": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"], "description": "Alert from this severity"},
                   "only_new": {"type": "boolean", "description": "Only findings not present in the previous scan"},
                   "include_uploads": {"type": "boolean", "description": "Also alert on first scans of new versions"},
                   "repos": {"type": "array", "items": {"type": "string"}, "description": "Empty = all repositories"}},
}
NETWORK = {
    "type": "object",
    "properties": {"http_proxy": {"type": "string", "description": "e.g. http://proxy:3128 (empty = direct)"},
                   "https_proxy": {"type": "string", "description": "empty = same as http_proxy"},
                   "no_proxy": {"type": "string", "description": "comma-separated hosts / domains / CIDRs"}},
}
USER_CREATE = {"type": "object", "required": ["username", "password"],
               "properties": {"username": {"type": "string"}, **USER_UPDATE["properties"]}}


def build_spec(base_url):
    T_REPO, T_PKG, T_VULN, T_REP, T_USR, T_SCAN = (
        "Repositories", "Packages & versions", "Vulnerabilities", "Reports", "Users & tokens", "Scanner")
    T_DOCKER, T_PYPI, T_NPM = "Docker registry", "PyPI", "npm"
    T_DEB, T_RPM, T_APK = "Debian (apt)", "RPM (dnf/yum)", "Alpine (apk)"
    T_NOTIFY = "Notifications"
    T_NET = "Network"
    T_STORE, T_CLAM, T_LDAP = "Storage & quotas", "Malware scanning (ClamAV)", "LDAP / Active Directory"
    T_MAVEN, T_GO, T_NUGET, T_CARGO, T_HELM, T_GENERIC = "Maven", "Go modules", "NuGet", "Cargo", "Helm", "Generic files"
    paths = {
        "/api/v1/whoami": {"get": _op("Current user", tag=T_USR, example="curl -H 'Authorization: Bearer $TOKEN' {base}/api/v1/whoami")},

        "/api/v1/repositories": {
            "get": _op("List repositories", "Anonymous callers only see public repositories.",
                       [_p("format"), _p("kind"), _p("sort", desc="name | format | created"), _p("dir", desc="asc | desc")],
                       auth="optional", tag=T_REPO, example="curl -H 'Authorization: Bearer $TOKEN' {base}/api/v1/repositories"),
            "post": _op("Create repository", body=REPO_CREATE, auth="admin", tag=T_REPO,
                        responses={"201": {"description": "Created"}, "400": {"description": "Validation error"}},
                        example="curl -X POST -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' \\\n"
                                "  -d '{\"name\": \"dockerhub\", \"format\": \"docker\", \"kind\": \"proxy\", "
                                "\"upstream_url\": \"https://registry-1.docker.io\"}' {base}/api/v1/repositories"),
        },
        "/api/v1/repositories/{name}": {
            "get": _op("Get repository", params=[_p("name", "path")], auth="optional", tag=T_REPO),
            "patch": _op("Update repository settings", params=[_p("name", "path")], body=REPO_SETTINGS, auth="admin", tag=T_REPO,
                         example="curl -X PATCH -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' \\\n"
                                 "  -d '{\"block_severity\": \"CRITICAL\"}' {base}/api/v1/repositories/pypi-remote"),
            "delete": _op("Delete repository", "Packages, versions and scan results are removed; download history is kept.",
                          [_p("name", "path")], auth="admin", tag=T_REPO, responses={"204": {"description": "Deleted"}}),
        },
        "/api/v1/repositories/{name}/packages": {
            "get": _op("List packages / images", params=[_p("name", "path"), _p("q", desc="Name contains"),
                                                         _p("sort", desc="name | created | updated"), _p("dir")] + PAGE,
                       auth="optional", tag=T_PKG),
        },
        "/api/v1/repositories/{name}/scan": {
            "post": _op("Re-scan all versions of a repository", params=[_p("name", "path")], auth="admin", tag=T_SCAN,
                        responses={"202": {"description": "Queued"}}),
        },
        "/api/v1/packages/{id}": {
            "get": _op("Get package with all versions", params=[_p("id", "path", schema={"type": "integer"})],
                       auth="optional", tag=T_PKG),
        },
        "/api/v1/versions/{id}": {
            "get": _op("Get version (files, metadata, scan summary)", params=[_p("id", "path", schema={"type": "integer"})],
                       auth="optional", tag=T_PKG),
            "delete": _op("Delete version", params=[_p("id", "path", schema={"type": "integer"})], auth="deployer",
                          tag=T_PKG, responses={"204": {"description": "Deleted"}}),
        },
        "/api/v1/versions/{id}/vulnerabilities": {
            "get": _op("Findings of a version", params=[_p("id", "path", schema={"type": "integer"}),
                                                        _p("severity", desc="Filter, e.g. CRITICAL")],
                       auth="optional", tag=T_VULN,
                       example="curl -H 'Authorization: Bearer $TOKEN' '{base}/api/v1/versions/42/vulnerabilities?severity=HIGH'"),
        },
        "/api/v1/versions/{id}/sbom": {
            "get": _op("Download CycloneDX SBOM", params=[_p("id", "path", schema={"type": "integer"})], auth="optional",
                       tag=T_VULN, responses={"200": {"description": "CycloneDX JSON",
                                                      "content": {"application/vnd.cyclonedx+json": {}}}},
                       example="curl -H 'Authorization: Bearer $TOKEN' -o sbom.cdx.json {base}/api/v1/versions/42/sbom"),
        },
        "/api/v1/versions/{id}/scan": {
            "post": _op("Queue a re-scan", params=[_p("id", "path", schema={"type": "integer"})], auth="deployer",
                        tag=T_SCAN, responses={"202": {"description": "Queued"}}),
        },
        "/api/v1/vulnerabilities": {
            "get": _op("All findings grouped by vulnerability ID", params=[_p("severity"), _p("q", desc="ID or component contains")],
                       tag=T_VULN),
        },
        "/api/v1/vulnerabilities/{vuln_id}": {
            "get": _op("Artifacts affected by a vulnerability", params=[_p("vuln_id", "path", desc="e.g. CVE-2024-3651")],
                       tag=T_VULN, example="curl -H 'Authorization: Bearer $TOKEN' {base}/api/v1/vulnerabilities/CVE-2023-43804"),
        },
        "/api/v1/reports/downloads": {
            "get": _op("Download log (who pulled what)", params=REPORT_FILTERS + [_p("sort", desc="time | user | package | repo"), _p("dir")] + PAGE,
                       auth="admin", tag=T_REP,
                       example="curl -H 'Authorization: Bearer $TOKEN' '{base}/api/v1/reports/downloads?days=7&user=alice'"),
        },
        "/api/v1/reports/usage": {
            "get": _op("Package inventory: versions in use with consumers and scan status", params=REPORT_FILTERS,
                       auth="admin", tag=T_REP),
        },
        "/api/v1/users": {
            "get": _op("List users", auth="admin", tag=T_USR),
            "post": _op("Create user", body=USER_CREATE, auth="admin", tag=T_USR,
                        responses={"201": {"description": "Created"}},
                        example="curl -X POST -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' \\\n"
                                "  -d '{\"username\": \"ci-team-a\", \"password\": \"…\", \"role\": \"deployer\", "
                                "\"restrict_deploy\": true, \"deploy_repos\": [\"npm-local\"]}' {base}/api/v1/users"),
        },
        "/api/v1/users/{id}": {
            "patch": _op("Update user (role, status, password, write scope)", params=[_p("id", "path", schema={"type": "integer"})],
                         body=USER_UPDATE, auth="admin", tag=T_USR),
        },
        "/api/v1/tokens": {
            "get": _op("List own API tokens", tag=T_USR),
            "post": _op("Create API token", "The token value is only returned once.",
                        body={"type": "object", "properties": {"name": {"type": "string"}}}, tag=T_USR,
                        responses={"201": {"description": "Created – contains `token`"}}),
        },
        "/api/v1/tokens/{id}": {
            "delete": _op("Revoke token", params=[_p("id", "path", schema={"type": "integer"})], tag=T_USR,
                          responses={"204": {"description": "Revoked"}}),
        },
        "/api/v1/scanner": {
            "get": _op("Scanner status: Trivy version, signature DB state, schedule, queue", auth="admin", tag=T_SCAN,
                       example="curl -H 'Authorization: Bearer $TOKEN' {base}/api/v1/scanner"),
        },
        "/api/v1/scanner/settings": {
            "put": _op("Change scanner schedule", body={"type": "object", "properties": {
                "trivy_db_interval_hours": {"type": "integer", "description": "0 = manual only"},
                "trivy_java_db": {"type": "boolean"},
                "rescan_interval_hours": {"type": "integer", "description": "0 = off"},
                "rescan_after_db_update": {"type": "boolean"}}}, auth="admin", tag=T_SCAN,
                example="curl -X PUT -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' \\\n"
                        "  -d '{\"trivy_db_interval_hours\": 6}' {base}/api/v1/scanner/settings"),
        },
        "/api/v1/scanner/db-update": {
            "post": _op("Trigger a signature DB update now", auth="admin", tag=T_SCAN,
                        responses={"202": {"description": "Requested – executed by the worker"}}),
        },
        "/api/v1/notifications": {
            "get": _op("Alert rule, SMTP status and alert history", auth="admin", tag=T_NOTIFY),
            "put": _op("Change alert rule", "Alerts are sent when (periodic) re-scans find new vulnerabilities at or above the threshold.",
                       body=ALERT_RULE, auth="admin", tag=T_NOTIFY,
                       example="curl -X PUT -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' \\\n"
                               "  -d '{\"enabled\": true, \"recipients\": [\"security@example.com\"], \"threshold\": \"CRITICAL\"}' {base}/api/v1/notifications"),
        },
        "/api/v1/notifications/test": {
            "post": _op("Send a test e-mail", body={"type": "object", "properties": {"to": {"type": "array", "items": {"type": "string"},
                        "description": "Defaults to the configured recipients"}}}, auth="admin", tag=T_NOTIFY),
        },
        "/api/v1/network": {
            "get": _op("Outbound HTTP/HTTPS proxy settings (passwords masked)", auth="admin", tag=T_NET),
            "put": _op("Change the global outbound proxy", body=NETWORK, auth="admin", tag=T_NET,
                       example="curl -X PUT -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' \\\n"
                               "  -d '{\"http_proxy\": \"http://proxy.corp:3128\", \"https_proxy\": \"http://proxy.corp:3128\", "
                               "\"no_proxy\": \"localhost,.corp\"}' {base}/api/v1/network"),
        },
        "/api/v1/network/test": {
            "post": _op("Test an upstream URL with the effective proxy settings",
                        body={"type": "object", "properties": {"url": {"type": "string"},
                              "repository": {"type": "string", "description": "use this repository's proxy settings"}}},
                        auth="admin", tag=T_NET),
        },

        # --- package manager protocols ---------------------------------------------------
        "/v2/": {"get": _op("Registry API version check / login", "Returns 401 with a Basic challenge when unauthenticated.",
                            tag=T_DOCKER, auth="user", example="docker login {host}")},
        "/v2/_catalog": {"get": _op("List images", params=[_p("n", schema={"type": "integer"}), _p("last")], tag=T_DOCKER)},
        "/v2/{repo}/{image}/tags/list": {"get": _op("List tags", params=[_p("repo", "path"), _p("image", "path", desc="may contain /")],
                                                    tag=T_DOCKER, auth="optional")},
        "/v2/{repo}/{image}/manifests/{reference}": {
            "get": _op("Pull manifest (tag or digest)", "Proxy repositories resolve tags against the upstream and cache the result. "
                       "Blocked versions return 403 DENIED.", [_p("repo", "path"), _p("image", "path"), _p("reference", "path")],
                       tag=T_DOCKER, auth="optional", example="docker pull {host}/dockerhub/nginx:alpine"),
            "put": _op("Push manifest", params=[_p("repo", "path"), _p("image", "path"), _p("reference", "path")],
                       tag=T_DOCKER, auth="deployer", example="docker push {host}/docker/team/app:1.0"),
            "delete": _op("Delete manifest or tag", params=[_p("repo", "path"), _p("image", "path"), _p("reference", "path")],
                          tag=T_DOCKER, auth="deployer"),
        },
        "/v2/{repo}/{image}/blobs/{digest}": {
            "get": _op("Download blob (layer/config)", params=[_p("repo", "path"), _p("image", "path"), _p("digest", "path")],
                       tag=T_DOCKER, auth="optional"),
        },
        "/v2/{repo}/{image}/blobs/uploads/": {
            "post": _op("Start blob upload (also monolithic ?digest= and cross-repo ?mount=&from=)",
                        params=[_p("repo", "path"), _p("image", "path")], tag=T_DOCKER, auth="deployer"),
        },
        "/v2/{repo}/{image}/blobs/uploads/{uuid}": {
            "patch": _op("Upload chunk", params=[_p("repo", "path"), _p("image", "path"), _p("uuid", "path")], tag=T_DOCKER, auth="deployer"),
            "put": _op("Complete upload (?digest=)", params=[_p("repo", "path"), _p("image", "path"), _p("uuid", "path"), _p("digest", required=True)],
                       tag=T_DOCKER, auth="deployer"),
        },
        "/pypi/{repo}/simple/": {"get": _op("Project index (PEP 503 HTML / PEP 691 JSON)", params=[_p("repo", "path")],
                                            tag=T_PYPI, auth="optional",
                                            example="pip install --index-url {scheme}://USER:TOKEN@{host}/pypi/pypi-remote/simple/ requests")},
        "/pypi/{repo}/simple/{project}/": {"get": _op("Project files with sha256, requires-python and PEP 658 metadata",
                                                      params=[_p("repo", "path"), _p("project", "path")], tag=T_PYPI, auth="optional")},
        "/pypi/{repo}/files/{project}/{filename}": {"get": _op("Download distribution (proxy: fetched and cached on first request)",
                                                               params=[_p("repo", "path"), _p("project", "path"), _p("filename", "path")],
                                                               tag=T_PYPI, auth="optional")},
        "/pypi/{repo}/": {"post": _op("Upload (twine / legacy upload API, multipart)", params=[_p("repo", "path")], tag=T_PYPI,
                                      auth="deployer", example="twine upload --repository-url {base}/pypi/pypi-local/ -u USER -p TOKEN dist/*")},
        "/npm/{repo}/{package}": {
            "get": _op("Packument (all versions)", params=[_p("repo", "path"), _p("package", "path", desc="@scope%2fname for scoped packages")],
                       tag=T_NPM, auth="optional", example="npm install lodash --registry={base}/npm/npm-remote/"),
            "put": _op("Publish / deprecate / dist-tags", params=[_p("repo", "path"), _p("package", "path")], tag=T_NPM,
                       auth="deployer", example="npm publish --registry={base}/npm/npm-local/"),
        },
        "/npm/{repo}/{package}/-/{tarball}": {"get": _op("Download tarball", params=[_p("repo", "path"), _p("package", "path"), _p("tarball", "path")],
                                                         tag=T_NPM, auth="optional")},
        "/npm/{repo}/-/user/org.couchdb.user:{name}": {"put": _op("npm login (returns a token)", params=[_p("repo", "path"), _p("name", "path")],
                                                                  tag=T_NPM, auth="none",
                                                                  example="npm login --registry={base}/npm/npm-local/ --auth-type=legacy")},
        "/npm/{repo}/-/whoami": {"get": _op("npm whoami", params=[_p("repo", "path")], tag=T_NPM)},
        "/npm/{repo}/-/v1/search": {"get": _op("npm search", params=[_p("repo", "path"), _p("text"), _p("size", schema={"type": "integer"})],
                                               tag=T_NPM, auth="optional")},
        "/npm/{repo}/-/package/{package}/dist-tags": {"get": _op("List dist-tags", params=[_p("repo", "path"), _p("package", "path")],
                                                                 tag=T_NPM, auth="optional")},

        # --- OS package repositories ------------------------------------------------------
        "/deb/{repo}/{path}": {
            "get": _op("apt: indexes (dists/…) and packages (pool/…)",
                       "Proxy: mirrors the upstream layout (e.g. http://deb.debian.org/debian), upstream signatures are kept. "
                       "Hosted: signed InRelease/Release.gpg and Packages(.gz) are generated from the uploads. "
                       "Public key: key.gpg (binary) / key.asc.",
                       [_p("repo", "path"), _p("path", "path", desc="e.g. dists/bookworm/InRelease")], tag=T_DEB,
                       auth="optional", example="echo 'deb [signed-by=/etc/apt/keyrings/florepo.gpg] {base}/deb/debian-local stable main' \\\n"
                                                "  > /etc/apt/sources.list.d/florepo.list"),
        },
        "/deb/{repo}/upload": {
            "put": _op("Upload a .deb (hosted)", "Raw body or multipart field `file`. Query: distribution (default stable), "
                       "component (default main).", [_p("repo", "path"), _p("distribution"), _p("component")],
                       tag=T_DEB, auth="deployer",
                       example="curl -u USER:TOKEN --upload-file hello_1.0_amd64.deb '{base}/deb/debian-local/upload/?distribution=stable'"),
        },
        "/rpm/{repo}/{path}": {
            "get": _op("dnf/yum: repodata/* and packages",
                       "Proxy: mirrors the upstream (e.g. https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/). Hosted: "
                       "repodata generated with createrepo_c, repomd.xml signed (repomd.xml.asc). Public key: key.asc.",
                       [_p("repo", "path"), _p("path", "path")], tag=T_RPM, auth="optional",
                       example="cat > /etc/yum.repos.d/florepo.repo <<'EOF'\n[florepo]\nname=Florepo\n"
                               "baseurl={base}/rpm/rpm-local/\nrepo_gpgcheck=1\ngpgcheck=0\n"
                               "gpgkey={base}/rpm/rpm-local/key.asc\nEOF"),
        },
        "/rpm/{repo}/upload": {
            "put": _op("Upload an .rpm (hosted)", params=[_p("repo", "path")], tag=T_RPM, auth="deployer",
                       example="curl -u USER:TOKEN --upload-file hello-1.0-1.x86_64.rpm {base}/rpm/rpm-local/upload/"),
        },
        "/apk/{repo}/{path}": {
            "get": _op("apk: APKINDEX.tar.gz and packages",
                       "Proxy: mirrors e.g. https://dl-cdn.alpinelinux.org/alpine (v3.20/main/x86_64/…). Hosted: signed "
                       "APKINDEX (RSA256). Public key: key.rsa.pub (install as /etc/apk/keys/<name> from keys/).",
                       [_p("repo", "path"), _p("path", "path")], tag=T_APK, auth="optional",
                       example="echo '{base}/apk/alpine-remote/v3.20/main' >> /etc/apk/repositories"),
        },
        "/apk/{repo}/upload": {
            "put": _op("Upload an .apk (hosted)", "Query: branch (default latest), repository (default main).",
                       [_p("repo", "path"), _p("branch"), _p("repository")], tag=T_APK, auth="deployer",
                       example="curl -u USER:TOKEN --upload-file hello-1.0-r0.apk '{base}/apk/alpine-local/upload/?branch=v3.20'"),
        },
        # --- Maven / Go / NuGet / Cargo / Helm / generic ------------------------------------------
        "/maven/{repo}/{path}": {
            "get": _op("Maven: artifacts, checksums, maven-metadata.xml",
                       "Maven 2 layout. .md5/.sha1/.sha256/.sha512 for every file; artifact-level maven-metadata.xml is "
                       "generated for hosted repositories. Proxy: e.g. https://repo1.maven.org/maven2.",
                       [_p("repo", "path"), _p("path", "path", desc="e.g. org/example/lib/1.0/lib-1.0.jar")], tag=T_MAVEN,
                       auth="optional", example="curl -u USER:TOKEN -O {base}/maven/maven-central/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar"),
            "put": _op("Maven: deploy a file (mvn deploy, gradle publish)", "Releases are immutable unless allow_redeploy; "
                       "SNAPSHOTs can be re-deployed. Uploaded checksum files are ignored.", [_p("repo", "path"), _p("path", "path")],
                       tag=T_MAVEN, auth="deployer"),
        },
        "/go/{repo}/{module}/@v/{file}": {
            "get": _op("GOPROXY: list, <version>.info, .mod, .zip", "Module paths use the GOPROXY case encoding (!x = X).",
                       [_p("repo", "path"), _p("module", "path"), _p("file", "path", desc="list | v1.2.3.info | v1.2.3.mod | v1.2.3.zip")],
                       tag=T_GO, auth="optional", example="go env -w GOPROXY={scheme}://USER:TOKEN@{host}/go/golang"),
            "put": _op("Upload a module version (<version>.zip, hosted)", "The zip may contain the files at the root, below one "
                       "directory or below module@version/; go.mod must declare the module.",
                       [_p("repo", "path"), _p("module", "path"), _p("file", "path", desc="v1.2.3.zip")], tag=T_GO, auth="deployer",
                       example="curl -u USER:TOKEN --upload-file v1.2.3.zip {base}/go/gomods/git.example.com/team/mod/@v/v1.2.3.zip"),
        },
        "/go/{repo}/{module}/@latest": {"get": _op("GOPROXY: latest version", params=[_p("repo", "path"), _p("module", "path")],
                                                    tag=T_GO, auth="optional")},
        "/go/{repo}/sumdb/{sumdb}/{path}": {"get": _op("Checksum database relay (proxy repositories)", "sum.golang.org and "
                                                       "sum.golang.google.cn only.", [_p("repo", "path"), _p("sumdb", "path"), _p("path", "path")],
                                                       tag=T_GO, auth="optional")},
        "/nuget/{repo}/index.json": {"get": _op("NuGet v3 service index", params=[_p("repo", "path")], tag=T_NUGET, auth="optional",
                                                example="dotnet nuget add source {base}/nuget/nuget-org/index.json -n florepo -u USER -p TOKEN --store-password-in-clear-text")},
        "/nuget/{repo}/v3-flatcontainer/{id}/index.json": {"get": _op("Versions of a package (PackageBaseAddress)",
                                                                      params=[_p("repo", "path"), _p("id", "path")], tag=T_NUGET, auth="optional")},
        "/nuget/{repo}/v3-flatcontainer/{id}/{version}/{file}": {"get": _op(".nupkg / .nuspec", params=[_p("repo", "path"), _p("id", "path"), _p("version", "path"), _p("file", "path")],
                                                                            tag=T_NUGET, auth="optional")},
        "/nuget/{repo}/registration/{id}/index.json": {"get": _op("Package metadata (RegistrationsBaseUrl)",
                                                                  params=[_p("repo", "path"), _p("id", "path")], tag=T_NUGET, auth="optional")},
        "/nuget/{repo}/query": {"get": _op("Search", params=[_p("repo", "path"), _p("q"), _p("skip"), _p("take"), _p("prerelease")],
                                           tag=T_NUGET, auth="optional")},
        "/nuget/{repo}/api/v2/package": {"put": _op("Push a .nupkg (dotnet nuget push -k TOKEN)", "Multipart field `package`; "
                                                    "API key = API token (X-NuGet-ApiKey).", [_p("repo", "path")], tag=T_NUGET, auth="deployer",
                                                    example="dotnet nuget push MyLib.1.0.0.nupkg -s {base}/nuget/nugets/index.json -k TOKEN")},
        "/nuget/{repo}/api/v2/package/{id}/{version}": {"delete": _op("Delete a package version", params=[_p("repo", "path"), _p("id", "path"), _p("version", "path")],
                                                                      tag=T_NUGET, auth="deployer", responses={"204": {"description": "Deleted"}})},
        "/cargo/{repo}/index/config.json": {"get": _op("Sparse registry config", params=[_p("repo", "path")], tag=T_CARGO, auth="optional",
                                                       example='[registries.florepo]\nindex = "sparse+{base}/cargo/crates/index/"')},
        "/cargo/{repo}/index/{path}": {"get": _op("Sparse index file of a crate", params=[_p("repo", "path"), _p("path", "path", desc="e.g. se/rd/serde")],
                                                  tag=T_CARGO, auth="optional")},
        "/cargo/{repo}/api/v1/crates/{name}/{version}/download": {"get": _op("Download a .crate", params=[_p("repo", "path"), _p("name", "path"), _p("version", "path")],
                                                                             tag=T_CARGO, auth="optional")},
        "/cargo/{repo}/api/v1/crates/new": {"put": _op("cargo publish", "Body: u32 length + JSON metadata + u32 length + .crate. "
                                                       "Authorization: <token>.", [_p("repo", "path")], tag=T_CARGO, auth="deployer")},
        "/cargo/{repo}/api/v1/crates/{name}/{version}/yank": {"delete": _op("cargo yank", params=[_p("repo", "path"), _p("name", "path"), _p("version", "path")],
                                                                             tag=T_CARGO, auth="deployer")},
        "/cargo/{repo}/api/v1/crates/{name}/{version}/unyank": {"put": _op("cargo yank --undo", params=[_p("repo", "path"), _p("name", "path"), _p("version", "path")],
                                                                            tag=T_CARGO, auth="deployer")},
        "/cargo/{repo}/api/v1/crates": {"get": _op("cargo search", params=[_p("repo", "path"), _p("q"), _p("per_page")], tag=T_CARGO, auth="optional")},
        "/helm/{repo}/index.yaml": {"get": _op("Chart repository index", "Proxy: upstream index with chart URLs rewritten to this repository.",
                                               [_p("repo", "path")], tag=T_HELM, auth="optional",
                                               example="helm repo add florepo {base}/helm/charts --username USER --password TOKEN")},
        "/helm/{repo}/charts/{file}": {"get": _op("Download a chart archive", params=[_p("repo", "path"), _p("file", "path")], tag=T_HELM, auth="optional")},
        "/helm/{repo}/api/charts": {
            "post": _op("Upload a chart (ChartMuseum API, helm cm-push)", "Raw body or multipart field `chart`; ?force overwrites.",
                        [_p("repo", "path")], tag=T_HELM, auth="deployer",
                        example="curl -u USER:TOKEN --data-binary @mychart-0.1.0.tgz {base}/helm/charts/api/charts"),
            "get": _op("List charts (ChartMuseum API)", params=[_p("repo", "path")], tag=T_HELM, auth="optional"),
        },
        "/helm/{repo}/api/charts/{name}/{version}": {"delete": _op("Delete a chart version", params=[_p("repo", "path"), _p("name", "path"), _p("version", "path")],
                                                                   tag=T_HELM, auth="deployer")},
        "/generic/{repo}/{path}": {
            "get": _op("Download a file (or a JSON listing for paths ending with /)", ".sha256/.sha1/.md5/.sha512 suffixes return checksums. "
                       "Proxy: fetched from <upstream>/<path> and cached.", [_p("repo", "path"), _p("path", "path")], tag=T_GENERIC,
                       auth="optional", example="curl -fu USER:TOKEN -O {base}/generic/files/tools/mytool/1.4.0/mytool.tar.gz"),
            "put": _op("Upload a file (<package path>/<version>/<file>)", "Optional header X-Checksum-Sha256 is verified.",
                       [_p("repo", "path"), _p("path", "path")], tag=T_GENERIC, auth="deployer",
                       example="curl -u USER:TOKEN -T mytool.tar.gz {base}/generic/files/tools/mytool/1.4.0/mytool.tar.gz"),
            "delete": _op("Delete a file", params=[_p("repo", "path"), _p("path", "path")], tag=T_GENERIC, auth="deployer",
                          responses={"204": {"description": "Deleted"}}),
        },

        # --- storage, quotas, ClamAV, LDAP ------------------------------------------------------------
        "/api/v1/storage": {"get": _op("Storage backend, usage per repository, quotas, metadata cache statistics",
                                       "?check=1 (admins) runs a write/read/delete test against the backend.",
                                       [_p("check")], auth="admin", tag=T_STORE,
                                       example="curl -H 'Authorization: Bearer $TOKEN' '{base}/api/v1/storage?check=1'")},
        "/api/v1/storage/quotas": {"put": _op("Set the default upload quota for users", body={"type": "object", "properties": {
            "default_user_quota": {"type": ["string", "null"], "description": "e.g. 10G, empty = unlimited"},
            "default_user_quota_bytes": {"type": ["integer", "null"]}}}, auth="admin", tag=T_STORE,
            example="curl -X PUT -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"default_user_quota\": \"10G\"}' {base}/api/v1/storage/quotas")},
        "/api/v1/clamav": {
            "get": _op("ClamAV settings, engine / signature version and verdict counters", auth="admin", tag=T_CLAM),
            "put": _op("Change ClamAV settings", body={"type": "object", "properties": {
                "enabled": {"type": "boolean"}, "host": {"type": "string"}, "port": {"type": "integer"},
                "block_infected": {"type": "boolean"}, "block_unscanned": {"type": "boolean", "description": "hosted: serve only after a clean scan"},
                "max_file_mb": {"type": "integer", "description": "skip larger files (0 = no limit)"}}}, auth="admin", tag=T_CLAM,
                example="curl -X PUT -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"enabled\": true, \"host\": \"clamav\"}' {base}/api/v1/clamav"),
        },
        "/api/v1/ldap": {
            "get": _op("LDAP / AD configuration (bind password masked), last sync", auth="admin", tag=T_LDAP),
            "put": _op("Change the LDAP configuration", "Fields: enabled, server_urls, start_tls, verify_tls, ca_cert, bind_dn, "
                       "bind_password, user_base, user_filter ({username}), username_attr, email_attr, name_attr, group_mode "
                       "(memberof | ad_nested | search), group_base, group_filter ({user_dn}, {username}), mappings "
                       "[{group, role, repos}], default_role, sync_minutes, timeout.", auth="admin", tag=T_LDAP),
        },
        "/api/v1/ldap/test": {"post": _op("Test connection, user lookup, password and resulting role", body={"type": "object", "properties": {
            "username": {"type": "string"}, "password": {"type": "string", "writeOnly": True},
            "config": {"type": "object", "description": "unsaved settings to test (merged with the stored ones)"}}}, auth="admin", tag=T_LDAP)},
        "/api/v1/ldap/sync": {"post": _op("Re-check all LDAP users now", auth="admin", tag=T_LDAP)},

        "/api/v1/repositories/{name}/cache": {
            "get": _op("Proxy cache usage (versions, bytes, retention)", params=[_p("name", "path")], auth="admin", tag=T_REPO),
        },
        "/api/v1/repositories/{name}/cache/purge": {
            "post": _op("Purge the proxy cache", "Removes cached artifacts not accessed for `older_than_days` "
                        "(omit to remove everything); blobs are deleted by the next garbage collection.",
                        params=[_p("name", "path")],
                        body={"type": "object", "properties": {"older_than_days": {"type": "integer"}}},
                        auth="admin", tag=T_REPO,
                        example="curl -X POST -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' \\\n"
                                "  -d '{\"older_than_days\": 30}' {base}/api/v1/repositories/dockerhub/cache/purge"),
        },
    }
    # read-only endpoints that security auditors may use as well
    for path, method in [("/api/v1/reports/downloads", "get"), ("/api/v1/reports/usage", "get"), ("/api/v1/users", "get"),
                         ("/api/v1/scanner", "get"), ("/api/v1/notifications", "get"),
                         ("/api/v1/repositories/{name}/cache", "get"), ("/api/v1/storage", "get"), ("/api/v1/clamav", "get")]:
        paths[path][method]["x-auth"] = "audit"
    return {
        "openapi": "3.1.0",
        "info": {"title": "Florepo API", "version": __version__,
                 "description": "Management REST API plus the package protocol endpoints (Docker, PyPI, npm, Maven, Go, NuGet, Cargo, Helm, generic, apt, dnf, apk)."},
        "servers": [{"url": base_url}],
        "components": {"securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer", "description": "API token (flo_…)"},
            "basic": {"type": "http", "scheme": "basic", "description": "username + password or API token"}}},
        "security": [{"bearer": []}, {"basic": []}],
        "tags": [{"name": t} for t in (T_REPO, T_PKG, T_VULN, T_REP, T_SCAN, T_CLAM, T_STORE, T_NOTIFY, T_NET, T_USR, T_LDAP, T_DOCKER, T_PYPI, T_NPM, T_MAVEN, T_GO, T_NUGET, T_CARGO, T_HELM, T_GENERIC, T_DEB, T_RPM, T_APK)],
        "paths": paths,
    }
