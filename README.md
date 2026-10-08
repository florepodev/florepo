# Florepo

**Free, lightweight, open artifact repository & container registry** – <https://florepo.dev> · <https://github.com/florepodev/florepo>

Self-hosted artifact repository for **Docker / OCI, PyPI, npm, Maven, Go, NuGet, Cargo, Helm, generic files,
Debian (apt), RPM (dnf/yum) and Alpine (apk)** – with pull-through caching, built-in vulnerability scanning (Trivy + OSV.dev),
optional **ClamAV malware scanning**, CycloneDX **SBOMs**, security policies, **quotas**, **LDAP / Active Directory** login,
storage on local disk, **NFS** or **S3**, e-mail alerts, usage reporting ("who pulled what") and a documented REST API.

Flask · Tailwind CSS · PostgreSQL · gevent · nginx – shipped as Docker containers. Licensed under **Apache-2.0**.

> The in-app **Setup guides** (`/docs/guides`) contain copy-ready examples for every client and option, filled with your instance's
> URL and repositories; the **API docs** (`/docs`) are generated from the OpenAPI 3.1 spec (`/api/openapi.json`).

---

## Contents

[Features](#features) · [Quick start](#quick-start) · [Clients](#clients) · [Architecture](#architecture) ·
[Scanning & SBOM](#security-scanning--sbom) · [Malware scanning](#malware-scanning-clamav) · [Proxy cache](#proxy-cache--retention) ·
[Quotas](#quotas) · [Storage](#storage-disk-nfs-s3) · [Permissions](#users-roles--permissions) · [LDAP / AD](#ldap--active-directory) ·
[Alerts](#e-mail-alerts) · [Outbound proxy](#outbound-httphttps-proxy) · [Reporting & API](#reporting--rest-api) ·
[Configuration](#configuration) · [Upgrades](#upgrades--database-migrations) · [Performance](#performance--scaling) ·
[Operations](#operations) · [Development](#development) · [License](#license)

## Features

| | Hosted (publish) | Proxy (pass-through cache) |
|---|---|---|
| **Docker / OCI** | `docker push`, chunked/monolithic uploads, cross-repo mount, multi-arch, Helm OCI | Docker Hub, GHCR, Quay, any v2 registry (token auth, upstream credentials) |
| **PyPI** | `twine upload` (wheel + sdist) | pypi.org or any PEP 503/691 index, PEP 658 metadata |
| **npm** | `npm publish`, unpublish, deprecate, dist-tags, scoped packages | registry.npmjs.org or any npm registry |
| **Maven / Gradle** | `mvn deploy`, `gradle publish`, SNAPSHOTs, generated `maven-metadata.xml`, md5/sha1/sha256/sha512 | Maven Central or any Maven 2 repository |
| **Go modules** | upload module zips (normalized to `module@version/`), GOPROXY protocol | proxy.golang.org incl. **checksum DB relay** (`sum.golang.org`) |
| **NuGet** | `dotnet nuget push`, delete, registrations, search | nuget.org (all upstream URLs rewritten) |
| **Cargo** | `cargo publish`, yank/unyank, search (sparse index) | crates.io sparse index (checksums verified) |
| **Helm** | ChartMuseum API (`helm cm-push`, curl), generated `index.yaml` | any chart repository (chart URLs rewritten) |
| **Generic** | any file via `curl -T`, checksum header, listing, delete | any HTTP(S) file server, e.g. GitHub releases |
| **Debian / Ubuntu** | upload `.deb`, signed `InRelease`/`Release.gpg`, `Packages(.gz)` | deb.debian.org, archive.ubuntu.com, … (upstream signatures kept) |
| **RPM** | upload `.rpm`, repodata via createrepo_c, signed `repomd.xml` | Rocky, Alma, CentOS Stream, Fedora, EPEL, … |
| **Alpine** | upload `.apk`, signed `APKINDEX.tar.gz` (RSA256) | dl-cdn.alpinelinux.org |

- **Vulnerability scanning** of every version on upload / first cache fill and periodically: Trivy for images and OS packages
  (distribution detected or configured), Trivy + OSV.dev for PyPI, npm, Maven, Go, NuGet and Cargo; jars, lock files and
  Go/Rust binaries inside Helm charts and generic archives are found by Trivy as well.
- **Malware scanning with ClamAV** (optional container): every file / image layer, infected versions blocked, alert e-mail,
  optional "hold back until scanned".
- **Signature DB management** – DB age, scheduled/manual updates, re-scan of outdated results.
- **CycloneDX SBOM** per version (UI + API).
- **Security policy** per repository – block downloads from a severity (HTTP 403, hidden from indexes); the last scan result keeps
  applying while a re-scan is pending.
- **Quotas** – per repository (hosted: upload limit, proxy: cache size limit with LRU eviction) and per user (global default + individual).
- **Storage backends** – local volume, NFS/SMB/CephFS share or **S3-compatible object storage** (AWS, Ceph, Garage, SeaweedFS, MinIO, …),
  migration tool `storage-copy`.
- **LDAP / Active Directory** – login with directory credentials (UI and all clients), **group → role / repository mapping**, nested AD
  groups, periodic sync that disables removed users.
- **Proxy cache retention** – keep cached packages *N days after the last download*, manual purge, cache hit statistics.
- **Metadata cache** – rendered package metadata cached pre-compressed, invalidated immediately on every change, ETag/304.
- **E-mail alerts** when re-scans reveal *new* vulnerabilities above a threshold or ClamAV finds malware (one batched mail per cycle).
- **Reporting** – downloads per day, top packages/users, cache hit rate, *vulnerable versions in use and who pulled them*,
  package inventory, per-user reports, download log, audit log – sortable, CSV export.
- **Roles** reader / deployer (all or selected repositories) / **security auditor** (read-only, reports, SBOMs, no downloads) / admin.
- **Outbound HTTP/HTTPS proxy** – global and per repository (direct / custom), `NO_PROXY`, connection test.
- **Automatic schema migrations** (Alembic) on every start; **multiple scan workers** with leader election.
- English web UI with Lucide icons, sortable tables, in-app setup guides and API docs.

## Quick start

Requirements: Docker with Compose v2.

```bash
./setup.sh                 # creates .env with random secrets (interactive; -y for defaults, --help for options)
docker compose up -d --build
```

Open the URL shown by `setup.sh` (default <http://localhost:8080>) and sign in as `admin` with the printed password.
Create repositories under **Repositories → New repository** and an API token under **API tokens** – each repository page
and the **Setup guides** show the client configuration.

`setup.sh` options: `-y` non-interactive, `--force` (backup + overwrite), `--start`, `--base-url`, `--port`, `--admin-user`,
`--admin-password`, `--smtp-*`, `--http-proxy`/`--https-proxy`/`--no-proxy`, `--storage fs|nfs|s3|s3-local` (with `--nfs-server`,
`--nfs-export`, `--s3-bucket`, `--s3-endpoint`, `--s3-region`, `--s3-access-key`, `--s3-secret-key`) and `--clamav`.
All values can also be passed as environment variables.

The first start downloads the Trivy vulnerability DB in the background (a few minutes; the Java DB is ~1 GB).

## Clients

Replace `USER`/`TOKEN` with your user name and an API token (`flo_…`). More variants (uv, poetry, yarn, pnpm, Gradle, Kubernetes,
CI pipelines, Dockerfiles, private apt/dnf/apk repositories) are in the in-app **Setup guides**.

```bash
# Docker – the first path segment is the repository
docker login registry.example.com
docker pull  registry.example.com/dockerhub/nginx:alpine          # proxy ("library/" added for Docker Hub)
docker push  registry.example.com/docker/team/myapp:1.0           # hosted

# PyPI
pip install --index-url https://USER:TOKEN@registry.example.com/pypi/pypi-remote/simple/ requests
twine upload --repository-url https://registry.example.com/pypi/pypi-local/ -u USER -p TOKEN dist/*

# npm (.npmrc)
registry=https://registry.example.com/npm/npm-remote/
//registry.example.com/npm/npm-remote/:_authToken=TOKEN
```

```bash
# Maven – ~/.m2/settings.xml: <mirror> of central -> https://registry.example.com/maven/maven-central/ (+ <server> credentials)
mvn deploy                       # pom.xml <distributionManagement> -> https://registry.example.com/maven/libs/

# Go – go never sends credentials over plain HTTP, use HTTPS
go env -w GOPROXY=https://USER:TOKEN@registry.example.com/go/golang,direct
go env -w GOSUMDB="sum.golang.org https://USER:TOKEN@registry.example.com/go/golang/sumdb/sum.golang.org"
curl -u USER:TOKEN --upload-file v1.4.0.zip https://registry.example.com/go/gomods/git.example.com/team/mymod/@v/v1.4.0.zip

# NuGet
dotnet nuget add source https://registry.example.com/nuget/nuget-org/index.json -n florepo -u USER -p TOKEN --store-password-in-clear-text
dotnet nuget push MyLib.1.0.0.nupkg -s https://registry.example.com/nuget/nugets/index.json -k TOKEN

# Cargo – ~/.cargo/config.toml: [registries.florepo] index = "sparse+https://registry.example.com/cargo/crates/index/"
cargo login --registry florepo TOKEN && cargo publish --registry florepo

# Helm
helm repo add florepo https://registry.example.com/helm/charts --username USER --password TOKEN
curl -u USER:TOKEN --data-binary @mychart-0.1.0.tgz https://registry.example.com/helm/charts/api/charts

# Generic files – <package path>/<version>/<file>
curl -u USER:TOKEN -T tool.tar.gz https://registry.example.com/generic/files/tools/mytool/1.4.0/tool.tar.gz
```

```bash
# Debian / Ubuntu – proxy (deb822 sources file; Debian's own keyring stays valid)
cat > /etc/apt/sources.list.d/debian.sources <<'EOF'
Types: deb
URIs: https://registry.example.com/deb/debian-remote
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
# Debian – hosted (signed by Florepo)
curl -u USER:TOKEN --upload-file mytool_1.0-1_amd64.deb "https://registry.example.com/deb/debian-local/upload/?distribution=stable"
curl -fsSL https://registry.example.com/deb/debian-local/key.gpg -o /etc/apt/keyrings/florepo.gpg
echo "deb [signed-by=/etc/apt/keyrings/florepo.gpg] https://registry.example.com/deb/debian-local stable main" \
  > /etc/apt/sources.list.d/florepo.list

# RPM – proxy baseurl / hosted repo with signed metadata
baseurl=https://registry.example.com/rpm/rocky-remote/$releasever/BaseOS/$basearch/os/
curl -u USER:TOKEN --upload-file mytool-1.0-1.x86_64.rpm https://registry.example.com/rpm/rpm-local/upload/
# /etc/yum.repos.d/florepo.repo: baseurl=…/rpm/rpm-local/  repo_gpgcheck=1  gpgkey=…/rpm/rpm-local/key.asc

# Alpine – proxy / hosted
echo "https://registry.example.com/apk/alpine-remote/v3.20/main" > /etc/apk/repositories
curl -u USER:TOKEN --upload-file mytool-1.0-r0.apk "https://registry.example.com/apk/alpine-local/upload/?branch=v3.20"
wget -O /etc/apk/keys/<key name shown on the repository page> https://registry.example.com/apk/alpine-local/key.rsa.pub
```

Docker and Go require TLS for remote registries with credentials – see [Operations](#operations).
.NET 9+ needs `allowInsecureConnections="true"` for plain HTTP sources.

## Architecture

```
                  ┌──────────── nginx ────────────┐
 clients/browser ─▶│ /static/*        from disk    │
                  │ /_storage/*      internal ◀───┼── X-Accel-Redirect ─┐   (file system / NFS)
                  │ /_s3/*           internal ◀───┼── X-Accel-Redirect ─┤   (S3: pre-signed, streamed by nginx)
                  │ everything else ──────────────┼─▶ web (gunicorn + gevent, Flask)
                  └───────────────────────────────┘    /v2 /pypi /npm /maven /go /nuget /cargo /helm /generic /deb /rpm /apk
                                                       /api/v1 · UI   (metadata cache, quotas, LDAP)
                                                         ├─▶ PostgreSQL (metadata, findings, events; Alembic migrations)
                                                         ├─▶ blob store: /data/storage (disk / NFS) or S3 bucket
                                                         ├─▶ LDAP / AD (optional)
                                                         └─▶ upstream registries (optionally via outbound proxy)
 worker × N ── one leader (advisory lock): DB updates, re-scan scheduling, alerts, counters, retention, cache limits, LDAP sync
            └─ all: ClamAV (optional) + Trivy / OSV scans (claimed atomically, in-memory Trivy cache)
```

- Every file is stored once by SHA-256; Docker blobs are only served through repositories they were pushed/mounted to or that
  reference them (no access to layers of other private repositories by digest).
- Proxy artifacts are immutable and cached; index metadata is cached for `PROXY_METADATA_TTL` and served stale if the upstream is down.
- Hosted deb/rpm/apk indexes are regenerated and signed on every upload/delete; keys are created once (`/data/keys`).

## Security scanning & SBOM

| Format | Scanner | Notes |
|---|---|---|
| Docker | Trivy image scan (OCI layout from the blob store) | one platform per tag (`linux/amd64` preferred) |
| PyPI, npm | Trivy (extracted package) + OSV.dev | |
| Maven | Trivy Java analyzer (jar/war/ear, Java DB) + OSV.dev (`group:artifact`) | dependencies of the POM in the SBOM |
| Go, Cargo, NuGet | Trivy filesystem scan (go.mod/go.sum, Cargo.lock, lock files) + OSV.dev | dependencies from go.mod / index / nuspec |
| Helm, generic | Trivy on the extracted archive / file (jars, lock files, Go/Rust binaries) | chart dependencies in the SBOM |
| deb, rpm, apk | Trivy SBOM scan with distribution context | distribution from the repository setting (`debian:12`, `ubuntu:24.04`, `alpine:3.20`, `rocky:9`, `alma:9`, …) or detected |

**Administration → Scanner & DB**: signature DB date and age, update schedule (manual … weekly, default 12 h), Java DB,
re-scan interval (default 24 h), "re-scan after DB update", re-scan outdated/failed/all, update history, running workers and
the ClamAV settings.

**Security policy**: *Block downloads from severity* per repository → HTTP 403 for clients (`docker pull` → `DENIED`);
blocked versions are removed from pip/npm/Maven/Go/NuGet/Cargo/Helm and hosted OS indexes.

## Malware scanning (ClamAV)

Optional: start the `clamav` service (`COMPOSE_PROFILES=clamav`, ~1.5–3 GB RAM, signatures updated by freshclam) and enable it under
**Administration → Scanner & DB → Malware scanning** (or `CLAMAV_ENABLED=true` / `PUT /api/v1/clamav`). Every new or changed version
is streamed to clamd before the vulnerability scan (all files; Docker: config + layers of the scanned platform; archives are unpacked
by ClamAV); periodic re-scans repeat the check with current signatures.

- **Block infected versions** (default) – HTTP 403 with `"reason": "malware"`, hidden from indexes, alert e-mail if alerts are enabled.
- **Hold back new uploads until scanned** – hosted repositories serve new versions only after a clean result.
- Files above *Skip files larger than* (default 1024 MB) are not sent; clamd's `StreamMaxLength` is 2000M in `docker-compose.yml`.
- Results per version in the UI and the API (`.scan.malware`), counters and infected versions on the scanner page.

## Proxy cache & retention

- **Keep cached packages on disk for N days after the last download** (repository setting `cache_retention_days`, 0 = forever).
  The worker removes expired versions hourly and runs a garbage collection; removed packages are fetched again on demand.
- **Cache size limit** = the quota of a proxy repository (see below).
- Manual purge (all, or entries unused for N days): repository page, `POST /api/v1/repositories/{name}/cache/purge`,
  `flask --app wsgi purge-cache <repo> --older-than 90`. Cache usage: repository page / `GET /api/v1/repositories/{name}/cache`.
- Every download records cache hit/miss → hit rate in **Reporting**.

## Quotas

| | Effect |
|---|---|
| Repository quota (hosted) | uploads that would exceed it are rejected with **HTTP 413** and a clear message (`docker push`: `DENIED: repository quota exceeded …`); layers already stored for other repositories count when the manifest is pushed |
| Repository quota (proxy) | **cache size limit** – least recently used cached versions are evicted hourly down to 90 % |
| User quota | total size a user may upload to hosted repositories; global default for non-admins (**Administration → Storage & quotas**), individual value (custom / unlimited) on the user page |

Values like `500M`, `20G`, `1T`. Usage is the logical size of the stored artifacts (Docker layers shared by several tags count once
per repository); **Storage & quotas** and the repository list show usage bars, `GET /api/v1/storage` returns all numbers.

## Storage: disk, NFS, S3

| `STORAGE_BACKEND` | Where | Notes |
|---|---|---|
| `fs` (default) | `STORAGE_PATH` (`/data/storage`) | local volume or a mounted **NFS / SMB / CephFS** share – `docker-compose.nfs.yml` mounts an NFS export (`NFS_SERVER`, `NFS_EXPORT`); writes are atomic (temp file + rename), several hosts can share it; uid 1000 must be able to write |
| `s3` | `S3_BUCKET` (+ `S3_PREFIX`) at `S3_ENDPOINT_URL` (empty = AWS) | AWS S3, Ceph RGW, Garage, Wasabi, SeaweedFS, MinIO, …; uploads staged locally (`STAGING_PATH`) and verified, multipart upload; downloads `S3_SERVE=proxy` (nginx streams from S3, default) / `redirect` (pre-signed URL) / `stream`; `docker-compose.s3-local.yml` bundles SeaweedFS |

Database, signing keys and the Trivy cache always stay on the local `data` volume. Migrating existing data:

```bash
docker compose run --rm web flask --app wsgi storage-copy     # copies blobs + SBOMs into the configured backend (skips existing)
docker compose exec web flask --app wsgi storage-check        # write / read / delete probe
```

## Users, roles & permissions

| | reader | deployer | auditor | admin |
|---|---|---|---|---|
| Browse repositories, vulnerabilities, SBOM download | ✔ | ✔ | ✔ (incl. private) | ✔ |
| Pull / install packages (all protocols) | ✔ | ✔ | – | ✔ |
| Publish, overwrite, delete versions | – | ✔ all or selected hosted repos | – | ✔ |
| Reports, download log, audit log, user list (read) | – | – | ✔ | ✔ |
| Repository, user, scanner, alert, network, storage and LDAP settings | – | – | – | ✔ |

API tokens inherit the permissions of their user; disabling a user blocks its tokens. Public repositories can be read anonymously.

## LDAP / Active Directory

**Administration → Authentication**: server URLs (ldaps / ldap + StartTLS, failover), service account, user search base and filter
(presets for AD and OpenLDAP), group membership via `memberOf`, **AD nested groups** (LDAP_MATCHING_RULE_IN_CHAIN) or a group search
filter, and an ordered **group → role mapping**; deployer rows may restrict write access to repositories. Users without a mapped group
are refused (or get a default role). Accounts are created at the first sign-in – in the UI and with every client using HTTP Basic
(`docker login`, pip, Maven, NuGet, Helm, …); role and repositories are refreshed at each login and by a periodic sync, which also
disables users removed from the directory, disabled in AD or dropped from all mapped groups (their API tokens stop working too).
Local accounts keep working. A *Test* function shows the found DN, groups and resulting role; `POST /api/v1/ldap/test`,
`flask --app wsgi ldap-sync`.

## E-mail alerts

Periodic re-scans (with new signatures) that reveal **new** findings at or above a threshold – and every ClamAV detection – trigger
one batched e-mail per scan cycle (plain text + HTML, with links). Configure SMTP via `SMTP_*` in `.env`, the rule (recipients,
threshold, repositories, "only new findings", "also on uploads") under **Administration → Notifications**, including *Send test* and
the alert history.

## Outbound HTTP/HTTPS proxy

All upstream traffic – proxy repositories, OSV.dev and Trivy DB downloads – can use a corporate proxy:
globally under **Administration → Network** (defaults from `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, credentials stored masked)
and per proxy repository (global / direct / custom URL). *Test connection* checks a URL with the effective settings.
Object storage traffic bypasses it unless `S3_USE_PROXY=true`.

## Reporting & REST API

Every pull is logged (user, version, file, IP, client, cache hit). **Reporting** shows usage, the package inventory, per-user
reports and – most important – vulnerable versions in use and who pulled them; all tables are sortable and exportable as CSV.

The REST API (`/api/v1`, `Authorization: Bearer <token>`) covers repositories, packages/versions, vulnerabilities, SBOMs,
reports, users/tokens, scanner, ClamAV, storage/quotas, LDAP, notifications, network and cache – reference at **`/docs`**,
spec at `/api/openapi.json`.

```bash
curl -H "Authorization: Bearer $TOKEN" "https://registry.example.com/api/v1/reports/downloads?days=7"
curl -s -H "Authorization: Bearer $TOKEN" https://registry.example.com/api/v1/versions/42 \
  | jq -e '.scan.counts.critical == 0 and .scan.malware.status != "infected"'
```

## Configuration

`setup.sh` writes `.env`; scanner schedule, ClamAV, alert rules, LDAP, quotas and the outbound proxy are additionally editable at
runtime in the UI.

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | – | session secret (**required**, generated by setup.sh) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / random | initial admin (only if no user exists) |
| `BASE_URL` / `PORT` | `http://localhost:8080` / `8080` | public URL / published nginx port |
| `POSTGRES_PASSWORD` | generated | database password (compose) |
| `WEB_WORKERS` / `WEB_WORKER_CONNECTIONS` | 2 × CPU (max 16) / `1000` | gunicorn gevent processes / connections each |
| `WORKER_REPLICAS` | `1` | parallel scan workers |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `5` / `15` | DB connections per web process |
| `PROXY_METADATA_TTL` | `300` | seconds proxied index metadata is cached |
| `METADATA_CACHE_MB` | `32` | rendered metadata cached per web worker (0 = off) |
| `UPSTREAM_TIMEOUT` | `30` | seconds for upstream requests |
| `TRIVY_DB_UPDATE_HOURS` / `RESCAN_INTERVAL_HOURS` | `12` / `24` | default schedules (0 = off/manual) |
| `TRIVY_JAVA_DB` / `RESCAN_AFTER_DB_UPDATE` / `OSV_ENABLED` | `true` / `false` / `true` | scanner options |
| `COMPOSE_PROFILES=clamav`, `CLAMAV_ENABLED` / `CLAMAV_HOST` / `CLAMAV_PORT` | – / `false` / `clamav` / `3310` | malware scanning |
| `STORAGE_BACKEND` | `fs` | `fs` or `s3` |
| `STORAGE_PATH` / `STAGING_PATH` | `/data/storage` / (fs: same, s3: `/data/staging`) | blob store / local staging |
| `NFS_SERVER` / `NFS_EXPORT` / `NFS_VERSION` | – / – / `4.1` | with `COMPOSE_FILE=docker-compose.yml:docker-compose.nfs.yml` |
| `S3_BUCKET` `S3_PREFIX` `S3_ENDPOINT_URL` `S3_REGION` `S3_ACCESS_KEY_ID` `S3_SECRET_ACCESS_KEY` | – | S3 storage |
| `S3_SERVE` / `S3_ADDRESSING_STYLE` / `S3_VERIFY_TLS` / `S3_CA_BUNDLE` / `S3_USE_PROXY` | `proxy` / `auto` / `true` / – / `false` | S3 options |
| `SMTP_HOST` `SMTP_PORT` `SMTP_SECURITY` `SMTP_USERNAME` `SMTP_PASSWORD` `SMTP_FROM` | – / 587 / starttls | e-mail alerts |
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | – | outbound proxy defaults |
| `ACCESS_LOG` / `LOG_LEVEL` | `true` / `INFO` | logging |
| `DATA_DIR` / `KEYS_PATH` | `/data`, `/data/keys` | data and signing key locations |

## Upgrades & database migrations

The schema is versioned with **Alembic** (`app/migrations/versions/0001_…` … `0005_…`; current revision in the table
`alembic_version`). When a new version starts, the web container applies all pending migrations **automatically** before
accepting requests – a database lock serializes concurrently starting containers and the workers wait until the schema is current.
Installations created before migrations existed are detected, patched to the baseline and stamped automatically.

```bash
git pull && docker compose up -d --build                 # migrates automatically
docker compose logs web | grep -i migrat                 # e.g. "Running upgrade 0004 -> 0005"
docker compose exec web flask --app wsgi db-current      # current: 0005  head: 0005
```

For developers: change `app/models.py`, then `flask --app wsgi db-revision -m "describe the change"` (autogenerate; review the
file) or `--empty` for data migrations; commit the file. `tests/test_migrations.py` fails if models and migrations differ.

## Performance & scaling

Measured on Docker Desktop / Windows (16 vCPUs; native Linux is typically 2–5× faster):

| Request (50–300 concurrent clients) | Requests/s |
|---|---|
| Docker layer (200 KB) via nginx X-Accel-Redirect | ~580 |
| npm packument, 264 KB (proxy, metadata cache + gzip) | ~650 (before the metadata cache: ~230) |
| PyPI simple index (proxy, metadata cache) | ~690 (before: ~290) |
| maven-metadata.xml (proxy, metadata cache) | ~600 (before: ~43) |
| Helm index.yaml, 6 MB (proxy, metadata cache + gzip) | ~200 (before: ~28) |
| PyPI wheel download incl. download logging | ~250 |
| Full re-scan, ~260 versions: 1 worker / 3 workers | 276 s / 101 s |

Design choices: nginx serves all stored files (also from S3), gevent workers, metadata cache with change fingerprints and pre-compressed
documents, proxy metadata TTL cache, append-only download log (no hot-row locks), cached token checks, PEP 658 metadata, in-memory Trivy
cache for parallel scans. Scale with `WEB_WORKERS`, `WORKER_REPLICAS` (or `docker compose up -d --scale worker=4`) and multiple `web`
containers/hosts (stateless with S3 or a shared NFS store); keep `WEB_WORKERS × (DB_POOL_SIZE + DB_MAX_OVERFLOW)` below PostgreSQL's
`max_connections` (500 in compose).

## Operations

- **TLS**: put a TLS reverse proxy in front (Caddy, Traefik, nginx; disable request size limits) and set `BASE_URL=https://…`.
- **Backup** the PostgreSQL database *and* the `data` volume (blobs, SBOMs, **signing keys** trusted by apt/dnf/apk clients) –
  with S3 / NFS storage, back up (or version) the bucket / export as well.
- `flask --app wsgi gc [--dry-run]` – delete unreferenced blobs (also run hourly after cache retention);
  `create-user`, `purge-cache`, `storage-check`, `storage-copy`, `ldap-sync`, `db-current`, `db-upgrade`, `db-revision`.
- Health: `GET /healthz`; **Scanner & DB** shows worker heartbeats, the leader and the ClamAV engine.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt     # needs gpg, rpm, createrepo_c for OS repositories
npm install && npm run watch:css
export DATA_DIR=./data SECRET_KEY=dev ADMIN_PASSWORD=admin123
flask --app wsgi init-db && flask --app wsgi run --debug     # + "flask --app wsgi worker" for scans
docker build -t florepo . && docker run --rm --entrypoint sh florepo -c "pip install -q --user pytest && python -m pytest -q tests"
```

```
app/
  blueprints/   docker · pypi · npm · maven · golang · nuget · cargo · helm · generic · ospkg (deb/rpm/apk)
                ui · reports · api · docs · common (shared helpers)
  scanner.py    Trivy / OSV / SBOM         malware.py     ClamAV client + policy   worker.py   scans + leader tasks
  storage.py    fs / S3 blob store         quotas.py      usage + limits           metacache.py metadata cache
  ldap_auth.py  LDAP / AD login + sync     auth.py        tokens, basic, sessions  migrate.py  Alembic
  ospkg.py      deb/rpm/apk parsing        signing.py     GPG + RSA keys           cache.py    retention + GC
  netproxy.py   outbound proxy             notifications.py e-mail alerts          services.py shared validation
  openapi.py    API spec                   migrations/    Alembic revisions        templates/  Jinja2 + Tailwind
docker/         nginx.conf · gunicorn.conf.py · entrypoint.sh       setup.sh   .env generator
docker-compose.nfs.yml · docker-compose.s3-local.yml                 storage variants
tests/          pytest suite (all formats, OS repositories, API, permissions, auditor, LDAP, quotas, ClamAV, storage,
                metadata cache, migrations, workers, alerts, proxy)
```

## Limitations

- Docker proxy repositories cannot be used as a daemon `registry-mirrors` entry (prefixed image names are required).
- Images are scanned (CVE and ClamAV) for one platform per tag; OS package scanning needs a known distribution.
- Upstream, proxy, LDAP bind and S3 credentials of the UI are stored in the database / `.env` (masked in UI and API).
- Go modules: hosted uploads are zip files (no VCS integration); Helm OCI charts go to Docker repositories.

## License

Copyright 2026 Maximilian Thoma

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the
License. You may obtain a copy of the License at <https://www.apache.org/licenses/LICENSE-2.0>. Unless required by applicable law
or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

### Third-party components

| Component | License | Use |
|---|---|---|
| Flask, Werkzeug, Jinja2, MarkupSafe, click, itsdangerous, Flask-SQLAlchemy, Flask-WTF, WTForms, idna, pycparser, zstandard | BSD-3-Clause | Python libraries |
| SQLAlchemy, alembic, Mako, gunicorn, gevent, Flask-Login, blinker, urllib3, charset-normalizer, PyYAML, jmespath, six | MIT | Python libraries |
| greenlet / cffi / typing_extensions | MIT AND PSF-2.0 / MIT-0 / PSF-2.0 | Python libraries |
| requests, packaging, cryptography, boto3, botocore, s3transfer, python-dateutil | Apache-2.0 (packaging, cryptography, dateutil: or BSD) | Python libraries (boto3: S3 storage) |
| psycopg, psycopg-binary | LGPL-3.0-only | PostgreSQL driver, dynamically imported, unmodified |
| ldap3 / pyasn1 | LGPL-3.0 / BSD-2-Clause | LDAP / AD authentication, dynamically imported, unmodified |
| certifi | MPL-2.0 | CA bundle, unmodified |
| zope.event, zope.interface | ZPL-2.1 | gevent dependencies |
| Trivy | Apache-2.0 | scanner (separate program in the image) |
| GnuPG | GPL-3.0-or-later | repository signing (separate program) |
| RPM, createrepo_c | GPL-2.0-or-later | RPM metadata (separate programs) |
| nginx | BSD-2-Clause | front-end container |
| PostgreSQL | PostgreSQL License | database container |
| ClamAV (optional) | GPL-2.0-only | malware scanning – separate container, clamd network protocol |
| SeaweedFS (optional example) | Apache-2.0 | S3 store in `docker-compose.s3-local.yml` |
| Lucide icons | ISC | UI icons (`app/static/icons`, see `LICENSE.lucide`) |
| Tailwind CSS | MIT | build time only |

Programs bundled in the images and the optional containers are separate executables invoked as external processes or over the
network. Vulnerability data (Trivy DB, OSV.dev) and ClamAV signatures are downloaded at runtime by the operator and are subject to
the terms of the respective sources. The name "Florepo" and the logo are not licensed under the Apache License (section 6).
