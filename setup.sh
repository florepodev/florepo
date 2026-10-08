#!/usr/bin/env bash
# Florepo setup: creates the .env file for docker compose.
#
#   ./setup.sh                    interactive (asks, suggests secure defaults)
#   ./setup.sh -y                 non-interactive with defaults (random passwords)
#   ./setup.sh -y --base-url https://registry.example.com --port 443
#   ./setup.sh --force            overwrite an existing .env (a backup is kept)
#
# Every option can also be passed as environment variable, e.g. BASE_URL=... ./setup.sh -y
set -euo pipefail

cd "$(dirname "$0")"
ENV_FILE=".env"
ASSUME_YES=0
FORCE=0
START=0

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  -y, --yes                 non-interactive, use defaults / given values
  -f, --force               overwrite an existing .env (backup: .env.bak.<timestamp>)
      --start               run "docker compose up -d --build" afterwards
      --base-url URL        public URL (default http://localhost:8080)
      --port PORT           published port (default 8080)
      --admin-user NAME     initial admin user (default admin)
      --admin-password PW   initial admin password (default: random)
      --smtp-host HOST      SMTP server for e-mail alerts (optional)
      --smtp-port PORT      (default 587)
      --smtp-user USER      --smtp-password PW   --smtp-from ADDRESS   --smtp-security starttls|ssl|none
      --http-proxy URL      outbound proxy, e.g. http://proxy:3128 (optional)
      --https-proxy URL     (default: same as --http-proxy)
      --no-proxy LIST       (default localhost,127.0.0.1,::1)
      --storage TYPE        fs (default, local volume) | nfs | s3 | s3-local (bundled SeaweedFS)
      --nfs-server HOST     --nfs-export PATH        (--storage nfs)
      --s3-bucket NAME      --s3-endpoint URL (empty = AWS)   --s3-region REGION
      --s3-access-key KEY   --s3-secret-key SECRET   (--storage s3)
      --clamav              start ClamAV and enable malware scanning (~1.5-3 GB RAM)
  -h, --help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    -f|--force) FORCE=1 ;;
    --start) START=1 ;;
    --base-url) BASE_URL="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    --admin-user) ADMIN_USERNAME="$2"; shift ;;
    --admin-password) ADMIN_PASSWORD="$2"; shift ;;
    --smtp-host) SMTP_HOST="$2"; shift ;;
    --smtp-port) SMTP_PORT="$2"; shift ;;
    --smtp-user) SMTP_USERNAME="$2"; shift ;;
    --smtp-password) SMTP_PASSWORD="$2"; shift ;;
    --smtp-from) SMTP_FROM="$2"; shift ;;
    --smtp-security) SMTP_SECURITY="$2"; shift ;;
    --http-proxy) HTTP_PROXY="$2"; shift ;;
    --https-proxy) HTTPS_PROXY="$2"; shift ;;
    --no-proxy) NO_PROXY="$2"; shift ;;
    --storage) STORAGE="$2"; shift ;;
    --nfs-server) NFS_SERVER="$2"; shift ;;
    --nfs-export) NFS_EXPORT="$2"; shift ;;
    --s3-bucket) S3_BUCKET="$2"; shift ;;
    --s3-endpoint) S3_ENDPOINT_URL="$2"; shift ;;
    --s3-region) S3_REGION="$2"; shift ;;
    --s3-access-key) S3_ACCESS_KEY_ID="$2"; shift ;;
    --s3-secret-key) S3_SECRET_ACCESS_KEY="$2"; shift ;;
    --clamav) CLAMAV=yes ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

random() {  # random URL-safe string of $1 characters
  local n="${1:-32}" s=""
  # no "producer | head" pipelines: the producer's SIGPIPE would abort the script under pipefail
  while [ "${#s}" -lt "$n" ]; do
    if command -v openssl >/dev/null 2>&1; then
      s+="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9')"
    else
      s+="$(LC_ALL=C tr -dc 'A-Za-z0-9' < <(head -c 256 /dev/urandom))"
    fi
  done
  printf '%s' "${s:0:$n}"
}

ask() {  # ask VAR "question" default [secret]
  local var="$1" question="$2" default="$3" secret="${4:-}" value=""
  if [ -n "${!var:-}" ]; then return; fi            # given via option / environment
  if [ "$ASSUME_YES" = 1 ] || [ ! -t 0 ]; then printf -v "$var" '%s' "$default"; return; fi
  if [ -n "$secret" ]; then
    read -r -s -p "$question [enter = ${secret}]: " value; echo
  else
    read -r -p "$question [${default}]: " value
  fi
  printf -v "$var" '%s' "${value:-$default}"
}

valid_url() { [[ "$1" =~ ^https?://[^[:space:]/]+(/.*)?$ ]]; }

if [ -f "$ENV_FILE" ] && [ "$FORCE" != 1 ]; then
  echo "$ENV_FILE already exists. Use --force to overwrite it (a backup will be created)." >&2
  exit 1
fi

echo "Florepo setup – creating $ENV_FILE"
echo

ask BASE_URL "Public URL clients use (scheme://host[:port])" "http://localhost:8080"
BASE_URL="${BASE_URL%/}"
valid_url "$BASE_URL" || { echo "invalid URL: $BASE_URL" >&2; exit 2; }
default_port=8080
[[ "$BASE_URL" =~ :([0-9]+)$ ]] && default_port="${BASH_REMATCH[1]}"
ask PORT "Port published on this host" "$default_port"
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || { echo "invalid port: $PORT" >&2; exit 2; }

ask ADMIN_USERNAME "Initial admin user" "admin"
GENERATED_ADMIN_PW=""
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  GENERATED_ADMIN_PW="$(random 20)"
  ask ADMIN_PASSWORD "Admin password (min. 8 characters)" "$GENERATED_ADMIN_PW" "random"
fi
[ "${#ADMIN_PASSWORD}" -ge 8 ] || { echo "admin password must have at least 8 characters" >&2; exit 2; }

ask SMTP_HOST "SMTP server for e-mail alerts (empty = no e-mails)" ""
if [ -n "$SMTP_HOST" ]; then
  ask SMTP_PORT "SMTP port" "587"
  ask SMTP_SECURITY "SMTP security (starttls|ssl|none)" "starttls"
  ask SMTP_USERNAME "SMTP username (empty = no login)" ""
  [ -n "$SMTP_USERNAME" ] && ask SMTP_PASSWORD "SMTP password" "" "keep empty"
  ask SMTP_FROM "Sender address" "florepo@$(echo "$BASE_URL" | sed -E 's#^https?://##; s#[:/].*##')"
fi

ask HTTP_PROXY "Outbound HTTP/HTTPS proxy, e.g. http://proxy:3128 (empty = direct)" ""
if [ -n "$HTTP_PROXY" ]; then
  valid_url "$HTTP_PROXY" || { echo "invalid proxy URL: $HTTP_PROXY" >&2; exit 2; }
  ask HTTPS_PROXY "HTTPS proxy" "$HTTP_PROXY"
  ask NO_PROXY "Hosts reached without proxy" "localhost,127.0.0.1,::1"
fi

ask STORAGE "Artifact storage: fs (local volume) | nfs | s3 | s3-local (bundled SeaweedFS)" "fs"
COMPOSE_FILE_VALUE=""
STORAGE_BACKEND=fs
case "$STORAGE" in
  fs) ;;
  nfs)
    ask NFS_SERVER "NFS server (host or IP)" ""
    ask NFS_EXPORT "NFS export path" "/export/florepo"
    [ -n "$NFS_SERVER" ] || { echo "--storage nfs needs an NFS server" >&2; exit 2; }
    COMPOSE_FILE_VALUE="docker-compose.yml:docker-compose.nfs.yml" ;;
  s3)
    STORAGE_BACKEND=s3
    ask S3_BUCKET "S3 bucket" "florepo"
    ask S3_ENDPOINT_URL "S3 endpoint URL (empty = AWS S3)" ""
    ask S3_REGION "S3 region" "us-east-1"
    ask S3_ACCESS_KEY_ID "S3 access key id" ""
    ask S3_SECRET_ACCESS_KEY "S3 secret access key" "" "keep empty" ;;
  s3-local)
    STORAGE_BACKEND=s3; S3_ENDPOINT_URL=http://s3:8333
    S3_BUCKET=${S3_BUCKET:-florepo}; S3_ACCESS_KEY_ID=${S3_ACCESS_KEY_ID:-florepo}
    S3_SECRET_ACCESS_KEY=${S3_SECRET_ACCESS_KEY:-$(random 40)}
    COMPOSE_FILE_VALUE="docker-compose.yml:docker-compose.s3-local.yml" ;;
  *) echo "unknown storage type: $STORAGE (fs | nfs | s3 | s3-local)" >&2; exit 2 ;;
esac

ask CLAMAV "Scan all artifacts with ClamAV for malware? Needs ~1.5-3 GB RAM (yes/no)" "no"
case "$CLAMAV" in y|Y|yes|YES|j|ja) CLAMAV=yes ;; *) CLAMAV=no ;; esac

if [ -f "$ENV_FILE" ]; then
  backup="$ENV_FILE.bak.$(date +%Y%m%d%H%M%S)"
  cp "$ENV_FILE" "$backup"
  echo "existing $ENV_FILE saved as $backup"
fi

umask 077
cat > "$ENV_FILE" <<EOF
# Generated by setup.sh on $(date -u +"%Y-%m-%d %H:%M UTC") – see README.md → Configuration
SECRET_KEY=$(random 64)
POSTGRES_PASSWORD=$(random 32)

BASE_URL=$BASE_URL
PORT=$PORT

ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD

SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-587}
SMTP_SECURITY=${SMTP_SECURITY:-starttls}
SMTP_USERNAME=${SMTP_USERNAME:-}
SMTP_PASSWORD=${SMTP_PASSWORD:-}
SMTP_FROM=${SMTP_FROM:-florepo@localhost}

HTTP_PROXY=${HTTP_PROXY:-}
HTTPS_PROXY=${HTTPS_PROXY:-}
NO_PROXY=${NO_PROXY:-localhost,127.0.0.1,::1}

# artifact storage (README → Storage)
STORAGE_BACKEND=$STORAGE_BACKEND
$( [ -n "$COMPOSE_FILE_VALUE" ] && echo "COMPOSE_FILE=$COMPOSE_FILE_VALUE" )
$( [ "$STORAGE" = nfs ] && printf 'NFS_SERVER=%s\nNFS_EXPORT=%s\n' "$NFS_SERVER" "$NFS_EXPORT" )
$( case "$STORAGE" in s3|s3-local) printf 'S3_BUCKET=%s\nS3_ENDPOINT_URL=%s\nS3_REGION=%s\nS3_ACCESS_KEY_ID=%s\nS3_SECRET_ACCESS_KEY=%s\n' \
     "$S3_BUCKET" "${S3_ENDPOINT_URL:-}" "${S3_REGION:-us-east-1}" "$S3_ACCESS_KEY_ID" "$S3_SECRET_ACCESS_KEY" ;; esac )

# malware scanning with ClamAV (separate container, Administration → Scanner & DB)
$( if [ "$CLAMAV" = yes ]; then printf 'COMPOSE_PROFILES=clamav\nCLAMAV_ENABLED=true\n'; else printf '# COMPOSE_PROFILES=clamav\n# CLAMAV_ENABLED=true\n'; fi )

# Optional tuning (defaults are fine):
# METADATA_CACHE_MB=32     # rendered package metadata cached per web worker
# WEB_WORKERS=
# WORKER_REPLICAS=1        # parallel scan workers
# PROXY_METADATA_TTL=300
# TRIVY_DB_UPDATE_HOURS=12
# RESCAN_INTERVAL_HOURS=24
EOF
chmod 600 "$ENV_FILE"

echo
echo "Created $ENV_FILE (permissions 600)."
echo "  URL:   $BASE_URL"
echo "  Admin: $ADMIN_USERNAME"
[ -n "$GENERATED_ADMIN_PW" ] && [ "$ADMIN_PASSWORD" = "$GENERATED_ADMIN_PW" ] && echo "  Admin password (generated, stored in $ENV_FILE): $ADMIN_PASSWORD"
case "$BASE_URL" in http://localhost*|http://127.0.0.1*) ;; http://*) echo "  Note: Docker requires HTTPS for registries other than localhost – put a TLS proxy in front (README → Production deployment).";; esac
echo

if [ "$START" = 1 ]; then
  docker compose up -d --build
else
  echo "Start with:  docker compose up -d --build"
fi
