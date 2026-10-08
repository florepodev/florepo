# ---- 1) Tailwind CSS build ---------------------------------------------------
FROM node:22-alpine AS css
WORKDIR /build
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY app/templates app/templates
COPY app/static/src app/static/src
RUN npx @tailwindcss/cli -i app/static/src/input.css -o app/static/css/app.css --minify

# ---- 2) Trivy (pinned + checksum verified) -------------------------------------
FROM debian:bookworm-slim AS trivy
ARG TRIVY_VERSION=0.74.0
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in amd64) arch=64bit ;; arm64) arch=ARM64 ;; *) echo "unsupported arch"; exit 1 ;; esac; \
    file="trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz"; \
    base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"; \
    curl -fsSLO "${base}/${file}"; \
    curl -fsSL "${base}/trivy_${TRIVY_VERSION}_checksums.txt" | grep " ${file}\$" | sha256sum -c -; \
    tar -xzf "${file}" trivy; mv trivy /usr/local/bin/trivy; /usr/local/bin/trivy --version

# ---- 3) nginx (static assets + X-Accel-Redirect file serving) -----------------------
FROM nginx:1.29-alpine AS nginx
# rendered by the image's entrypoint (envsubst replaces only ${NGINX_*} variables defined below / in compose)
ENV NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx NGINX_ENVSUBST_FILTER=^NGINX_ NGINX_RESOLVER=127.0.0.11
COPY docker/nginx.conf /etc/nginx/templates/nginx.conf.template
COPY --chmod=755 docker/nginx-ipv6.sh /docker-entrypoint.d/15-ipv6-listen.sh
COPY app/static /usr/share/nginx/static
COPY --from=css /build/app/static/css/app.css /usr/share/nginx/static/css/app.css
EXPOSE 8080

# ---- 4) Runtime -----------------------------------------------------------------
FROM python:3.12-slim
# OS package repositories: gpg (signing), rpm (metadata), createrepo_c (RPM repodata)
RUN apt-get update && apt-get install -y --no-install-recommends gnupg rpm createrepo-c \
    && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DATA_DIR=/data TRIVY_CACHE_DIR=/data/trivy-cache
RUN useradd --system --create-home --uid 1000 florepo && mkdir -p /data && chown florepo /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY . .
COPY --from=css /build/app/static/css/app.css app/static/css/app.css
RUN chmod +x docker/entrypoint.sh
USER florepo
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)" || exit 1
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["web"]
