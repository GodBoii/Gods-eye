# syntax=docker/dockerfile:1

FROM node:26-bookworm-slim AS dashboard-build
WORKDIR /build/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
RUN npm run build

FROM golang:1.27.2-bookworm AS go-build
WORKDIR /build/go
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY gen/go/ ./gen/go/
RUN go test ./... \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/godseye ./cmd/godseye

FROM python:3.13.16-slim-bookworm AS python-build
WORKDIR /build/python
COPY backend/requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.lock
COPY backend/pyproject.toml ./
COPY backend/src/ ./src/
RUN pip install --no-cache-dir --no-deps --prefix=/install .

# Complete existing backend and built React frontend during the Python migration.
FROM debian:bookworm-slim AS dashboard
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 godseye \
    && useradd --uid 10001 --gid godseye --no-create-home godseye \
    && mkdir -p /state /workspace \
    && chown godseye:godseye /state /workspace
COPY --from=go-build /out/godseye /usr/local/bin/godseye
COPY --from=dashboard-build /build/web/dist/ /app/web/
COPY licenses/ /app/licenses/
COPY LICENSE NOTICE /app/
WORKDIR /workspace
USER 10001:10001
EXPOSE 8765
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error --max-time 3 http://127.0.0.1:8765/api/health || exit 1
ENTRYPOINT ["godseye"]
CMD ["serve", "--bind", "0.0.0.0", "--root", "/workspace", "--state", "/state", "--web", "/app/web"]

# Separate, explicit Python candidate. Its state is never shared with Go.
FROM python:3.13.16-slim-bookworm AS python-backend
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 godseye \
    && useradd --uid 10001 --gid godseye --no-create-home godseye \
    && mkdir -p /state /workspace \
    && chown godseye:godseye /state /workspace
COPY --from=python-build /install/ /usr/local/
COPY --from=dashboard-build /build/web/dist/ /app/web/
COPY licenses/ /app/licenses/
COPY LICENSE NOTICE /app/
WORKDIR /workspace
USER 10001:10001
EXPOSE 8875
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import json,urllib.request; d=json.load(urllib.request.urlopen('http://127.0.0.1:8875/api/health',timeout=3)); assert d['runtime']=='python' and 'source-scans-v1' in d['capabilities']"]
ENTRYPOINT ["python", "-m", "godseye"]
CMD ["serve", "--bind", "0.0.0.0", "--port", "8875", "--root", "/workspace", "--state", "/state", "--web", "/app/web"]

FROM node:26-bookworm-slim AS earth-build
ENV PUPPETEER_SKIP_DOWNLOAD=1
WORKDIR /build/earth
COPY apps/earth/package.json apps/earth/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/earth/ ./
RUN npm run build

# Earth keeps its keyless Node provider middleware in production preview mode.
FROM node:26-bookworm-slim AS earth
ENV NODE_ENV=production PUPPETEER_SKIP_DOWNLOAD=1
WORKDIR /app
COPY --from=earth-build --chown=node:node /build/earth/ ./
RUN mkdir -p .gev-cache .gev-logs && chown node:node .gev-cache .gev-logs
USER node
EXPOSE 4173
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
    CMD ["node", "--input-type=module", "-e", "const r=await fetch('http://127.0.0.1:4173/',{signal:AbortSignal.timeout(3000)});if(!r.ok)process.exit(1)"]
CMD ["node", "node_modules/vite/bin/vite.js", "preview", "--host", "0.0.0.0", "--port", "4173", "--strictPort", "--configLoader", "native"]
