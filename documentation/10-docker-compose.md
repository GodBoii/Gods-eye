# Run the application with Docker Compose

From the repository root, with Docker Desktop running in Linux-container mode:

```powershell
docker compose up --build
```

The build installs dependencies and builds both frontends inside Docker. No host npm, Python or Go installation is required for this command. The first build downloads base images and dependencies; later builds reuse Docker's cache.

| URL | Service |
| --- | --- |
| [http://127.0.0.1:8765](http://127.0.0.1:8765) | Full security dashboard and current Go backend, including Workbench and assessments |
| [http://127.0.0.1:4173](http://127.0.0.1:4173) | Earth console with its keyless Node provider middleware |
| [http://127.0.0.1:8875](http://127.0.0.1:8875) | Separate Python migration candidate, supporting inventory and source/HTTPS checks |

Use port 8765 for the full product. Container packaging does not complete the Python migration. The `dashboard` service retains the current Go implementation while features move to `python-backend`. Each service has its own state volume. The Python candidate's Workbench routes remain unimplemented; its existing frontend starts on Workbench, so choose Overview, Assets or Checks there.

All published ports bind to host loopback. The backend processes bind to container interfaces explicitly while retaining the configured Host/Origin/request-header checks. Use the URLs above, including `127.0.0.1`.

## Daily commands

```powershell
# Run in the background and wait for healthchecks.
docker compose up --build -d --wait

# See service state and logs.
docker compose ps
docker compose logs -f

# Stop and remove the containers. Named volumes retain saved state.
docker compose down
```

Source changes take effect after `docker compose up --build`. Each image contains its matching built frontend; there is no host node_modules or dist mount. Earth runs Vite production preview with its existing provider plugins, rather than static-only hosting.

## Workspace and saved data

The repository is mounted read-only at `/workspace` by default. Source checks use workspace-relative paths, such as `backend/src` or `apps/web/src`. To scan another directory, set its path before starting Compose:

```powershell
$env:GODSEYE_WORKSPACE = 'C:\path\to\your\source'
docker compose up --build
```

Only the chosen workspace is mounted. Windows paths outside it are not available to container scanners. The build context excludes `.godseye`, local environments, credentials and `.env` files; those files are not baked into images. The chosen read-only scan mount still contains its own files, including hidden files, under the scanner's existing coverage policy.

Named volumes store dashboard inventory/evidence/cache, separate Python inventory, and Earth cache/logs. Native `.godseye` state is not imported automatically, and containers never write the native state directory. This avoids two runtimes writing one store. Normal `docker compose down` preserves the volumes.

Inside a container, `127.0.0.1` means that container. For an explicitly authorized host service, use `host.docker.internal` and its actual port where reachable. Container packaging does not give the scanner access to installed Windows applications, host-loopback-only services, radio hardware or other unmounted files. The optional external Nmap engine is not installed in these images; the existing native assessment remains available in `dashboard`.

## Frontend development outside Docker

The fully containerized setup needs no separate npm command. For dashboard hot reload against the running Compose backend:

```powershell
cd apps/web
npm ci
npm start
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). Its development proxy sends `/api` to the backend on port 8765. It translates only the two expected development origins and preserves the backend's cross-site and custom-header guards.

`npm run build` in `apps/web` creates production assets. It does not start a server. Compose performs that build itself and serves the assets through the backend. Earth's dependencies and supported Node runtime are handled by its image.

## Runtime boundaries

Services use non-root users, a read-only root filesystem, bounded temporary storage, dropped capabilities and explicit memory/CPU/process limits. They run as one backend process per state owner. No Docker socket, privileged mode, cloud credentials, external scanner bundle or shared writable Go/Python store is required.

If a listed port already belongs to a native instance, stop that instance or adjust the deployment deliberately. The launch will report a port conflict rather than replacing another process. The separate upstream Compose file under `apps/earth` is retained for provenance; the supported complete application entry point is the root `compose.yaml`.

## Executed verification

Verified on 19 October 2026 using Docker Desktop's Linux amd64 engine on Windows. The runtime versions are Go 1.27.2, Python 3.13.16 and Node 26.12.0. All three services built, started, became healthy and remained healthy after forced recreation. The source code remains on the default `main` branch.

| Check | Result |
| --- | --- |
| `docker compose config --quiet` | Pass |
| `docker compose up --build -d --wait` | All three containers healthy |
| Go backend tests during the Linux image build | All packages pass |
| Native Python behavior/parity tests | 134 pass, including wildcard-bind Host/Origin rejection |
| Dashboard unit tests and production build | 11 pass, build passes on host and inside Docker |
| Earth free-edition tests inside its Node container | 26 pass |
| Synthetic source scan and JSON/SARIF exports through both container APIs | Pass, one candidate found and value omitted from exports |
| Full backend catalog and structural recovery/import | 26 assessments, 14 formats; import and PNG byte-range recovery pass |
| Named-volume persistence after forced container recreation | Both inventories and saved evidence/downloads reopen correctly |
| Runtime permissions | Backend UID 10001, Earth UID 1000; attempted workspace write rejected, state write succeeds |
| `npm start` API proxy | Normal read/write requests pass; untrusted Origin, cross-site and missing-header requests rejected |
| Browser smoke | Full Workbench and its assessment selector render; Earth globe and public earthquake layer render |

Earth emitted two existing Cesium geometry warnings about terrain outlines/height references, with the globe rendering normally. Provider availability remains dependent on its public upstreams; the check does not claim every live feed was available. No target personal data or native state was used for container smoke tests.

For developers with host Python available, the reproducible smoke runner assumes the default repository workspace mount:

```powershell
python deploy/smoke.py exercise
docker compose up -d --force-recreate --wait
python deploy/smoke.py verify
```

Exercise creates clearly labelled synthetic assets and evidence. Their IDs are saved under ignored `.godseye/compose-smoke.json`; verify checks the same saved records after recreation. The runner never writes raw credentials to reports or uses an external scan target. It is separate from ordinary Compose startup.
