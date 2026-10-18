# Docker and local operation

Status: operating design for implementation. No Dockerfile, Compose configuration, Python server or changed launcher is created by this planning task. Commands below are future interfaces to implement and verify.

## Supported operating modes

| Mode | Intended use | Behavior and constraints |
| --- | --- | --- |
| Native Python on Windows | Primary parity target for the current user | Host filesystem, host DNS/trust configuration and host-loopback diagnostics remain available; prove reparse confinement |
| Native Python on Linux | Linux parity target | Descriptor-based confined scanning, normal host networking and process groups; real runtime tests required |
| Python in Docker Desktop/Linux containers | Reproducible packaged deployment and mounted-workspace scans | Container DNS, trust, filesystem and loopback differ from host; expose/document tested target scope |
| Separate native Earth | Initial Earth choice | Preserve existing Node middleware and local receiver behavior on 4173 |
| Optional containerized Earth | Later packaging option | Must preserve provider middleware and account for local receiver/network differences |

Native Python plus optional Docker is the recommendation. Docker is useful packaging, but it cannot make container loopback identical to Windows loopback. Docker Desktop should manage the optional Compose application; it is not required to use the product.

## Native Python operation

The implementation should supply these interfaces:

```text
godseye serve --root . --web apps/web/dist --state .godseye --port 8765
godseye scan --format json --project local <directory>
godseye lab catalog
godseye lab assess --tool cloudfox --authorized <template.json>
```

Keep Go-compatible CLI grammar. Provide a module entry for environments without the console shim, and a reproducible Python environment setup using the selected locked dependencies. The Windows launcher starts that environment's Python with a fully resolved path; it must not accidentally use a different global interpreter.

`scripts/start.ps1` should retain its frontend/Earth build steps while replacing the Go build/executable step with the Python environment/install step. Startup validates service identity, required capabilities and matching build ID before reuse. It rejects an unrelated/stale listener clearly. Do not automatically kill whatever occupies 8765 or 4173.

The current smoke script needs a Python CLI execution mode, explicit working directory and the same report/overwrite/exit-code assertions. Build assets and backend from the same release. An optional packaged Windows executable can be evaluated later; a Python environment is sufficient for first parity.

## Backend image

Use a Node build stage for `apps/web`, then a Python runtime stage with its exact image digest/patch locked at implementation time. Include built dashboard files, the Python wheel/package and required CA certificates. Keep application paths separate from writable state and scanned workspace.

Proposed container paths:

| Path | Access | Purpose |
| --- | --- | --- |
| `/app` | Read-only at runtime | Backend package and built dashboard |
| `/workspace` | Read-only bind mount | User-selected scan workspace |
| `/state` | Read/write named volume or dedicated bind mount | Inventory, normalized evidence and World cache |
| `/tmp` | Bounded temporary filesystem | Owned temporary process/analysis files |

Bind mounting data gives the container access to that host path. Use a narrowly selected read-only workspace mount and a separate state directory. Do not mount the entire drive, home directory or Docker socket. [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/).

Run as a non-root user, drop capabilities, use a read-only root filesystem, enable an init process, bound memory/CPU/PIDs and use explicit stop grace. Proposed initial local budget is 2 CPUs, 1 GiB memory and 128 PIDs, subject to the five-job stress test. These are starting configuration targets, not measured requirements or a universal guarantee. If the budget cannot support existing admission groups, optimize or revise the documented deployment minimum before shipping rather than silently lowering capacity.

One Uvicorn worker must bind `0.0.0.0:8765` inside its container so Docker can forward traffic. Publish only `127.0.0.1:8765:8765` on the host. Keep application validation against the explicit external authority `127.0.0.1:8765`; accepting all Hosts because the internal bind is wildcard would remove the existing boundary. Do not trust forwarded host headers by default. Internal healthchecks must send the configured allowed Host too.

Native default binding stays `127.0.0.1`; container wildcard bind is an explicit deployment configuration. The frontend and API remain one origin in both modes. React needs no new CORS allowances.

## Networking and host targets

| Target | Native interpretation | Container interpretation |
| --- | --- | --- |
| `127.0.0.1` | User's host machine | The backend container |
| Another Compose service name | Usually not resolvable outside Docker | That service on the Compose network |
| `host.docker.internal` | Docker-provided hostname may vary by environment | Docker Desktop route to host services; validate actual binding/firewall reachability |
| LAN/private IP | Host routing/firewall | Docker VM/bridge routing/firewall; must be tested |
| Public hostname | Host DNS/trust/network path | Container DNS/CA/network path |

Never silently replace a user-supplied target. If a user selects host-local diagnostics while running in Docker, explain the actual container scope and require an explicit host target appropriate to that mode. A host service bound only to 127.0.0.1 may not be reachable through the Docker host address. Keep native mode for exact host-loopback behavior. [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/).

Test IPv6, VPN-connected hosts, custom DNS, firewalls and CA stores where advertised. A container cannot inherit the Windows certificate store or DNS behavior merely by using the same application code. Add explicit CA configuration without disabling verification. Do not use privileged mode or mount raw interfaces to compensate; current functionality does not require radio or live packet capture.

The fixed regional aircraft feed and other public World feeds still use their configured public URLs. Their outbound networking must obey the fixed-provider adapter, not a user URL proxy.

## Workspace and state mapping

CLI/container examples must explain that `--root /workspace` limits scanning to the mounted workspace. The API `workspace` value reflects the container root; record this expected display difference. Persisted source asset targets are relative, so keep relative structure consistent. Do not rewrite existing host path data indiscriminately.

Windows bind mount performance and filesystem metadata differ from Linux storage. Benchmark the actual mounted checkout, including copied Earth datasets, and retain partial-coverage reporting for binary/oversized files. Do not exclude new directories just to improve benchmark numbers.

A named state volume survives ordinary container recreation. Removing the volume is data deletion and is never part of normal upgrades. Backup/export uses the documented state-copy procedure. Permission errors or invalid persisted reports must prevent a false clean startup.

Go/Python comparison uses separate directories/volumes and ports. Production uses exactly one writer. The active-state volume name/path is recorded in the installation manifest, not inferred from a temporary container name.

## Compose and health

Compose should define one backend service; Earth is an optional separate service/profile. No Redis/Postgres is required for the parity release. Include the service build ID, expected capabilities, volumes, loopback publication, restart policy, resources and a healthcheck.

Health should confirm service readiness after stores are validated. A ready process with unavailable optional upstream data remains usable; provider failure belongs in the feed response rather than restarting the entire app. A health failure due to invalid state must remain visible and must not trigger destructive state resets.

If another service depends on backend readiness, use health-based startup dependency rather than assuming container creation means readiness. [Compose startup order](https://docs.docker.com/compose/how-tos/startup-order/).

The image must include the complete selected Python package and dependencies; a Docker build that happens to find host files is not reproducible. The `.dockerignore` must exclude `.git`, `.godseye`, `.env*` except approved examples, credentials, binaries, caches, node_modules and unrelated large datasets from the backend context. Build-only Node dependencies must not remain in the backend runtime image.

## Optional installed Nmap

Native mode detects a compatible installed `nmap` using a controlled PATH. Container mode detects it inside the image/container, not on Windows. Base image omission must show `engineAvailable:false` while native Python Nmap assessments remain functional.

If offering an optional engine image, pin the engine version, review redistribution terms, preserve fixed non-shell argv and allowlisted execution, and validate it with controlled local targets. Do not add tshark/Foremost execution merely because their names exist in the old generic helper allowlist. No host PATH, arbitrary executable path or user command string enters the request contract.

## Earth packaging boundary

Earth's existing root `vite.config.js` registers provider middleware in both dev and preview. Preserve that behavior, its current free-edition exclusions and source/data attribution. A static nginx copy of `dist` would break middleware-backed provider calls.

Keeping Earth native preserves local receiver semantics during the Go migration. If a separate Node container is later built, configure internal `0.0.0.0:4173` and host `127.0.0.1:4173:4173`, carry the current plugins, and test all active proxy families and intended excluded routes. Verify its allowed-host behavior and local receiver targets. This is a packaging change with its own acceptance evidence, not an automatic consequence of a successful Python backend image.

## Operating acceptance

Before documenting a mode as supported, prove clean install, start, capability handshake, scan of the intended workspace, explicit local/public target semantics, evidence persistence after restart, read-only mount enforcement, cancellation, same-origin frontend behavior and graceful stop. A successful `docker build` alone establishes none of these.
