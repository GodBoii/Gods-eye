# Ubuntu deployment behind Cloudflare Access

The deployment uses the existing `ubuntu-server` SSH host and a checkout at
`/home/arun/Gods-eye` on `main`. Existing applications keep their ports.

```sh
cd /home/arun/Gods-eye
docker compose -f compose.yaml -f deploy/compose.ubuntu.yaml up --build -d --wait
docker compose -f compose.yaml -f deploy/compose.ubuntu.yaml ps
```

The Docker daemon must start at boot. Containers use `restart: unless-stopped`.
Named volumes retain inventory, evidence and Earth cache across recreation.
Keep backups of the state volumes; do not use `down -v` unless deleting state
is intended. Source scans inspect the Ubuntu workspace, not the remote browser's
filesystem.

| Host loopback port | Service |
| --- | --- |
| 18765 | Full dashboard and Go backend, internal port 8765 |
| 14173 | Earth console, internal port 4173 |
| 18875 | Python migration candidate, internal port 8875 |
| 18080 | Domain-aware Cloudflare gateway |

## Cloudflare setup

The gateway does not implement login or validate Cloudflare Access tokens.
Create Access applications **before** publishing either hostname. Keep all
origin ports on loopback and use the host's existing `ubuntu-ssh` tunnel.
The tunnel process must run on the host so that its `127.0.0.1` reaches the
host port. A bridge-network Docker tunnel has its own loopback address.

1. In Zero Trust > Access controls > Applications, add a self-hosted application
   covering `godseye.polycognition.online` and `earth.polycognition.online`, or
   create one application for each hostname.
2. Add an Allow policy for the owner's exact email address. Use the email
   one-time PIN login method or an existing identity provider. Do not use an
   Everyone, Bypass, or public policy. Other users should have no matching Allow
   policy.
3. In Networking > Tunnels > ubuntu-ssh > Routes, add these published
   applications, leaving existing routes unchanged:

   | Hostname | Service type | Origin URL |
   | --- | --- | --- |
   | godseye.polycognition.online | HTTP | 127.0.0.1:18080 |
   | earth.polycognition.online | HTTP | 127.0.0.1:18080 |

4. Preserve the incoming HTTP Host header. Do not set an HTTP Host Header
   override on either route. The gateway selects the upstream using the domain.
5. Verify both public URLs from a signed-out browser. They must require Access
   login. After login, verify dashboard reads and writes and Earth rendering.

Cloudflare creates the route's DNS record when the published application is
saved. No new tunnel token or inbound firewall opening is needed.

The gateway translates only each site's exact HTTPS Origin to its expected
internal HTTP Origin. Unknown origins and hosts are rejected. Backend
cross-site and custom-request-header checks remain active.

The dashboard's existing Earth link points to local port 4173. For this
deployment, open `https://earth.polycognition.online` directly.

## Local verification before publishing

```sh
curl -fsS http://127.0.0.1:18080/healthz
curl -fsS -H 'Host: godseye.polycognition.online' http://127.0.0.1:18080/api/health
curl -fsS -H 'Host: earth.polycognition.online' http://127.0.0.1:18080/ -o /dev/null
```

An unexpected Host or an Origin such as `https://untrusted.example` must return
403. These local checks do not prove Cloudflare Access enforcement; complete
the signed-out public checks after configuring Cloudflare.
