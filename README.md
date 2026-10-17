# God's Eye

A local defensive auditing dashboard and CLI, with a separate public-source World view. The source scanner runs offline; optional HTTPS checks and world feeds use the network. Original code and rules are Apache-2.0, with attributed third-party helpers under their own licenses. No account, subscription, API key or paid service is needed.

The complete God's Eye View source is now copied into `apps/earth` as a separate keyless Earth console with a minimal black interface. Open its [local console](http://127.0.0.1:4173/) for the full 3D globe, public-source layers, saved views, personal pins, weather inspection and map tools. The Excluded section lists disconnected paid and credential-dependent providers. The existing scanner, dashboard and compact World view remain available. See the [edition guide](docs/earth-edition.md) for exact scope and source/data attribution.

On Windows, build and start both workspaces with `pwsh -File scripts/start.ps1 -Build`. Later starts can omit `-Build`. The Earth process is separate from the Go dashboard and runs on loopback port 4173. Its active configuration never loads provider credentials. The full upstream source includes historical provider modules for provenance; they are disconnected from this edition.

## Run

### Local dashboard

Build the React/TypeScript frontend with Node.js 22.12 or newer, then serve it through Go:

```powershell
cd apps/web
npm ci
npm run build
cd ../..
go build -o bin/godseye.exe ./cmd/godseye
.\bin\godseye.exe serve --root .
```

Open `http://127.0.0.1:8765`. The Overview, Assets, Checks, Coverage and World view pages use the real backend. Source scans are restricted to the configured workspace. HTTPS checks inspect one explicitly authorized public endpoint, without crawling or following redirects. The source and web check modules are native code; no external pentesting tools are integrated.

World view provides an interactive vector globe, live public earthquake/natural-event layers, calculated space-station positions, a central-India aircraft feed, saved browser-local pins and GeoJSON export. It reuses two MIT source helpers from God's Eye View with attribution. It needs no paid API, API key or external map tiles. See [World view sources and limitations](docs/world-view.md) for exact coverage and data-license terms.

Inventory is saved in `.godseye/assets.json`. Check history lasts for the server session, capped at 20 runs. Export results before stopping the server. Do not put credentials in asset names or targets. This local server has no shared-user authentication and must not be exposed through a public reverse proxy.

Use `--port`, `--web` and `--state` to change the port, built-frontend directory and inventory directory. The default paths are relative to the launch directory. `npm run dev` is a frontend-only development server; use the Go-served production build for a fully connected dashboard.

### Command-line scan

Requires Go 1.25 or newer. The current implementation has been built and tested with Go 1.27.2 on Windows.

```powershell
go build -o bin/godseye.exe ./cmd/godseye
.\bin\godseye.exe scan --project my-project C:\path\to\source
.\bin\godseye.exe scan --format sarif --out findings.sarif C:\path\to\source
```

On Linux/macOS, build with `go build -o bin/godseye ./cmd/godseye` and run `./bin/godseye scan /path/to/source`. Flags must precede the directory argument. Reports go to stdout unless `--out` names a new file. Existing output files are never overwritten.

| Exit code | Meaning |
| --- | --- |
| 0 | Completed within configured coverage, no candidates found |
| 1 | Completed, credential candidates found |
| 2 | Invalid arguments, filesystem setup error, or output error |
| 3 | Incomplete coverage, exhausted limit, cancellation or timeout |

## Implemented

- Generated Go Protobuf message bindings for the canonical findings and telemetry contract.
- Two concurrent file workers by default, bounded channels, cancellation checks and input/output-count limits.
- Three original pattern rules for private-key markers, AWS access-key identifiers and GitHub token candidates. Matches require human verification; the tool does not test credentials against a service.
- Source locations, fingerprints independent of line numbers, redacted evidence, and explicit incomplete-scan status.
- Canonical Protobuf JSON findings inside a scan envelope and SARIF 2.1.0 reports.
- Offline operation, root-confined file opens, symlink exclusion, and report files created without overwriting existing files.
- A separate keyless World view with public-source geographic records, browser-local annotations and attributed source-code reuse.

The default limits are 10,000 files, 1 MiB per file, a 64 MiB input reservation budget, 1,000 findings and 30 seconds. `scan --help` lists the controls. The budget reserves each discovered file's size plus one byte for growth detection. Files that grow beyond that reservation are omitted with an explicit coverage gap.

## Coverage and limits

This is an early implementation, not the completed platform. The local dashboard server supports one active check at a time. It has no durable job queue, external plugin execution, gRPC server, SAST data-flow analysis, dependency auditing, runtime collection, VPN or proxy deployment yet. The generated schema does not mean all protocol validation and lifecycle behaviors are implemented.

Only UTF-8 text is inspected. Binary/non-UTF-8 content, unreadable or oversized files, and exhausted limits mark a scan incomplete. The directories `.git`, `node_modules`, `vendor`, `.venv`, `bin`, `reports`, `.godseye` and `dist` are policy exclusions and their counts are reported. Symlinks and special files are excluded. Git history, archives and `.gitignore` semantics are not implemented. Other hidden files, including `.env`, are scanned.

Scan an idle local checkout. The scanner confines opens with Go's `os.Root`, but does not create an immutable snapshot or sandbox a hostile, concurrently modified directory. Timeouts are cooperative and cannot interrupt a blocked operating-system filesystem call. Directory enumeration and the Go runtime are not subject to a hard memory sandbox. Fingerprints use rule, path and match ordinal; inserting another match of the same rule before an existing one can change its fingerprint.

Credential values and source excerpts are omitted from reports, but paths and project IDs are retained. A clean result means no supported patterns were found within the stated coverage, not that the project is secure.

## Development

```powershell
go test ./...
go vet ./...
go test -race ./...
```

Frontend checks run with `npm test` and `npm run build` inside `apps/web/`.

With the dashboard running, `pwsh -File scripts/smoke.ps1` exercises the real local API, synthetic detection, exports, cancellation, limits and overwrite protection. Add `-Website https://your-authorized-domain/` only when you want to check that explicitly authorized public HTTPS endpoint. See [live verification results](docs/live-verification-2026-10-16.md) for the recorded domain and local tests.

The race detector requires a supported C compiler on Windows. Protobuf bindings were generated using `protoc-gen-go v1.36.10` and the compiler bundled with `grpcio-tools 1.84.0`. See the generation header for the compiler version. Generate with `--go_out=. --go_opt=module=godseye` and `api/` as the source include root.

- [Architecture and planned monorepo](docs/architecture.md)
- [Plugin protocol and future validation requirements](docs/plugin-protocol.md)
- [Canonical Protobuf schema](api/godseye/v1/plugin.proto)
- [Open-source policy and licensing](docs/open-source.md)
- [Verification results and first scan benchmark](docs/verification.md)
- [Asset coverage, native capability plan and operating systems](docs/platform-scope.md)
- [God's Eye View repository review](docs/reference-review.md)
- [World view functionality, sources and attribution](docs/world-view.md)

The architecture separates live proxy/VPN traffic from audit workers. It does not promise universal anonymity or claim measured network performance.
