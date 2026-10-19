# God's Eye

Start the complete containerized application from this directory:

```powershell
docker compose up --build
```

Open the [security dashboard](http://127.0.0.1:8765) and [Earth console](http://127.0.0.1:4173). Both frontends build inside Docker. The [Python candidate](http://127.0.0.1:8875) starts separately while the remaining backend migration continues. See [Docker setup and local frontend development](documentation/10-docker-compose.md).

Earth requests high-performance graphics for its WebGL renderers. See [GPU setup and workload coverage](documentation/11-gpu-acceleration.md) to prefer your dedicated GPU on Windows and check the actual device in Earth > Options > Graphics.

The [Python backend migration](documentation/08-implementation-ledger.md) has started. Its isolated candidate supports inventory, source scans with JSON/SARIF exports, and HTTPS response checks. Run `./scripts/start-python.ps1 -Build -Port 8876` with PowerShell 7.4 or newer on Windows. The remaining backend features and default launcher still use Go until their parity gates pass. See [Python setup](backend/README.md).

Version 0.4 adds [26 native assessment modules](docs/assessment-modules.md) to Workbench, including scoped web crawling, exposure rules, API contract review, cloud-template analysis, directory paths and extended capture analysis. Nmap has an optional installed-engine adapter. The module names identify related workflows; they do not mean all 26 external suites are installed or fully reproduced.

A local defensive auditing dashboard and CLI, with a separate public-source Earth console. The source scanner runs offline; optional HTTPS checks and Earth feeds use the network. Original code and rules are Apache-2.0, with attributed third-party helpers under their own licenses. No account, subscription, API key or paid service is needed.

The complete God's Eye View source is adapted in `apps/earth` as a keyless Earth console with a minimal black interface. Open its [local console](http://127.0.0.1:4173/) for the 3D globe, public-source layers, saved views, personal pins, weather inspection and map tools. NASA EONET natural events have moved here from the retired World view. The Excluded section lists disconnected paid and credential-dependent providers. See the [edition guide](docs/earth-edition.md) for exact scope and source/data attribution.

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

Open `http://127.0.0.1:8765`. The default Investigate screen guides you through adding inputs, confirming their types, reviewing selected checks and reading results. Paste one input per line or attach photos and evidence files. The plan selects supported checks from the confirmed context and shows manual-review and unsupported inputs explicitly. See the [investigation guide](documentation/12-guided-investigations.md) for the exact routing and retention rules.

Saved results contains normalized analysis reports and session-only source/HTTPS checks. Advanced contains the specialist workbench, asset inventory and tool coverage. The workbench retains assessment modules, report imports, TCP/DNS diagnostics, offline capture and file analysis, cloud configuration review, data recipes and evidence graphs. External engines are not bundled; Advanced > Specialist tools > Assessments can explicitly invoke an installed Nmap engine. See the [assessment guide](docs/assessment-modules.md) and [workbench guide](docs/tool-workbench.md).

Source scans stay inside the configured workspace. The HTTPS response check inspects one authorized public endpoint without crawling or following redirects. The separately selected exposure review fetches that URL; the optional linked-page review crawls up to eight same-origin pages. Earth console retains its separate application.

Earth console includes USGS earthquakes, NASA EONET natural events, calculated satellite positions and viewport-scoped ADSB.lol aircraft reports. Enable Natural events in Layers, then expand Natural event records to inspect categories, observation dates, coordinates and provider links or jump to a reported point.

Inventory is saved in `.godseye/assets.json`. Source/HTTPS check history lasts for the server session, capped at 20 runs. Workbench evidence persists in `.godseye/evidence/`, retaining the newest 20 normalized reports. Raw uploads are not saved. Export important reports before retention removes older evidence. Do not put credentials in asset names or targets. This local server has no shared-user authentication and must not be exposed through a public reverse proxy.

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
- A keyless Earth console with public-source geographic records, NASA natural events, saved views, browser-local pins and attributed source-code reuse.
- A security workbench with 14 report import formats, scoped TCP/DNS diagnostics, classic Ethernet PCAP metadata, file recovery candidates, static AWS IAM review, durable normalized evidence and per-report relationship graphs.
- Eighteen browser-local recipe operations using two attributed CyberChef helpers, plus nine Sherlock URL templates for manual profile review. These are explicit subsets, not full replacements for those products.

The default limits are 10,000 files, 1 MiB per file, a 64 MiB input reservation budget, 1,000 findings and 30 seconds. `scan --help` lists the controls. The budget reserves each discovered file's size plus one byte for growth detection. Files that grow beyond that reservation are omitted with an explicit coverage gap.

## Coverage and limits

This is an early implementation, not the completed platform. The local dashboard supports one source/HTTPS check and up to two bounded workbench operations at a time. It has no durable job queue, external plugin execution, gRPC server, SAST data-flow analysis, dependency auditing, runtime collection, VPN or proxy deployment yet. Workbench report persistence does not persist the source/HTTPS run history. The generated schema does not mean all protocol validation and lifecycle behaviors are implemented.

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
- [Earth console sources and operating limits](docs/earth-edition.md)
- [Security workbench, 26-tool coverage and source reuse](docs/tool-workbench.md)

The architecture separates live proxy/VPN traffic from audit workers. It does not promise universal anonymity or claim measured network performance.
