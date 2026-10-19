# Python implementation ledger

Updated 19 October 2026. The migration has started. The default application remains on Go while the Python candidate implements inventory, source scanning and HTTPS response checks. Go removal and full cutover have not happened. The complete current application now has a tested root Docker Compose setup; see [container operation](10-docker-compose.md).

## Baseline and isolation

Implementation starts at `9482391`, after the planning commits. `git diff --exit-code 4d27de83ad087703b197432ccbf2870a5ea6164c 9482391 -- cmd internal api apps` passed, confirming no application-source drift from the planned baseline. The working tree was clean before implementation.

The first foundation batch was pushed through `bd324ef`. The tested HTTPS/build-lifetime code batch was pushed through `1b8bff999292c9a5774445022391a7583c5c2993`. Every changed file has its own commit, as required. Cross-file changes were tested as complete batches; intermediate commits are not separate migration releases. The running candidate's health records its source build identity independently of these documentation-only follow-ups.

The baseline was rebuilt as ignored `bin/godseye-go-baseline.exe`, using Go 1.27.2 on Windows. Its SHA256 is `df85bffbbdd867ab10e4891e7431ae8f8c0045cccf916e58e3d4f43ac2096399`; it reports version 0.4.0. Git retains the release source and the existing built executables remain untouched.

Existing Go installations on ports 8766 and 8767 use distinct state directories. They were inspected by process path and command line and left running. Python was started on port 8876 with `.godseye/python-preview`, separate from those installations and the root inventory/evidence. Automated tests use temporary synthetic workspaces and stores, including separate copies for bidirectional inventory compatibility. No live state was pruned or rewritten.

The effective catalog was captured with `bin/godseye-go-baseline.exe lab catalog` in `backend/tests/fixtures/go-v0.4/catalog.json`. It records all 26 tool descriptions, 26 assessments and 14 formats. Installed Nmap was unavailable. Catalog capture does not count as Python implementation.

## Implemented candidate

- Installable Python 3.13 package, module/console entry, typed configuration and universal hash-locked runtime/development dependencies.
- FastAPI application lifecycle, disabled interactive docs, exact Host/Origin/fetch-site/mutation-header guards and legacy security response headers.
- Bounded JSON request envelopes with unknown-field/type rejection, Go-compatible missing/null scalar defaults and case-insensitive field names. Validation errors omit input values.
- Compatible inventory storage with UTF-8 byte limits, 200-asset limit, atomic replacement and publish-after-save semantics. An OS-owned lock excludes other Python writers.
- All three source patterns, exact ruleset/fingerprint hash framing, source locations, redaction, bounded workers/reads/reservations, exclusions and partial-coverage reporting.
- Python Protobuf bindings and type stubs generated from the unchanged schema with grpcio-tools 1.84.0. Canonical ProtoJSON preserves enums, uint64 strings, optional fields and oneofs.
- Source JSON/SARIF exports and scan CLI exit codes, exclusive output files and Go duration units.
- Dashboard source job admission, status polling, cancellation, retention and downloads. A spawned Python child owns scanner computation; the parent awaits cleanup before releasing admission.
- HTTPS HEAD checks with first-address DNS pinning, verified TLS/SNI, explicit public-address exclusions, no proxy/cookies/redirects, bounded HTTP/1.1 headers and preserved review counts. The TLS stream exposes the verified certificate expiry; h11 handles HTTP parsing. This implements HEAD only. The proposed aiohttp GET adapters, DNS records and native diagnostic TLS still need separate acceptance.
- A separate Windows preview launcher with a Python runtime/capability check. It cannot replace port 8765 or the root Go state.

Python health advertises `inventory-v1`, `source-scans-v1` and `https-checks-v1`. It deliberately does not advertise `workbench-v1` or `tool-assessments-v1` before their implementations exist. There is no Go subprocess fallback. A source build identifier captured at startup prevents the launcher from reusing a stale candidate after files change.

## Verification evidence

Reference environment: Windows, Python 3.13.3, Go 1.27.2, Node 22.15.0. Exact Python dependencies and hashes are in `backend/requirements*.lock`. Tests below were executed during implementation, rather than copied from historical reports.

| Requirement | Command or case | Actual result | Scope and remaining gap |
| --- | --- | --- | --- |
| Existing backend baseline | Local Go toolchain `go test -count=1 ./...` and `go vet ./...` | Pass | Cache bypassed for the final baseline rerun; race detector and Linux runtime not rerun |
| React dashboard regression | `npm test` and `npm run build` in `apps/web` | 11 pass, build pass | Existing UI code unchanged |
| Earth free edition regression | `npm run test:free` in `apps/earth` | 26 pass | Initial attempt used a nonexistent `test:free-edition` script, then corrected to the actual script |
| Python behavior and public-interface parity | `GODSEYE_GO_BASELINE` set, `python -m pytest backend/tests -q` | 133 pass | Includes 10 CLI parity cases, two real-listener parity cases, real pinned TLS and HTTPS review cases; not all 156 Go test behaviors transferred |
| Scan JSON/SARIF semantic parity | Clean/candidate/binary/file-count/file-byte fixtures, Unicode paths and HTML/U+2028 hash inputs | Pass | Only random IDs and timestamps normalized; fingerprints, producer digests, arrays, errors and gaps compared exactly |
| Source scanner limits/privacy | `test_scanner.py`, CLI tests | Pass | Byte/record limits, pre-cancel, UTF-8/binary handling and credential omission; saturated concurrent retention and performance need broader comparison |
| Root boundary prototype | Real Windows junction rejection, directory rename denial while pinned, child-name rejection, growth omission | Pass | Uses read handles, no reparse following and final-handle path checks before content reads; full adversarial platform matrix remains unverified |
| CLI and report behavior | `test_cli_parity.py` | Pass | 0/1/2/3 exits, Go duration units, flag ordering and no overwrite |
| Inventory both directions | Go creates copied store, Python reopens/mutates, copied Python store reopens in Go | Pass | Existing IDs and timestamps retained; real user store never used |
| Atomic failure | Inject failed replace against a real temporary file | Pass | Prior bytes and in-memory assets retained; temporary file removed |
| State ownership | Separate-process lock exclusion and release on process exit | Pass | Coordinates Python only; isolated state is still mandatory versus Go |
| HTTP guards and errors | Real Go/Python listeners plus ASGI request tests | Pass | 19 boundary cases, legacy plain-text guard failures, JSON errors and security headers |
| Job lifetime | Actual spawned scanner, second request 409, immediate cancel, terminal status and readmission | Pass | Child absent before admission release; future installed-engine descendants not implemented |
| HTTPS substitution | Real local trusted TLS listener, wrong-name/untrusted certificates, forbidden second DNS lookup, mixed answer rejection and hostile proxy environment | Pass | First-address HEAD and SNI verified. No public-network test substitutes for these stable cases. |
| Browser smoke | Existing built dashboard against Python on 8876 | Partial | Overview, inventory form and live HTTPS evidence render; no captured console errors. Workbench initially shows expected missing-route error, and static UI version/capability labels still describe the original release. Full UI parity and mobile verification remain pending. |
| Static/type/format checks | Ruff check/format, strict mypy for Windows and Linux platforms | Pass | Linux type checking is not Linux runtime testing |
| Schema generation | `python backend/tools/generate_protocol.py --check` | Pass | Compiler is build-only; schema is unchanged |
| Package integrity | Hash-locked dependency installation and `pip check` | Pass | Native Windows development and fresh runtime environments |
| Fresh no-Go runtime | New virtual environment, hash-locked runtime dependencies, wheel built from `./backend`, version and synthetic scan from an external temporary directory | Pass | Go absent from PATH; scan exited 1 with one redacted candidate. This proves only the implemented source/inventory subset, not full no-Go release acceptance. |
| Docker availability | `docker version` | Engine unavailable | Desktop CLI installed; Linux engine pipe absent. No image execution or container claim |

The initial tests caught and fixed Windows stdout encoding and ineffective metadata-only directory pinning. The latter required requesting read access for directory handles. Tests also exposed overly long generated pytest case names for the oversized fixture; those now use short explicit IDs. No failure was reclassified as a pass by dropping required output fields.

## Phase status

| Planned phase | Status |
| --- | --- |
| 0. Recoverable baseline | Baseline build, suites, synthetic catalog and CLI/HTTP comparisons implemented. Live-state backup/restore rehearsal and full performance corpus remain open. |
| 1. Difficult substitutions | Windows filesystem and spawned scanner prototypes implemented. Full Windows/Linux filesystem matrix, DNS pinning, TLS and installed-engine tree cleanup remain open. |
| 2. Python foundation | Package, boundary middleware, lifecycle and tested request handling implemented. Full subsystem wiring remains open. |
| 3. Contracts and stores | Protocol and inventory implemented. Evidence normalization/store, World cache and their bidirectional compatibility remain open. |
| 4. Scanner and reports | Initial scanner/CLI/exporter implemented and compared. Full platform, malformed/growth/saturation and performance acceptance remain open. |
| 5. Network foundations | Public HEAD policy/transport and HTTPS evaluation implemented. Generic TCP/DNS/GET and native diagnostic certificate observation remain pending. |
| 6. Imports and local analysis | Pending |
| 7. Assessment modules | Pending, all 26 rows below |
| 8. Dashboard coordinator/API | Source/HTTPS runs and inventory implemented. Lab and assessment groups remain open. |
| 9. World/Earth | Earth regression suite passes. Python World feeds and full browser verification pending. |
| 10. Native/Docker packaging | Windows candidate launcher and root Compose packaging implemented. Current Go dashboard, separate Python candidate and keyless Earth built and tested on Linux containers. Python-only feature acceptance and the full platform matrix remain open. |
| 11. Release validation | Pending |
| 12. Default cutover | Pending |
| 13. Go retirement | Pending, explicitly gated by feature parity |

## Assessment transfer checklist

Each module needs its existing behavior tests, Python dispatch, API/CLI access, scope/limit/privacy cases and persisted report reload before acceptance. Every row currently remains unported.

| Module | Python status | Baseline definition |
| --- | --- | --- |
| Nmap | Pending | Captured effective capability and original tests |
| Hashcat | Pending | Captured effective capability and original tests |
| CyberChef | Pending | Captured effective capability and original tests |
| CloudFox | Pending | Captured effective capability and original tests |
| recon-ng | Pending | Captured effective capability and original tests |
| Sherlock | Pending | Captured effective capability and original tests |
| SpiderFoot | Pending | Captured effective capability and original tests |
| BBOT | Pending | Captured effective capability and original tests |
| Shodan | Pending | Captured effective capability and original tests |
| Maltego | Pending | Captured effective capability and original tests |
| BloodHound | Pending | Captured effective capability and original tests |
| Burp | Pending | Captured effective capability and original tests |
| Caido | Pending | Captured effective capability and original tests |
| Metasploit | Pending | Captured effective capability and original tests |
| Foremost | Pending | Captured effective capability and original tests |
| Wireshark | Pending | Captured effective capability and original tests |
| Aircrack | Pending | Captured effective capability and original tests |
| Airgorah | Pending | Captured effective capability and original tests |
| hping3 | Pending | Captured effective capability and original tests |
| Netcat | Pending | Captured effective capability and original tests |
| spiderdomain | Pending | Captured effective capability and original tests |
| passive-recon | Pending | Captured effective capability and original tests |
| sqlmap | Pending | Captured effective capability and original tests |
| Evilginx defenses | Pending | Captured effective capability and original tests |
| Nuclei | Pending | Captured effective capability and original tests |
| Skipfish | Pending | Captured effective capability and original tests |

## Authorized final verification request

The user supplied personal identifiers, a user-owned HTTPS website and an installed desktop app for final functional/security verification. Those values must remain in ignored local artifacts and must not enter test fixtures, commits or public reports. Preliminary target observations now live in ignored `.godseye/private-validation/verification.md` and `observations.json`. The website's one-response HTTPS review completed. Selected packaged desktop source was scanned and manually reviewed. This is not the requested final all-feature audit, which remains pending the remaining migration and suitable module inputs. Original desktop source/backend location was requested; installed files were not modified. Personal identifiers were not submitted to third-party lookup services.

The HTTPS batch also fixed a Windows process-lifetime test failure. Terminating a virtual-environment redirector could return before the real server released its file lock. Real-listener tests and the launcher now bypass that redirector using the same environment mechanism as CPython's Windows multiprocessing launcher. State-copy parity then passed. The launcher reports the actual server PID.

Next implementation work is evidence contracts/storage, remaining network adapters, imports/local analysis and the individually accepted assessments. The existing working Go release remains the comparison implementation throughout that work. Removing it now would drop supported features.

## Container packaging, 19 October 2026

The root `docker compose up --build` starts the full Go-served dashboard on 8765, the separate Python candidate on 8875, and the Node Earth console on 4173. Both frontends build inside Docker. There is no per-request Go fallback in the Python service, and each backend has an independent named state volume. Native state and existing native listeners were left intact.

The first packaging code batch was pushed through `be50beb`, one file per commit. Backend wildcard binding is explicit through `--bind`; the accepted HTTP authority, Origin and mutation-header guards remain enforced. The source workspace is read-only, images exclude private/local state, all services use non-root users and the host publications are loopback-only.

Docker Desktop's engine was started for this task. Image builds, service health, source scans/exports, import/recovery, read-only mount enforcement and inventory/evidence reopening after recreation passed. All Go tests passed inside the Linux build stage. Native Python verification now has 134 passing tests, and Earth's 26 free-edition tests pass inside its Node container. The added `npm start` dashboard proxy was exercised against the Compose backend, including rejected untrusted requests. Browser verification confirmed full Workbench and the Earth globe rendering.

These checks supersede the earlier Docker-engine-unavailable observation for this packaging task. They accept the currently implemented container modes, not the unported Python modules or the complete migration release. Detailed commands and limits are recorded in the [Compose guide](10-docker-compose.md).
