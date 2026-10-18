# Step-by-step implementation plan

This plan authorizes no claim of completed migration. Each phase has deliverables and an acceptance gate. Implement in the order below; a failed gate keeps the Go service as the normal working backend. All new planning and migration records belong in `documentation`.

## Phase 0: establish a recoverable baseline

1. Recheck repository instructions, branch, dirty files and the baseline commit recorded in [the index](07-source-and-test-index.md). Preserve unrelated user changes.
2. Record build/version, frontend dependency locks, Go toolchain and every application entry point. Identify running instances by executable, port and configured state directory. Do not stop them for inspection.
3. Use an isolated state copy and alternate ports for all migration experiments. Never let Go and Python write the same state directory at the same time.
4. Run the Go unit/integration suite, vet, dashboard tests/build and selected Earth free-edition tests. Record exact commands, environment and results. Record unavailable checks honestly.
5. Capture synthetic API/CLI fixtures, catalog/capability JSON, scan exports and file formats. Inject fixed time/IDs at test boundaries where possible. Do not put live uploads, credentials, private paths or raw existing evidence into Git fixtures.
6. Copy representative non-sensitive legacy inventory/evidence/cache into fixture stores. Include corrupt, oversized and over-retention cases. Record the original release commit and recoverable artifacts.

Deliverables: a baseline evidence ledger, fixture manifest, reproducible Go build and state backup procedure. Gate: normal workflows and known limitations are reproduced, and the rollback artifact can start against an isolated state copy. If baseline failures exist, classify them before porting.

## Phase 1: prove the difficult Python substitutions

1. Prototype confined scan opens on Windows and Linux. Exercise symlinks, junctions, reparse points, directory swaps, nonregular files, Unicode/drive/UNC paths and file growth. Compare with Go's actual behavior. Do not accept `resolve()` followed by unrestricted `open()` as equivalent.
2. Prototype custom DNS resolution and pinned async HTTP dialing. Check IPv4/IPv6, mapped addresses, mixed allowed/disallowed answers, TLS SNI/hostname, no redirects, proxy environment isolation, chunked/compressed body limits and cancellation.
3. Prototype native Nmap certificate observation/verification using the proposed Python stack. Check valid, untrusted, expired, wrong-name and intermediate-chain fixtures with the intended trust stores. Preserve both evidence and verification outcome.
4. Prototype spawned child jobs on Windows and Linux with bounded IPC. Cancel blocked/CPU work, kill descendants when needed, reject late completion and release admission exactly once.
5. Generate Python Protobuf types from the unchanged schema. Check Go/Python binary and ProtoJSON fixtures, enums, uint64 strings, optional positions, timestamps and oneofs.
6. Verify that the chosen packages install cleanly on both platforms. Select the exact Python patch and compatible versions, rather than guessing a package lock in documentation.

Deliverables: small disposable test probes promoted into meaningful platform integration tests, a dependency decision record and documented remaining gaps. Gate: filesystem, network/TLS and job lifetime facts are proved. Failure blocks the relevant platform or module from being declared migrated; it does not justify a hidden Go fallback.

## Phase 2: create the Python foundation

1. Add `backend/pyproject.toml`, reproducible runtime/development lock files, console entry point, package discovery and pytest/lint/type-check configuration.
2. Add typed configuration with command flags taking explicit precedence over environment/defaults. Validate workspace, state and web paths once. Keep native defaults compatible; use explicit different container defaults.
3. Implement the application factory/lifespan, injected clock/ID generators, redacted error taxonomy and structured logging.
4. Implement strict request envelope DTOs, legacy missing/null behavior, camelCase output serializers and legacy HTTP error translation.
5. Add the health/capability contract, then Host/Origin/fetch-site/header guards and security response headers before exposing mutation routes.
6. Add route/method/static fallback tests. Keep interactive FastAPI docs disabled by default or explicitly local/dev-only; they are not required product routes.

Deliverables: installable package with validated health/middleware behavior. Gate: the new shell rejects prohibited requests like Go and has no import-time network/process side effects. It cannot claim scanning capability before that implementation exists.

## Phase 3: transfer contracts and compatible stores

1. Generate Python Protobuf bindings with a pinned generator and descriptor verification. Preserve `.proto` field numbers/package and optionality. Keep generation build-only.
2. Implement report DTOs, text sanitation, URL target redaction, graph/finding ID formulas, array defaults, collection caps and gap deduplication.
3. Implement atomic inventory reads/writes with current UTF-8 byte limits and 200-asset cap. Preserve error-on-invalid-startup and write-before-memory-commit behavior.
4. Implement evidence reopen/validation/retention and 26-character IDs. Validate all matching files before sorting/trimming. Keep no raw-input persistence.
5. Implement compatible World cache serialization and tolerant invalid-cache loading.
6. Add a per-state-directory single-instance writer lock and crash cleanup that relies on OS lock ownership rather than stale PID existence alone.
7. Prove Go-read/Python-read compatibility in both directions on copied synthetic stores. Test interrupted writes, write failures and permissions.

Deliverables: shared serializers and stores independent of FastAPI. Gate: no legacy data rewrite is needed for startup, deterministic IDs match vectors, and a new Python report is readable by the rollback implementation.

## Phase 4: port the scanner, report exporter and scan CLI

1. Port exact byte patterns, literal-marker prefilters and ruleset digest framing. Use fixture vectors for ASCII word boundaries and Unicode-adjacent bytes.
2. Port confined directory traversal, exclusions, per-file/total reservations, growth checks, binary/UTF-8 handling and 1-based line accounting.
3. Port bounded file-worker behavior and cancellation/limit handling. Keep sorted findings/gaps and explicit partial coverage.
4. Implement scan `Result`, generated Protobuf findings, exact v1 fingerprints and the normal JSON envelope.
5. Port source-only SARIF exporter and validate against a pinned official schema fixture without making tests depend on live schema downloads.
6. Implement `scan` CLI flags, Go duration compatibility, stdout/stderr, exclusive `--out`, exit 0/1/2/3 and signals. Add `version`.
7. Compare complete/saturated/binary/oversized/unreadable/symlink/cancelled fixtures. Benchmark the same input corpus and worker limits as Go.

Deliverables: fully Python scanner/CLI/exporters. Gate: all `secrets`, `report` and scan CLI behavior cases transfer, no raw credentials appear in reports/errors/logs, and no Go runtime is invoked.

## Phase 5: port network foundations and simple diagnostics

1. Implement explicit public-HEAD, diagnostic/private-target and fixed-provider address policies. Copy the intended CIDR exclusions and test IPv4-mapped IPv6. Do not depend solely on Python `ipaddress.is_global`, whose classification may differ.
2. Port validated hostname/URL grammar, DNS pinning, TLS settings and response limits. Separate logical hostname from socket destination.
3. Port dashboard HTTPS HEAD checks and evaluation, including certificate expiry, source-specific CSP applicability, no redirects and `reviewCount`.
4. Port basic TCP explicit-port validation, four-way bounded work, first-address semantics, timing and incomplete states.
5. Port DNS A/AAAA, NS, MX, TXT/SPF and DMARC behavior with no-record versus resolver-failure distinctions. Preserve current `limited:true` on collection errors.
6. Add deterministic local DNS, TCP, HTTP and TLS fixtures. Any external live smoke is explicit and low-volume; it is supplementary to stable tests.

Deliverables: shared network services usable by CLI/routes/assessments. Gate: policy rejection and failure semantics pass before enabling active modules.

## Phase 6: port generic imports and local analysis

1. Port format registry and bounded JSON object/array/JSONL readers, safe XML and CSV readers. Keep per-format schemas and supported version checks.
2. Transfer Nmap/Metasploit/Burp XML importers, then Nuclei/HAR/Shodan/BBOT/BloodHound/TShark JSON importers and the five CSV formats. Mark each format accepted only after its entire case set passes.
3. Port generic IAM static review, file MIME/hash/entropy/signature recovery and classic Ethernet PCAP. Preserve generic behavior separately from new assessment-specific parsers.
4. Test malformed trailing input, HTML in place of XML/JSON, huge record counts, false matches, unsupported fields, out-of-scope entities and secret omission.
5. Implement lab `catalog`, `import`, `file`, `pcap`, `iam`, `tcp`, `dns` commands with matching flags, bounds, new-file output and exit codes.

Deliverables: all 14 imports plus current generic CLI workflows. Gate: normalized report structures, identities and retained fields match Go fixtures; collection limits are enforced before large retained allocations.

## Phase 7: port the 26 assessment modules in dependency order

Keep one visible parity checklist row per module. Each row requires its module source/test transfer, positive/negative result fixture, scope/limit/privacy cases, shared CLI dispatch, API dispatch and persisted report reload. Do not mark a whole batch done because a dispatcher returns a report.

| Batch | Modules | Reason for ordering |
| --- | --- | --- |
| A | Hashcat, CyberChef, CloudFox | Offline security data, certificate and IAM primitives; prove sensitive-value handling early |
| B | recon-ng, Sherlock, SpiderFoot, BBOT, Shodan | Evidence normalization, scoped entities and provenance |
| C | Maltego, BloodHound, Burp, Caido, Metasploit | Graph traversal, multi-input correlation and API contract matching |
| D | Foremost, Wireshark, Aircrack, Airgorah | Bounded structural/binary parsers and snapshot comparison |
| E | Nmap native, hping3, Netcat, spiderdomain, passive-recon | Validated network/DNS/TLS primitives and classification |
| F | sqlmap, Evilginx defenses, Nuclei, Skipfish | Shared bounded GET/HAR adapters and scope-controlled crawling |

1. Port the common `ToolRequest`, input decoding and dispatcher before any module. Keep empty browser input normalizing encoding to empty; forbid unsupported `runEngine` requests.
2. Port each module's exact current limits and cancellation points. Some modules intentionally produce `limited:true` despite completed processing. Keep those distinctions.
3. Transfer strict security-document parsing and redaction before calculating observations/IDs. For Hashcat, preserve suppression of both input fingerprints and sensitive values.
4. Transfer binary parser malformed cases and property/fuzz tests, including PCAPNG structure, wireless FCS/security fields and recovery framing/checksums.
5. Preserve exact directed path and entity scope behavior. Missing data must remain unknown rather than becoming a new vulnerability assertion.
6. Add the optional installed Nmap adapter separately after native Nmap passes. Preserve fixed argv, pinned address, PATH availability, stdout/stderr caps and deadlines. Test a real installed version in a controlled environment; keep native mode working when absent.
7. Make effective catalog coverage/limits derive from one Python registry. Keep current ordering/IDs/source/license text and truthful implementation provenance.

Deliverables: 26 independently accepted modules and Python lab `assess`. Gate: all matrix rows in [the parity document](03-compatibility-and-feature-parity.md) have evidence; no placeholder, dropped module or Go subprocess fallback remains.

## Phase 8: assemble the dashboard coordinator and API

1. Implement run ownership/state transitions and one-active-run admission, then source/HTTPS execution with application-owned lifetime.
2. Implement cancellation, terminal-result identity checks, history retention, details and reports. Avoid serialization/disk/network work under the run-state lock.
3. Expose inventory routes using the accepted store, then evidence catalog/list/get/import/file/diagnose routes.
4. Implement two immediate-admission slots for generic lab operations and a separate two for assessments. Preserve 429 messages/status and deadlines; check disconnect cancellation.
5. Expose all 26 capabilities, assessments and saved report downloads. Maintain 201 only after evidence persistence succeeds.
6. Add compatible static serving at the same origin. Validate frontend assets/capabilities/build identity at startup.
7. Add CLI `serve`, graceful shutdown and port conflict handling. Require one Uvicorn worker and one writable state owner.

Deliverables: a Python-served dashboard on an isolated alternate port. Gate: existing frontend API schemas parse every route, real concurrent tests show responsive state/download behavior, and conflicting/cancelled operations preserve status and capacity.

## Phase 9: restore compact World and verify Earth

1. Port the four fixed World feeds, TTLs, body checks, persisted cache and per-feed coalescing.
2. Test concurrent requests, provider errors, redirects, oversized/invalid bodies, cache-save failure, cooldown, stale status and restart with fresh disk cache.
3. Verify compact globe data consumers, satellite calculations, pins, exports and source attribution against Python responses.
4. Run Earth through its existing Node root Vite configuration. Verify dashboard link, free layers, provider middleware, browser storage, map tools and intentionally disconnected credential/billing paths.
5. Keep the browser origins/ports unchanged for final release. Test any alternate-port storage separately without pretending it is the user's original localStorage.

Deliverables: both geographic views work with the Python dashboard. Gate: no Earth provider middleware is removed, no stale data is marked fresh and map storage survives the final same-origin switch.

## Phase 10: package native operation and Docker

1. Add native Windows/Linux setup and launch commands with the locked Python environment and built dashboard assets. Update `scripts/start.ps1` to select Python explicitly, verify health/capabilities/build and retain Earth's separate process.
2. Adapt the smoke runner's CLI invocation to the Python console/module entry, preserving every assertion. It currently accepts a Go binary, so changing only the server URL is insufficient.
3. Build a multi-stage dashboard+Python image with the supported runtime and CA certificates. Exclude `.godseye`, credentials, fixture private material, Go binaries and development caches from build context.
4. Add Compose with one API worker, read-only workspace mount, dedicated state volume, loopback-only published port, non-root user, bounded resources, healthcheck and graceful shutdown.
5. Prove supported Docker filesystem/network workflows and document their differences. Native mode remains required where host-loopback semantics cannot be matched.
6. Keep Earth native initially. If containerizing it, build a separate Node service that retains current middleware, loopback publication and keyless configuration. Static hosting alone fails its gate.
7. Document optional installed Nmap separately; no scanner or privileged access is silently installed to satisfy tests.

Deliverables: verified native and container operating instructions, not only syntactically valid Dockerfiles. Gate: an install without Go can run every required native workflow; Docker's declared subset and host-target configuration pass real tests.

## Phase 11: complete release validation

1. Run full Python behavior, parity, malformed-input, integration and platform suites. Run dashboard tests/build, browser smoke and Earth checks on the release artifacts.
2. Compare performance and resource behavior using the same corpora/limits and local services. Verify health/state responsiveness under the maximum admitted mix.
3. Test saved-state reopen both ways, retention/pruning, corruption, worker crashes, timeouts, disconnects, file-write errors and shutdown.
4. Test installed Nmap where available and explicit unavailable behavior where absent. Record OS/runtime/certificate-store differences.
5. Complete every gate in [validation and rollback](06-validation-cutover-and-rollback.md). Resolve failed/unknown parity rows before changing the default.

Deliverables: signed-off release checklist and evidence ledger in `documentation`, with raw local artifacts ignored. Gate: no release-blocking unknowns for advertised capabilities/platforms.

## Phase 12: cut over one installation

1. Stop admission on the chosen Go instance and wait for active jobs or cancel with explicit completion status. Export any important memory-only run reports.
2. Stop only the identified owned process, back up the selected state and verify backup checksums/restore. Leave unrelated installations alone.
3. Start Python on the original port using a verified compatible state copy and the matching frontend build. Ensure only it owns the selected writable store.
4. Verify health/build, inventory, evidence reopen/export, source/HTTPS, one representative module from every batch, compact World and Earth.
5. Promote the verified state copy as the installation's documented active store. Preserve the pre-cutover backup. Record service paths, build and state selection so later launchers use the same installation.
6. If any critical behavior differs, stop Python and follow the rollback runbook. Never mask failure by silently routing missing Python modules back to Go.

Deliverable: the normal application runs on Python. Gate: a monitored acceptance session completes with correct data and no leftover worker/writer process.

## Phase 13: retire the Go runtime and update final docs

1. Search startup scripts, tests, build/release workflows and documentation for `go`, `godseye.exe`, Go package imports and subprocess fallback paths. Classify references as active, historical or retained schema metadata.
2. Remove Go from active runtime/build prerequisites only after the no-Go installation gate passes. Keep old source during the comparison/rollback window; remove it in a later deliberate cleanup if desired.
3. Update the original architecture/README to the implemented Python design. Retain the old architectural history with explicit status rather than leaving contradictory Go-only instructions.
4. Keep `.proto`, notices and rollback release references. Generated Python bindings must be reproducible without installing Go.
5. Record final accepted features, supported modes, benchmarks and unresolved roadmap work. Close the migration only when all required parity rows have evidence.

## Delivery and effort

Use the repository's one-file-one-commit rule. Validate related work as a group, then commit each intended file separately; push incremental tested batches without unrelated files or secrets. Cross-file dependencies must be described in the phase ledger so an intermediate commit is not misrepresented as a complete release.

The port covers roughly 10.4k handwritten Go production lines plus the behavioral tests and deployment work. It is a substantial migration, not an API wrapper. Phases 1, 4, 7 and 11 are the dominant uncertainty. Estimate calendar effort after the platform/network spikes and the first representative module have measured implementation and review cost. Do not promise a date based on line count or a tool-name count.
