# Validation, cutover and rollback

Status: acceptance design. No Python implementation, benchmark or migration test is claimed to have passed yet.

## Evidence ledger

During implementation maintain a release ledger in `documentation` with the following columns:

| Field | Required content |
| --- | --- |
| Requirement | API/CLI/module/store/policy case and source test reference |
| Builds | Exact Go baseline and Python candidate commits, frontend build ID |
| Environment | OS, Python/Go/package versions, filesystem, native/container mode and resources |
| Fixture | Synthetic fixture ID/content hash and local service configuration |
| Command | Exact reproducible command without secrets |
| Expected/actual | Status, structure, semantic output, persisted result and redaction assertions |
| Difference | Allowed dynamic field or explicitly reviewed behavioral delta |
| Result | Pass, fail or unverified; evidence artifact location |

Keep raw logs/results/screenshots under ignored local state with synthetic inputs where possible. The committed ledger contains references and sanitized summaries, not copies of user's uploaded captures, credential candidates or live personal data. An empty evidence row is unverified, not pass.

## Comparison strategy

Run Go and Python separately on the same synthetic corpus, with separate ports/state directories. The comparison runner lives outside either backend implementation and drives their real CLI and HTTP interfaces. Do not route a single live user request to both backends: that would duplicate network activity and writes.

For deterministic functions inject the same clock/ID provider at test boundaries and compare complete semantic output. Through public interfaces normalize only random observation/report IDs, timestamps, measured durations and documented implementation text. Test ID format, uniqueness and internal references even when values are normalized. Preserve stored IDs when reopening legacy files. Compare deterministic finding/node IDs and scanner fingerprints exactly.

Do not globally sort every output array or drop every error/detail field to make tests pass. Rule order, evidence ordering, source locations, scope, coverage gaps and limitations can carry meaning. Keep an explicit comparison allowance list with a reason for every field. JSON whitespace/object-key order can differ outside hash inputs; serialized hash inputs themselves must match.

Do not count live internet comparisons as stable parity tests: DNS, provider bodies, certificate chains and timings can change between runs. Use local fixtures for reproducibility and authorized point-in-time live checks for supplementary operating confidence.

## Required test groups

| Group | Required behavior and failure cases |
| --- | --- |
| HTTP boundary | Every route/method/status; Host, Origin, Sec-Fetch-Site, mutation header, body size, extra fields, empty/null/wrong types, trailing JSON, slash redirects and unknown routes |
| Dashboard jobs | One active run, second 409, immediate 202, completion/partial/failure/cancelling/cancelled, repeated cancel, late result, concurrent state and slow report download |
| Lab admission | Two imports/diagnostics admitted, third 429; separately two assessments admitted, third 429; groups do not accidentally block each other |
| Scanner | All current rules, false matches, exact byte boundaries/fingerprints/line positions, exclusion counts, growth, unreadable files, finding/file/byte caps, partial coverage and redaction |
| Reports | ProtoJSON round-trip, optional presence, enum/uint64 semantics, SARIF schema, incomplete notifications, source-only SARIF and exclusive output |
| Storage | Legacy load and new report re-open in both implementations, timestamps/order, arrays, corrupt/truncated state, over-limit files/counts, retention, atomic failures and single writer |
| Imports | All 14 formats and supported variants, scope/false matches, unsafe XML, malformed JSONL/trailing data, record limits and selective-field privacy |
| Assessments | All 26 capability rows, their existing named tests, mode restrictions, cancellation, graph direction, limits and module-specific privacy |
| Binary/structural | PCAP endian/link variants; PCAPNG block/interface/options/lengths; radiotap/FCS/security fields; file signature and CRC/framing; original-range downloads |
| Network | DNS pinning, mixed/mapped addresses, metadata rejection, local/private allowed cases, original-host TLS, no redirects/proxies/shared cookies, compressed/oversized bodies |
| DNS/TLS | SERVFAIL/refused/timeout versus conclusive no record, partial success, valid/untrusted/expired/wrong-name certificates and selected trust stores |
| Installed engine | PATH unavailable, exact fixed argv, IPv6, output bounds, process timeout/descendants, nonzero exit and valid-but-incomplete Nmap XML |
| World | All four IDs/TTLs, one fetch under concurrent callers, cache restart, cooldown, stale/unavailable, invalid/TLE/oversized/redirected provider response and save failure |
| Browser | Existing React schemas and full workflows, polling, graphs, counts, errors, uploads, download/recovery, recipes, profile templates, compact World and Earth link |
| Deployment | Native Windows/Linux, container runtime, mounts/permissions, port conflicts, health/build mismatch, stop/restart, no Go installed |

Transfer behavior from all 156 named Go tests listed in [the source index](07-source-and-test-index.md), including their table/subtest cases. A 156-test Python count is not itself a goal; one Go test may contain several distinct cases. Retain each behavior with a source-to-Python test mapping and add migration-specific coverage. Preserve malformed binary parser fuzz cases as reusable seeds.

## Responsiveness and performance gate

No language-speed claim substitutes for measurement. First collect a Go baseline on the same machine/mode, corpus and limits. Use a small source tree, a 10,000-file tree, near-budget input, finding-heavy input, maximum-size imports, binary captures and structural recovery, plus bounded graph/hash workloads. Use private synthetic files for secret-positive cases.

Collect wall time, throughput, parent/child RSS, CPU, peak retained input/output, socket/descriptor/handle counts and child count. Use local fixtures for active modules so provider/network variation does not dominate. Include warmup and at least five repeated trials for throughput; use enough requests to characterize health/state latency under load. Save the raw sample count and distribution, not just an average.

Proposed initial acceptance targets, to freeze after the baseline phase:

- Zero lost eligible supported findings/evidence in non-saturated deterministic fixtures, and no false success when input is omitted.
- Health/state p95 under 250 ms during the maximum admitted local workload on the reference machine, with no sustained event-loop stall above 500 ms. Use trivial fixture state sizes and a separate large-state case so serialization cost is visible.
- Cooperative cancellation normally acknowledges cleanup within one second and all owned process trees exit within five seconds. A blocked OS operation is measured as such and cannot be labeled stopped if still running.
- For deterministic local workloads, investigate a median duration above twice the Go baseline, and any unchanged default workload that now hits its deadline. The twice-baseline threshold is a review trigger; a timeout or lost behavior is a hard release failure.
- After 100 bounded operations, no monotonic child/handle/socket leakage. Set a memory high-water limit from the measured baseline and proposed Docker budget; explain process-start overhead separately from sustained growth.

Do not secretly raise deadlines, discard findings, reduce module coverage or lower admission capacities to pass. Optimize measured hot paths inside Python, using streaming, bounded batches, byte operations and process isolation. Any intentional performance/limit change must be documented and reviewed before final acceptance.

## Browser and platform verification

Run the built dashboard against Python, not a mock server. Exercise source and HTTPS checks, each assessment input family, positive/negative evidence, original-file byte recovery and report reopen/export. Visit Overview, Assets, Checks, Workbench, compact World and Earth. Check keyboard operation and mobile fit because changed error/loading/timing behavior can affect the existing UI even without CSS changes.

Verify all 26 modules through automated public-interface cases and browser smoke on representative members of each batch. Confirm all 26 forms/metadata remain accessible. Original-upload recovery must match exact bytes/hash, and saved reports must accurately explain why recovery is unavailable without the original file.

Native Windows and Linux are release targets. Linux cross-compilation of the old Go binary does not prove Python Linux runtime. Docker tests must execute the image, mount a workspace read-only, persist state across recreation and prove the documented host-target interpretation. Do not mark unavailable radio/capture/full-engine workflows as regressions because they were not implemented before.

## Release checklist

- [ ] Baseline and rollback artifact reproduced; source drift reconciled.
- [ ] Windows/Linux filesystem confinement and network/TLS spikes proved.
- [ ] All 17 explicit API method/path contracts and static delivery accepted.
- [ ] Scan, serve, version and all eight lab subcommands accepted.
- [ ] All three scanner rules, report formats and CLI exit codes accepted.
- [ ] All 14 imports and all 26 native modules accepted.
- [ ] Optional installed Nmap works where advertised; missing-engine mode remains explicit.
- [ ] Compatible inventory/evidence/cache, retention, corrupt-state rejection and writer locking accepted.
- [ ] Current corrected review counts, DNS incomplete flags and launcher capabilities retained.
- [ ] Admission, cancellation, shutdown and responsive polling tested under real concurrent load.
- [ ] World freshness, cache and provider failures accepted; Earth middleware/storage unchanged.
- [ ] Existing frontend tests/build and operating browser workflows pass.
- [ ] Native no-Go install and declared Docker workflows execute successfully.
- [ ] Resource/performance evidence meets frozen criteria or documented accepted changes.
- [ ] Redaction checks cover reports, exceptions, logs, IPC and child process errors.
- [ ] Backup/restore and both-direction state compatibility rehearsed.
- [ ] Every required feature/platform row is pass; no critical fail/unverified row remains.

## Cutover procedure

1. Identify the exact installation to replace by service path/build, port and state directory. Record current Go and frontend artifact hashes. Keep unrelated alternate-port instances untouched.
2. Finish active work or cancel it through the application and wait for terminal status. Export any important memory-only dashboard report. Such jobs do not become restartable merely because the backend language changes.
3. Stop only that owned Go process. Verify listener ownership and that it no longer writes its state.
4. Copy inventory, evidence and cache to a timestamped backup outside the active store. Hash the copy and perform an isolated restore test. Do not rewrite the originals.
5. Create a separate candidate state copy from the stopped installation. Validate it with Python before serving traffic. Do not launch Go concurrently against the writable candidate copy.
6. Start the accepted Python build and matching dashboard on the original port with the candidate state. Keep the external browser origin unchanged, so localStorage persists. Use a build/capability handshake before declaring ready.
7. Smoke health, inventory count, stored report IDs/counts, downloads, source/HTTPS, representative assessment families, World and Earth. Confirm original input bytes are required for reopened recovery reports as before.
8. If acceptance succeeds, update the launcher/installation manifest to that exact state location and build. Retain the original backup. Treat new Python evidence as production data and include it in later backups.
9. Record the cutover result, known limits and rollback artifact. During the initial acceptance window monitor errors, cancellations, store writes and child cleanup.

No test is allowed to prune the only production evidence copy. Remember both implementations retain 20 reports and can prune on open/save. All rehearsals use copies.

## Rollback procedure

Rollback triggers include missing capability, unreadable legacy data, changed supported findings, redaction/policy failure, broken cancellation, repeated crashes or operating-mode behavior outside its declared contract.

1. Stop Python admission, cancel/drain active jobs, and stop the Python service plus owned children. Confirm the candidate store has no remaining writer.
2. Preserve a copy of the candidate state, including evidence created after cutover. Preserve redacted failure logs/build identity. Do not replace it with the older backup.
3. Validate the post-cutover state copy with the retained Go release in an isolated location. During development, the two-way compatibility gate should make this possible. If valid, use a new rollback working copy of that state so recent compatible evidence remains available.
4. If validation fails, restore the pre-cutover backup to a new working directory and keep the incompatible post-cutover copy for recovery. Do not silently discard recent reports. Export/recover compatible normalized reports through a separately validated procedure; preserve original IDs and hash them before any merge. Never merge by overwriting arbitrary matching filenames.
5. Start the known Go backend with its matching frontend and selected rollback state on the original port. Verify health/capabilities, inventory, reports, one check and Earth access.
6. Record data selection and any evidence temporarily unavailable, then fix the Python candidate using isolated copies. Do not resume a half-migrated mixed writer installation.

Rollback restores an operating release and its supported state, not an ability to resume memory-only jobs. Keep the old release available until the agreed acceptance window ends. Deleting Go source/tooling before the no-Go acceptance and rollback rehearsal would make this plan less recoverable.

## Final completion

The migration is complete when the normal launcher runs the Python backend, all required parity gates pass, existing data/UI/CLI work, declared Windows/Linux/container modes are verified, and no supported request needs the Go executable. Document the result and remove active Go prerequisites. Future SQLite, public multi-user deployment, plugin execution or frontend redesign work requires its own plan and acceptance criteria.
