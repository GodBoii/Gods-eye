# Compatibility and feature parity

All rows below are release requirements. They are not a claim that the Python implementation exists. The source baseline and existing tests outrank older roadmap descriptions.

## HTTP contract

Register API routes before the static-file handler. Preserve GET/HEAD handling, rejection of unsupported methods, unknown API behavior and trailing-slash behavior through captured fixtures. FastAPI must not silently redirect POSTs or turn missing API routes into successful HTML responses.

| Method and route | Existing behavior to preserve |
| --- | --- |
| `GET /api/health` | 200; `service: godseye`, version and `workbench-v1`, `tool-assessments-v1` capability strings |
| `GET /api/state` | Workspace, assets and newest-first run summaries; summary `findings` and `checks` are empty arrays, not omitted |
| `POST /api/assets` | `{name,kind,target,owner}`; 201 asset; 400 validation; 409 at 200 assets; 500 save failure |
| `DELETE /api/assets/{id}` | 200 `{removed:true}`; 404 unknown ID; persist before changing memory |
| `POST /api/runs` | `{target,kind,authorized}`; 202 `{id}`; ownership acknowledgement, target validation; 409 if a run is active |
| `GET /api/runs/{id}` | 200 complete run DTO; 404 unknown |
| `POST /api/runs/{id}/cancel` | 200 current status; running becomes cancelling; repeated/terminal cancellation is idempotent; 404 unknown |
| `GET /api/runs/{id}/report?format=json|sarif` | Finished report attachment; 409 active; 400 unsupported format or non-source SARIF; 404 unknown |
| `GET /api/world/{layer}` | 200 fixed-layer snapshot even if stale/unavailable; 404 unknown layer |
| `GET /api/lab/catalog` | 26 effective tool descriptions, 14 formats and `maxInputBytes:8388608` |
| `GET /api/lab/capabilities` | 26 ordered module contracts; installed-engine availability determined separately |
| `GET /api/lab/reports` | Newest-first persisted report summaries, maximum 20 |
| `GET /api/lab/reports/{id}?download=1` | Full report; optional attachment `godseye-evidence-{id}.json`; 404 unknown |
| `POST /api/lab/import?format={id}` | Raw byte body; 201 saved normalized report; 400 empty/invalid format or input; 413 over body cap |
| `POST /api/lab/file?mode=file|pcap|iam` | Raw byte body; mode-specific analysis; same persistence/errors |
| `POST /api/lab/diagnose` | `{mode,target,ports,authorized}`; `tcp` or `dns`; 201 saved report; strict target/port validation |
| `POST /api/lab/assess` | ToolRequest JSON; 201 saved report; 400 bad envelope/module input; 429 capacity; 500 persistence failure |
| Static dashboard paths | Built `apps/web/dist` assets on the same origin, existing CSP and content types; no state/source directory exposure |

Errors normally use `{"error":"..."}`. Middleware Host/Origin/fetch-site/custom-header failures currently use plain text and HTTP 403. Capture exact rejection cases and distinguish transport/header limits from application validation. There are 17 explicit API method/path contracts plus static delivery in this table, including their parameterized families; query alternatives are not new routes.

The health response may add a build ID and implementation marker while retaining required fields/capabilities. The launcher should compare the frontend build ID when available, not merely trust a listener. Keep the default browser origin `http://127.0.0.1:8765` and configurable native port behavior.

## DTOs and data identity

| Contract | Required details |
| --- | --- |
| Asset | `id,name,kind,target,owner,createdAt`; nine category IDs unchanged |
| Dashboard run | `id,target,kind,status,startedAt,finishedAt,files,findingCount,reviewCount,findings,checks,gaps,error`; unfinished `finishedAt` is null |
| Finding in dashboard | `id,title,rule,severity,file,line,description`; lower-case severity |
| HTTPS check | `name,status,detail`; preserve observed/pass/review/limited distinctions and separate `reviewCount` |
| Evidence report | `id,tool,summary,createdAt,inputSha256,findings,observations,nodes,edges,artifacts,gaps,limited` |
| Evidence finding | `id,title,severity,target,detail`; deterministic ID and deduplication |
| Graph | Node `id,kind,label`; edge `source,target,relation`; preserve directed relationships and deduplication |
| Artifact range | `name,offset,length`; original input byte offsets, not decoded/re-encoded offsets |
| World snapshot | `id,source,sourceUrl,status,fetchedAt,expiresAt,body,error`; body remains a string; nullable timestamps |

Empty arrays, empty strings, absent optional Protobuf fields and null ordinary timestamps are different values. Check exact frontend readers in `apps/web/src/api.ts`, `lab/api.ts`, `lab/Assessments.tsx` and `world/model.ts` before altering serialization.

Preserve evidence finding IDs as the first 24 lower-case hex characters of SHA-256 over `tool + NUL + title + NUL + target + NUL + detail`, after the same normalization. Preserve graph node IDs from `kind + NUL + label`. Retain 26-character saved report IDs and UUID scan observation/run IDs. Do not include original secrets in identities or logs.

## Scanner parity

- Keep exactly the three current built-in rule IDs and semantics: private-key headers, AWS access-key identifiers and GitHub token candidates. This is candidate detection, not credential verification.
- Use byte regex matching with ASCII word boundaries. Python Unicode `str` regex boundaries are not a drop-in equivalent to Go's rules. Preserve one-based line counts from LF bytes, match ordinals per rule/file and deterministic final ordering.
- Preserve the v1 fingerprint tuple and Go-compatible compact JSON encoding. Test non-ASCII paths, HTML-escaped characters, backslashes and JSON escape handling. Python's default `json.dumps()` inserts spaces and escapes Unicode differently; using it unconfigured changes fingerprints.
- Keep ruleset digest framing based on UTF-8 byte lengths and the literal rule pattern strings. Source artifact URIs must match Go path escaping, including colon encoding. Keep project ID validation at 128 UTF-8 bytes.
- Default limits: two file workers, 10,000 file entries, 1 MiB/file, 64 MiB reserved input and 1,000 retained findings. Allowed worker range 1..32; per-file maximum 16 MiB; finding maximum 10,000. Preserve file-size-plus-one reservation and growth detection.
- Exclude `.git`, `node_modules`, `vendor`, `.venv`, `bin`, `reports`, `.godseye`, `dist`, symlinks and special files with the correct exclusion counts. Other hidden files remain eligible. Binary/non-UTF-8/oversized/unreadable/growing files and interrupted/budget-limited runs must not be reported clean.
- Port confined opening, regular-file checks, sorted/deduplicated gaps and finding sorting. Under finding saturation, existing concurrent completion order can affect the retained subset; compare safety, cap, partial status and valid identities rather than inventing guaranteed selection that Go does not provide.
- Preserve all report envelope keys, canonical ProtoJSON, source-only SARIF 2.1.0, result/driver metadata, `partialFingerprints["godseye/v1"]` and incomplete invocation notifications. Schema-valid output is required in addition to visual similarity.

## CLI parity

| Command | Key behavior |
| --- | --- |
| `godseye version` | Compatibility version output, with release version policy documented when Python ships |
| `godseye scan` | `--format`, `--out`, `--project`, `--timeout`, `--workers`, `--max-files`, `--max-file-bytes`, `--max-total-bytes`, `--max-findings`; one directory |
| `godseye serve` | `--root`, `--web`, `--state`, `--port`; verify frontend exists before binding |
| `godseye lab catalog` | Tools, formats and assessments |
| `godseye lab assess` | `--tool`, `--target`, `--ports`, `--authorized`, `--engine`, optional input file, encoding and file limits |
| `godseye lab import` | `--format` plus one file |
| `godseye lab file`, `pcap`, `iam` | One bounded regular file, original generic workflows |
| `godseye lab tcp`, `dns` | Explicit target, TCP ports and acknowledgement |

All lab commands preserve relevant `--out` behavior. Flags precede the positional path. Reproduce supported Go flag spellings/forms, bool flags and duration syntax in fixture tests; do not assume argparse defaults match Go's flag parser. Signal cancellation and stdout/stderr separation remain explicit. Output files use exclusive creation and are never overwritten.

Scan exit codes are 0 completed/no findings, 1 completed/with findings, 2 invalid request or operational/output error, 3 incomplete processing. Lab exits are 0 completed even with findings, 2 request/execution/output error and 3 `limited:true`. Do not unify these meanings. Serve/version retain existing exit behavior. A no-Go installation supplies the `godseye` console command and platform launcher; it need not pretend a Python package is the old native binary.

## Imports and generic analysis

Keep format IDs `nmap`, `nuclei`, `har`, `burp`, `shodan`, `bbot`, `bloodhound`, `aircrack`, `cloudfox`, `spiderfoot`, `recon-ng`, `sqlmap`, `metasploit`, `tshark`.

Keep selected-field extraction, valid root/schema checks, CSV header aliases, JSON arrays and JSONL/streamed objects where supported, malformed trailing-data rejection, scope filtering and field-specific omission. Generic JSON record readers cap at 10,000 inputs and normalized collections at 1,000. Do not load unbounded Python objects before checking limits. XML must not resolve external entities/DTDs. Reject non-finite numeric values and preserve module-specific duplicate-key handling, especially JWT/security documents.

Generic `file` analysis retains media-type identification, SHA-256, byte entropy and JPEG/PNG/PDF/ordinary ZIP signature ranges. It differs from the structural Foremost assessment. Keep both. Go's content-type sniffing must be characterized rather than replaced by filename-based `mimetypes` guesses.

Generic `pcap` supports classic Ethernet captures and rejects PCAPNG. The Wireshark assessment additionally supports PCAPNG enhanced-packet blocks. Keep these route-specific distinctions. Preserve endian variants, VLAN/IPv4/IPv6 conversation rules, offsets, omitted-frame disclosures and collection caps.

Generic IAM lint supports string-or-array fields, Allow/Deny, wildcard/sensitive action review, resources, principals and conditions without claiming effective-permission simulation.

## All 26 assessments

Each row maps to `internal/workbench/<source>` and its corresponding `_test.go`. Keep current ToolCapability ID, label, input hint, coverage, limit, engine and availability fields. Port positive, negative, scope, cap, cancellation and privacy cases from the test index, not only the happy-path parser.

| ID | Source | Required migrated behavior | Completion evidence |
| --- | --- | --- | --- |
| `nmap` | `tool_nmap.go` | Up to four sorted resolved addresses, explicit ports, TCP states, bounded banners, known-port TLS and optional fixed installed engine | Real TCP/TLS fixtures, bad certificates, mixed DNS, exact engine argv, timeout/output failures |
| `wireshark` | `tool_wireshark.go` | Classic PCAP plus PCAPNG section/interface/options/EPB validation and Ethernet conversations | Both endian orders, multi-section/interface IDs, malformed/truncated/unsupported blocks |
| `metasploit` | `tool_metasploit.go` | Service-correlated imported vulnerability/advisory review and provenance | Host/service isolation, malformed XML, collection caps, no imported secret values |
| `aircrack` | `tool_aircrack.go` | Airodump CSV and classic 802.11/radiotap capture beacon protection/management metadata | FCS, malformed security elements, truncation and unknown protection |
| `hashcat` | `tool_hashcat.go` | Supplied candidate verification against SHA-256/384/512; reuse/short match review | Max 256 hashes, 4096 candidates, 1,000,000 comparisons, 1 MiB JSON, 1024 bytes/candidate; no secrets/input digest retained |
| `skipfish` | `tool_skipfish.go` | Up to eight same-origin GET pages, depth two, selected markup/header checks | Redirect/query/encoded-path filtering, base tags, non-HTML, truncation, cancellation |
| `foremost` | `tool_foremost.go` | Structurally validated PNG/GIF/uncompressed BMP/PCM WAV original ranges | Valid/false headers, CRC/framing, 32 artifacts, 256 candidates, 32 MiB work budget |
| `sqlmap` | `tool_sqlmap.go` | Single baseline GET or captured HAR database error and request-change correlation | Error families, missing/Base64 bodies, same-endpoint one-query-change requirement |
| `hping3` | `tool_hping3.go` | Three TCP samples/port for up to eight ports, stability and min/median/max | Refused versus timeout, success ratios, first-address coverage |
| `shodan` | `tool_shodan.go` | Exported exposure/CVE assertions, freshness and TLS metadata | JSON variants, exact IP scope, no port/vulnerability inference from absent data |
| `spiderdomain` | `tool_spiderdomain.go` | DNS alias/PTR enrichment or supplied zone configuration checks | Completeness flag, absolute/relative names, mail records, bounds |
| `maltego` | `tool_maltego.go` | Exact cross-report entity merging, provenance and directed paths | 20 reports/1000 combined nodes and edges, cycles, distinct kinds, disconnected paths |
| `airgorah` | `tool_airgorah.go` | Before/after Airodump snapshots and protection changes | Shared SSID ambiguity, quoted fields, unknown security, control-character cleaning |
| `netcat` | `tool_netcat.go` | Fixed HTTP HEAD, SMTP EHLO/QUIT, Redis PING, Memcached version and server-first banners | Eight-port cap, exact writes, cancellation, no arbitrary payload path |
| `passive-recon` | `tool_passive_recon.go` | Native DNS and public verified TLS SANs, or scoped supplied CT records | Historical/date handling, wildcards, 1000 records/10,000 name-token limits, no visiting names |
| `spiderfoot` | `tool_spiderfoot.go` | Scoped supplied JSON/CSV infrastructure events, parent/source evidence | Out-of-scope exclusion, IPv6, record and graph caps, sanitized retained fields |
| `sherlock` | `tool_sherlock.go` | Up to 32 explicit profile-response observations and evidence quality | Soft-404, canonical mismatch, status/freshness, values withheld, no live enumeration |
| `recon-ng` | `tool_recon_ng.go` | Before/after host/IP inventory reconciliation and source comparison | 1000 combined records, duplicate normalization, no takeover/decommissioning claims |
| `bbot` | `tool_bbot.go` | Scoped supplied event graph, parent provenance and coverage frontier | JSON/JSONL, conflicting IDs/cycles, excluded parents and scope |
| `cloudfox` | `tool_cloudfox.go` | Static CloudFormation S3/RDS/security-group/IAM review and IAM fallback | Intrinsic unknowns, defaults/encryption, all-protocol ingress, no live account access |
| `evilginx3` | `tool_evilginx3.go` | Defensive cookie, HSTS, cache, framing and password-form review from URL/HAR | Values redacted, HSTS parsing, no interception or credential collection |
| `caido` | `tool_caido.go` | Paired HAR comparison and owner-defined expected-denial review | Origin/path ambiguity, missing/encoded bodies, no replay or claimed bypass |
| `nuclei` | `tool_nuclei.go` | Native directory/debug/embedded-map/cookie checks from one page | Positive/negative rules, scope, cookie values withheld, existing import retained |
| `bloodhound` | `tool_bloodhound.go` | Cross-collection directed selected ACL/membership path analysis | Exact collected endpoint IDs, cycles, unknown rights, 20 collections/1000 records |
| `cyberchef` | `tool_cyberchef.go` | Offline JWT policy/lifetime and public certificate inspection | Duplicate/ambiguous claims, dates, 256 KiB/32 certificates, no signature/trust claim |
| `burp` | `tool_burp.go` | OpenAPI3 versus captured HAR method/path/status/parameter/media contract checks | Path priority, overrides, unresolved refs, origin scoping, bounded collections |

All assessments require the current explicit `authorized` flag even for offline input. Only Nmap advertises installed-engine support. No engine is installed automatically. Preserve privacy exceptions such as Hashcat deliberately omitting input fingerprints as well as candidate/hash values. Descriptions that literally say "Native Go" should become "Native Python" with a recorded wording-only comparison allowance.

## Operation limits and feed behavior

| Area | Current cap/deadline |
| --- | --- |
| Ordinary JSON input | 16 KiB; one JSON object, reject unknown envelope fields |
| Raw evidence | Nonempty up to 8 MiB |
| Assessment JSON envelope | 8 MiB + 64 KiB; encoded `input` <= 8 MiB |
| Assessment upload through browser/CLI | File <= 6 MiB before Base64; exact edge sizes must be tested |
| Assessment target/ports | Target <= 4096 bytes; dispatcher <= 32 ports, narrower limits per module |
| Evidence collections | 1000 findings/observations/nodes/edges; <= 32 artifacts; <= 30 distinct gaps |
| Dashboard run | One active; 30 seconds; retain newest 20 in memory |
| Generic lab handlers | Two independent slots; 12-second parent deadline |
| Assessment handlers | Two other slots; 45-second parent deadline |
| Basic TCP/DNS | 10 seconds; TCP four workers and 700 ms dial timeout |
| Assessment HTTP | 8 seconds overall, 4-second TLS/header limits, 2-second address attempts, <= four attempts, 1 MiB body prefix |
| Optional engine | 30-second helper ceiling, inherited shorter module deadline, 8 MiB stdout, 4 KiB stderr, two-second wait delay |
| World fetch | 12 seconds, 2 MiB body, no redirects, one-minute failure cooldown unless request cancelled |

World layers retain these exact IDs, sources and TTLs: `earthquakes` USGS 60 seconds; `events` NASA EONET 10 minutes; `satellites` CelesTrak stations TLE two hours; `aircraft` ADSB.lol fixed regional endpoint 30 seconds. Keep per-layer coalescing, persisted last-good body, fresh/stale/unavailable distinction and error if live data could not be cached. TLE is text; JSON feeds must pass JSON validation. Do not turn stale orbital or aircraft data into fresh observations.

## Browser and Earth behavior

Keep current polling and cancellation, inventory categories, graph views, source/HTTPS counts, upload/assessment forms, report history/downloads, original-file recovery slices, browser recipes and manual profile templates. The browser must remain at the same origin/port after cutover so localStorage is preserved.

Earth stays at port 4173 with the current root `vite.config.js`, provider middleware, credential exclusions, free layer catalog, map tools and storage. A Go-to-Python migration does not justify removing the Node service. Test Earth and compact World independently; they are different systems.

## Allowed differences and blockers

Random IDs/timestamps/timings vary between comparison runs. Framework-added headers, JSON whitespace/key ordering and truthful implementation provenance may differ only when explicitly allowlisted and consumers remain compatible. Existing IDs read from disk and deterministic fingerprints must not change. Schema changes, dropped module behavior, broader network access, missing redaction, silent capacity changes and lost evidence block cutover.

Safer parser rejection or improved error handling that changes accepted legacy behavior must be recorded with a fixture and rationale. Do not reproduce a confirmed defect solely to obtain a zero diff, and do not quietly ship a changed contract as "parity".
