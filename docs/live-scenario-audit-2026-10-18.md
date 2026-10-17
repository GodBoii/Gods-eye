# God's Eye live scenario audit, 2026-10-18

Tested approximately 03:27 to 03:33 IST against the user-authorized target `https://www.polycognition.online/`. The requested subject was God's Eye's behavior against a real domain, rather than an audit of the domain's application workflows.

## Assessment

The current source build performs its implemented HTTPS, DNS, TCP, evidence import and export workflows successfully against the live target. Independent HTTP and DNS requests agreed with the observations. Its scanner also distinguished successful, partial and cancelled scans correctly in the exercised cases.

Three actionable problems remain: the normal local installation serves an incompatible frontend/backend pair; DNS resolver failures do not mark reports as limited; and HTTPS summary counts omit header review items. These make the software less reliable to operate or interpret even though the existing automated checks pass.

This is useful bounded diagnostic software. The evidence does not support treating it as a comprehensive website vulnerability scanner. The 26 reference tools in the catalog describe native subsets and report compatibility; their external scanner engines were not executed.

## Live target observations

| Scenario | Actual result | Verification |
| --- | --- | --- |
| HTTPS response | HTTP 200 | God's Eye API and browser workflow, independently checked with PowerShell HEAD |
| Certificate | Normal certificate verification succeeded; expiry 2027-01-12 | Native HTTPS checker |
| HSTS | Present, `max-age=63072000` | Independent response headers agree with checker presence result |
| MIME protection | `X-Content-Type-Options` absent | Checker and independent HEAD agree |
| Browser policy | `Content-Security-Policy` absent | Checker and independent HEAD agree |
| DNS address | Apex resolved to `216.198.79.1` | CLI, dashboard and system DNS queries |
| Nameservers | `galilea.ns.cloudflare.com`, `dimitris.ns.cloudflare.com` | CLI and dashboard |
| MX | No record returned | Native diagnostic |
| SPF | No SPF policy observed, low severity | Independent TXT lookup returned a Google verification record without SPF |
| DMARC | `p=quarantine` with relaxed alignment | Native diagnostic and independent TXT lookup agree |
| TCP | Ports 80 and 443 accepted connections on `64.29.17.1` for `www` | CLI and dashboard; observed connection timings about 11 to 21 ms |

The missing headers and SPF record are configuration review items, not demonstrated exploits. SPF action depends on whether the domain sends mail. An open web port is expected and is not a vulnerability. TCP tests covered one resolved address, not every address or origin behind the hosting service. Timings are individual observations, not a performance benchmark. The header results describe HEAD responses only.

## Confirmed software issues

### 1. Incompatible running server breaks the default Workbench

Priority: P2. Reproduced in the existing installation on port 8765.

1. Open `http://127.0.0.1:8765/`.
2. The default Workbench displays `Unexpected non-whitespace character after JSON at position 4 (line 1 column 5)`.
3. `GET /api/lab/catalog` returns HTTP 404 with a plain-text body, `404 page not found`.
4. The same frontend served by a fresh build on port 8767 loads successfully, and the catalog returns 26 tools and 14 formats.

The running `bin/godseye.exe` does not implement the workbench API that its frontend expects. `scripts/start.ps1:35` reuses any listener on the configured port without checking its version or capabilities. A build or frontend update can therefore leave an incompatible process in use. The API wrapper at `apps/web/src/api.ts:61` attempts JSON parsing before examining HTTP status or content type, hiding the useful 404 behind a parser error.

Recommended correction: validate a server capability/build identifier at startup, report incompatible listeners clearly, and launch the frontend and backend from the same build. Decode API errors defensively so a text or HTML error becomes an actionable status message. Retry alone does not fix an incompatible server.

Evidence: `.godseye/audit-2026-10-18/stale-server.json`, `fresh-server.json`, `stale-workbench.jpg`.

### 2. DNS lookup failures leave `limited` false

Priority: P2. Reproduced with the real exported `workbench.DNS` function and an isolated local DNS responder that returns SERVFAIL for every query.

The function returns no error, zero observations, zero findings, five explicit lookup-failure gaps, and `limited: false`. A user or downstream consumer relying on the report's completion flag cannot distinguish this failed collection from a normally completed diagnostic without reading the gaps. Saved report summaries expose the same flag.

`internal/workbench/diagnostics.go:144` appends a gap for resolver errors but does not set `Limited`. The flag changes only when the shared context expires at line 214. A fast SERVFAIL therefore produces contradictory status information.

Recommended correction: mark collection incomplete whenever a required lookup fails for a reason other than a conclusive no-record response. Preserve successful observations if other lookups succeeded. Add regression coverage for SERVFAIL, refused queries and mixed successful/failed lookups.

Reproducer: `.godseye/audit-2026-10-18/dns_failure_probe.go`. Output: `dns-failure-reproduction.json`. Run with `go run .godseye/audit-2026-10-18/dns_failure_probe.go`. It changes only the resolver inside its own process and sends its DNS traffic to loopback. This is a simulated dependency outage, not an outage observed on the user's domain.

### 3. HTTPS summaries show zero candidates despite review items

Priority: P2. Reproduced with the live domain.

The Checks history labels the successful website run `0 candidates`, while the detail view contains two `review` results for missing headers. Its JSON also has `findingCount: 0`. The Overview uses the same finding count for its latest-candidates summary.

`internal/dashboard/server.go:340` counts only `Findings`, which are populated by source scans. HTTPS review results live in `Checks`. `apps/web/src/Checks.tsx:90` displays the source-oriented candidate count for every run kind, and `apps/web/src/App.tsx:313` uses it in Overview.

This does not erase the detailed evidence or its export. It does make the summary misleading for the normal task of reviewing website checks.

Recommended correction: give HTTPS runs a separate review-item count and label, or display a kind-specific summary. Preserve the distinction between a configuration review and a confirmed vulnerability.

Evidence: `https-export-checks.json`, `https-results-desktop.jpg`, `https-results-mobile.jpg` under the audit evidence directory.

## Verification completed

- Fresh `go test -count=1 ./...` passed across every package with tests. `go vet ./...` passed.
- All 11 dashboard frontend tests passed. TypeScript checking and the Vite production build passed.
- All 13 existing smoke checks passed against both the original server and the isolated current build. They covered live HTTPS checking, inventory creation/removal, real source scanning, three synthetic credential detections, JSON/SARIF redaction, SARIF mapping, binary-file partial coverage, cancellation, finding limits and overwrite protection. Passing this script does not cover Workbench startup compatibility.
- Ten additional live API rejection checks passed: missing ownership acknowledgement, missing mutation header, cross-origin reads, invalid Host, workspace traversal, inventory-only scan kinds, duplicate ports, URLs supplied as DNS names, metadata destinations and unknown routes.
- Browser DNS checking returned one finding, five observations, four graph nodes and three edges. Observation tables and a nonblank SVG relationship graph rendered correctly.
- Browser TCP checking rejected duplicate ports clearly, required renewed acknowledgement after an input change, and recovered successfully after correction.
- The live website result rendered its review items in desktop and 390px mobile layouts. No document-wide horizontal overflow was observed; navigation/history scrolling stayed within their containers. No browser warning/error logs appeared in the fresh-build checks inspected.
- Exported HTTPS JSON matched the result ID and check content returned by the detail API.
- A minimal HAR containing an independently measured live HEAD exchange imported successfully. It retained one HTTP observation, produced no fabricated findings, matched the input SHA-256 and exported with the same report ID.
- A separate process reopened the actual on-disk evidence store and recovered all four saved reports. This verified persistence by reopening files; it was not a full server stop/restart test.
- A full repository scan inspected 2,118 files, retained zero supported credential candidates and returned CLI exit code 3 with partial coverage. Binary/non-UTF-8 files and oversized files were correctly disclosed as omissions. This is not a clean security assessment of the repository.

## Limits and follow-up order

Fix startup compatibility first, then DNS completion flags, then HTTPS summary labels. Repeat the same live scenarios after those changes.

Race detection could not run because the available Go environment lacks cgo support. Authenticated routes, application logic, injection detection, service fingerprinting, exhaustive ports/addresses, external scanner execution, load/concurrency performance, and Earth/World functionality were outside this domain-focused exercise. Existing importer fixtures exercise supported formats; only HAR was imported from a real target response during this run.

No fixes to application source or hosting configuration were made during the audit. An isolated fresh server remains available at `http://127.0.0.1:8767/`, with separate state in `.godseye/audit-2026-10-18/state`. The original server session remains running on 8765. The first smoke run added expected scan history to that session and removed its temporary inventory asset.

Raw evidence and screenshots remain local and Git-ignored in `.godseye/audit-2026-10-18/`. The fresh-build smoke artifacts are in `.godseye/smoke-a10a2525bc4e42cdaaf37630a5a09129/`; the original-server smoke artifacts are in `.godseye/smoke-3ea3165b92c74fd097cd86566a4701c7/`.
