# Assessment expansion verification, 2026-10-18

All 26 requested tool workstreams received a separate subagent. Three agents interrupted by the account usage limit resumed after the user's instruction and completed their work. Shared dispatch, API, CLI, frontend integration and release verification were handled by the parent agent. A separate focused review found no actionable issue in the shared transport, engine execution, dispatch and API boundaries.

## Delivered behavior

The 0.4 build exposes 26 unique assessment modules through `GET /api/lab/capabilities`, `POST /api/lab/assess`, the Workbench Assessments form and `godseye lab assess`. A regression test requires every catalog reference to have an assessment route and nonempty coverage/input/limitation descriptions. The [module guide](assessment-modules.md) documents exact capabilities and remaining gaps.

These are scoped native implementations and evidence analyzers, not full replacements for 26 external engines. Nmap has one optional installed-engine adapter. No external scanner engine was available on this machine, so installed-engine execution was not verified live. All network results in this verification came from native Go implementations.

The previously reported issues were addressed:

- DNS collection errors set `Limited`, with a regression test that forces resolver failures without changing machine DNS settings.
- HTTPS results carry a separate `reviewCount`. A fresh live result had two review items and `reviewCount: 2`; detail and summary counts agreed.
- API text/HTML errors produce an actionable HTTP/build mismatch message rather than exposing a JSON parsing error.
- The launcher checks the running dashboard capability handshake before reusing it. It rejects an older or unrelated service rather than silently attaching the new frontend to it. Existing old server processes were not replaced during verification.

## Automated verification

- Fresh `go test ./... -count=1` passed after all modules and integration changes.
- `go vet ./...` passed.
- All 11 existing frontend suites passed; TypeScript checking and the Vite production build passed.
- Windows amd64 and Linux amd64 production builds passed. Linux runtime behavior remains untested.
- CLI integration tests exercised an actual local HTTP exposure fixture and an uploaded CloudFormation file through the common assessment dispatcher. Authorization acknowledgement remained required.
- API integration tests exercised actual local HTTP requests, report persistence/reopening/export, invalid input rejection, capability handshake and concurrent execution. Two real concurrent assessments completed and persisted; a third was rejected with HTTP 429.
- Network tests covered target validation, DNS pinning, redirect refusal, metadata rejection, response-size limits, cancellation, real TCP/TLS fixtures and fixed engine arguments.
- Module tests covered each implemented parser/rule/graph path, malformed inputs, collection limits and relevant negative/privacy cases. PCAPNG and wireless parsers also received focused fuzz runs.
- The 13 existing smoke checks passed against the fresh build using its actual CLI binary. The expected overwrite rejection was preserved and did not make the smoke script fail.

Race detection remains unverified because this Go environment lacks cgo support. No claim of race-detector coverage is made.

## Live domain results

The user authorized `https://www.polycognition.online/`. Verification used explicit low-volume native checks; it did not submit login forms, create accounts, inject SQL, exploit services or access a database.

| Workflow | Observed result |
| --- | --- |
| Native web crawl | Five pages fetched: `/`, `/login`, `/signup`, `/privacy-policy`, `/terms-of-service` |
| Header review | CSP, X-Content-Type-Options and Referrer-Policy absent on each page: 15 page-level items across three configuration concerns |
| Native exposure rules | No directory-listing, debug, embedded-map or cookie findings from the root response; this is limited rule coverage, not a security verdict |
| Database disclosure review | No supported database-error signature in the single baseline response; no injection attempt or database audit |
| Native multi-address TCP/TLS | Ports 80/443 accepted connections on both addresses resolved during that run; TLS 1.3 certificate verification passed |
| Repeated TCP samples | Results produced timings and explicit first-address coverage limitations |
| Fixed protocol probes | HTTP/connect observations produced; protocol and additional-address omissions remained marked limited |
| DNS and verified TLS reconnaissance | Existing DNS results and certificate observations returned; absent SPF remained a review item |
| Defensive session review | One configuration finding, with authentication design and phishing-resistance explicitly unverified |

Hosting addresses varied between runs, which is expected for resolved service endpoints. Results are point-in-time observations, not a complete origin inventory. Missing headers are configuration review candidates and do not establish an exploitable vulnerability.

## Browser and recovery verification

The final desktop browser displayed all 26 module options and successfully ran a native assessment against the real domain. Controls showed native execution and the absence of an installed Nmap engine explicitly. Loading, result and expanded-finding states rendered correctly, and the inspected console had no warnings/errors.

The assessment forms were checked at a 390px mobile viewport. Long Sherlock and CyberChef schema hints initially caused overflow; scoped wrapping/min-width fixes corrected it. A second pass across all 26 selected forms recorded no document-wide horizontal overflow. The viewport override was reset afterward.

Controlled local fixtures verified positive directory/cookie findings, local digest matching with secrets omitted from saved reports, and structural file recovery. A real PNG embedded at offset 14 produced an exact 123-byte browser recovery download. Original and recovered SHA-256 hashes matched:

```text
7D6872FA320A9B27D9DD13874B2B3B7349A719CCC5590A2ACF523DF70ED3AC60
```

The new release runs locally at `http://127.0.0.1:8771/` using `bin/godseye-0.4.exe` and separate state in `.godseye/expansion-2026-10-18/final-state`. The original user server remains separate. To launch this binary again after it stops:

```powershell
.\bin\godseye-0.4.exe serve --root . --port 8771 --state .godseye/expansion-2026-10-18/final-state
```

Local ignored evidence is in `.godseye/expansion-2026-10-18/`, including live JSON results, recovery hash comparison, module-count verification, review-count verification, screenshots and before/after mobile overflow measurements. Fresh smoke evidence is in `.godseye/smoke-5cea402797984c0f9e5578899b43f12f/`.

## Remaining coverage

Authenticated application behavior, role-based access testing, live database configuration/permissions, live cloud/directory collection, general source-code data-flow analysis, dependency advisories and full external engine workflows remain unimplemented. Wireless modules require supplied captures and do not operate radios. Evidence analyzers do not convert imported claims into independently confirmed exploits. These gaps remain explicit in the product and module guide.
