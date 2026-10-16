# Live domain and local codebase verification

Tested on 2026-10-16 at approximately 13:40 IST. The user explicitly authorized checks against `https://www.polycognition.online/`. The local target was this God's Eye source repository on the user's Windows laptop.

## Domain results

The native checker completed successfully for the supplied URL. A separate PowerShell HEAD request confirmed the status and selected headers. The first native check took approximately 292 ms; this is one observation, not a latency benchmark.

| Check | Observed result |
| --- | --- |
| HTTP response | 200 |
| TLS connection | Normal certificate verification succeeded |
| Leaf certificate expiry | 2027-01-12 |
| Strict-Transport-Security | Present; independent request returned `max-age=63072000` |
| X-Content-Type-Options | Absent on the tested HEAD response |
| Content-Security-Policy | Absent on the tested HEAD response |
| Dashboard rendering | All returned checks displayed correctly; no browser console warnings/errors observed |

The two missing headers are review items, not evidence of an exploited vulnerability. Consider `X-Content-Type-Options: nosniff` after confirming accurate response content types. Design a CSP around the application's actual scripts, styles, connections and other resources; test a report-only policy before enforcing it. No changes were made to the domain or its hosting configuration.

Coverage was one unauthenticated HEAD response per check. Redirects were not followed, response bodies were not collected, and no injection payloads, crawlers, port sweeps, authentication tests or denial-of-service traffic were used. This does not assess all endpoints, backend logic, account access or the entire deployment.

## Local results

The real repository scan completed with 43 files inspected, zero supported credential candidates and five policy-excluded entries. This measurement included the new smoke-test script and preceded this report. Exclusion counts describe directory entries, not the total number of files inside excluded trees.

The synthetic fixtures produced three expected candidates, one for each original rule. The candidate values and private-key marker were absent from both JSON and SARIF reports. Source files were not modified by scanning. A separate binary fixture produced partial coverage, and an active 512-file fixture scan was successfully cancelled.

The source scan covers the three implemented credential patterns. It does not prove the repository is free from vulnerabilities, and no operating-system runtime audit of the laptop was performed.

## Live smoke-test outcomes

All 13 checks in `scripts/smoke.ps1` passed:

1. Register a temporary asset and find it in the saved inventory.
2. Complete the real HTTPS website check.
3. Complete the actual local codebase scan.
4. Detect all three synthetic credential patterns.
5. Withhold credential content from JSON.
6. Withhold credential content from SARIF.
7. Map the three results into SARIF 2.1.0.
8. Mark binary-file omissions as incomplete coverage.
9. Cancel a live scan through the API.
10. Return CLI exit code 3 for a scan limited to one finding.
11. Retain only one finding and mark its coverage partial.
12. Refuse to overwrite an existing report and preserve its content hash.
13. Remove only the temporary test asset, preserving the user's inventory.

The overwrite test intentionally produces an existing-file error. The binary and cancelled runs intentionally remain partial/cancelled in session history. These are expected test outcomes.

## Additional checks

- Fresh `go test -count=1 -v ./...` passed, including boundary validation, invalid target rejection, symlinks, admission limits, slow report downloads and inventory size limits.
- `go vet ./...` passed.
- Frontend TypeScript checking and production build passed.
- `npm audit --omit=dev` reported zero known vulnerabilities at test time.
- Both the real-codebase and synthetic-candidate SARIF artifacts passed the official OASIS SARIF 2.1.0 JSON schema with format checking.
- Race detection remains unverified because a supported C toolchain is unavailable.

## Repeat and inspect

Start the local dashboard, then run:

```powershell
pwsh -File scripts/smoke.ps1
```

That performs local tests only. To repeat the expressly authorized domain check:

```powershell
pwsh -File scripts/smoke.ps1 -Website https://www.polycognition.online/
```

The script refuses remote dashboard API hosts, creates unique synthetic fixtures under the configured workspace's `.godseye/` directory, and removes only its own temporary inventory record. It preserves its evidence and synthetic fixtures for inspection. The evidence is excluded from ordinary source scans and Git.

This run's evidence directory is `.godseye/smoke-56cfb84d3b36411c85cad369f16e0df6/`. It contains check outcomes, the website result and real/synthetic JSON/SARIF reports. The dashboard screenshot is `.godseye/verification-20261016/domain-dashboard.jpg`. These artifacts are local, untracked files. Exported reports persist, while dashboard session history still disappears when the server stops.
