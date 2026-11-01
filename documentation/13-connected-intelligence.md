# Connected intelligence and exposure checks

The Go dashboard now connects collected security evidence in **Intelligence**, alongside Investigate, Saved results and Advanced. Earth and the Python migration candidate are separate; the Python candidate does not implement this workflow yet.

## Collect, connect, investigate

1. Run a guided investigation or import supported scanner evidence in Advanced.
2. Open Intelligence and refresh after new reports finish. The asset index includes observed hosts and opaque resource targets, including assets with observations but no findings.
3. Review the severity-ordered queue. Search terms match title, target, detail and tool names together. Combine search with asset and severity filters; findings are paginated in groups of 25.
4. Expand **Trace evidence & sources** to inspect report recording times, reported severity, original finding IDs and input hashes where available. Open the source report to review its observations, coverage gaps and original per-report graph. Keyboard focus moves to the source report and returns to the opener when closed.
5. Use directed infrastructure relationships to pivot between hosts and IPs. Every retained relationship links to its source reports. The source register also exposes reports without findings or graph nodes.
6. Export the connected JSON snapshot, or export individual normalized reports from source evidence.

`GET /api/lab/intelligence` and `GET /api/lab/intelligence?download=1` use the dashboard's existing Host, Origin and cross-site request guards. No new provider requests or credentials are involved in correlation.

## Matching and interpretation

HTTP/HTTPS URLs connect to exact lowercased hosts; literal IPs and host:port records connect to their host. DNS host trailing dots are removed for asset identity. URL paths, schemes and non-default ports remain distinct finding targets. Opaque identifiers, email addresses, source locations and case-sensitive paths are not treated as host identities. Only explicit infrastructure node kinds participate in cross-report graph relationships; arbitrary person nodes are not resolved into identities.

Findings deduplicate only when normalized title, sanitized target and detail match. Distinct details/advisories stay separate. Every source record keeps its finding ID, tool, original severity, report time and available input hash. The queue uses the highest reported severity among duplicate records. Reimporting identical evidence does not increase the number of unique findings or establish independent confirmation. Input hashes describe supplied bytes, not authenticity or a signed chain of custody.

First/last recorded are report recording times within the retention window. They do not prove when an issue began or ended; an absent finding is not evidence of remediation. A shared IP, similar tool names or imported relationship does not prove ownership, identity, reachability or an exploitable attack path. Imported assertions remain unverified. No synthetic data is installed in the normal workspace.

The snapshot caps findings, entities and relations at 5,000 each, marks truncation and propagates limited source coverage. Reports retain their own detailed coverage notes. The asset list displays 100 matches and asks for a narrower search beyond that; relationship tables show 50 rows and retain the full snapshot for export, subject to the snapshot limits.

## Durable source and HTTPS evidence

Finished source and HTTPS checks save normalized evidence to `<state>/evidence/`, sharing the existing newest-20-report retention window with imports and assessments. This includes partial, failed and cancelled checks, with incomplete coverage marked. A persistence failure appears in the session check's coverage notes and changes a completed run to partial. Original run records and original source JSON/SARIF exports remain session-only; they are not reconstructed on restart. CLI checks do not enter dashboard storage.

Source reports preserve candidate locations prefixed with the workspace-relative scan target. Source contents, credential values and absolute workspace paths are not added to normalized evidence. HTTPS review items use low triage severity and remain response-configuration review candidates. This does not change the source scanner's three-pattern rule set or the Python candidate's storage behavior.

## Expanded single-response exposure rules

The guided **Page exposure review** and Advanced's native Nuclei-related module inspect exactly the requested URL with one GET. Existing response bounds, pinned address validation, verified TLS and no-redirect behavior remain in place. They do not discover or guess sensitive paths.

| Added check | Required evidence | Interpretation and next action |
| --- | --- | --- |
| Environment configuration | Successful non-HTML response at an explicit `.env` or `.env.*` path, at least two assignments and a non-placeholder sensitive assignment | High candidate. Restrict deployment-file access and privately verify/rotate real credentials. Placeholder filtering is heuristic and can miss exposures. |
| Git configuration | Successful non-HTML response at `/.git/config`, a core section and a repository field | Medium candidate. Restrict repository metadata; no Git objects are fetched. |
| GitHub credential pattern | Successful non-HTML response with a supported classic or fine-grained token pattern | High candidate. Values may be test fixtures or revoked; no authentication or token validation occurs. |
| Private-key material | Successful non-HTML response containing PEM parseable as PKCS#1, PKCS#8 or EC private-key material | High candidate. Review intended publication and key usage. Encrypted keys, OpenSSH format and JSON-escaped PEM are outside coverage. |
| CORS configuration | Multiple origins; wildcard plus credential allowance; or credentialed `null` origin | Multiple/wildcard conflicts are low configuration candidates. Credentialed null-origin trust is medium and needs browser validation with real authorization context. No cross-origin authenticated request is made. |

Sensitive assignment names, matched values and key bytes are omitted from reports. Declared HTML is skipped by sensitive-content rules to reduce documentation/SPA false positives. Listings, debug tracebacks, embedded-source maps and cookie checks remain available. A clean response establishes only that these supported signatures were not found in the inspected bytes.

CORS interpretation follows the [Fetch Standard](https://fetch.spec.whatwg.org/#http-access-control-allow-origin), including the browser rejection of credentialed wildcard origins. Private-key parsing uses the standard [Go x509 parsers](https://pkg.go.dev/crypto/x509#ParsePKCS8PrivateKey).

## Verification

`go test ./...`, `go vet ./...`, the dashboard build and `npm test` cover the connected workflow alongside existing behavior. Focused tests exercise exact matching, path/advisory separation, IPv6, deduplication, source hashes, recording times, report-store restart, collection limits, API guards, durable source findings, response review severity, single-URL requests, redaction and benign exposure lookalikes. Browser QA uses an isolated state directory and synthetic `.test`/documentation-IP fixtures, not the normal evidence store.

Browser checks covered 1280-pixel desktop and 390-pixel mobile layouts, empty and filtered-empty states, search/severity filtering, provenance disclosure, source-report focus and return, and relationship pivots. The Go race detector could not run in this environment because cgo is disabled and no C compiler is on PATH; concurrency race verification remains unproven here. The frontend build retains the existing main-bundle size warning; the new Intelligence view loads in a separate chunk.
