# Workbench verification, 2026-10-17

Verified on Windows amd64 with Go 1.27.2 and the repository's existing React/TypeScript/Vite stack. The workbench adds no runtime dependency. A local Go toolchain archive from go.dev was SHA-256 checked before use.

## Automated checks

- `go test ./...` passes, including the existing scanner, dashboard, web-check and World view tests.
- New importer fixtures cover all 14 formats, selected-field redaction, URL credential/query omission, duplicate findings, false matcher results, clean sqlmap rows, out-of-scope BBOT events, malformed reports, oversized input and JSON-record collection bounds.
- Native tests exercise a real loopback TCP listener, target/port validation, metadata/link-local rejection, cancellation, static IAM findings and malformed policies, file signature offsets, byte slices and synthetic Ethernet PCAP decoding/truncation rejection.
- Storage tests verify the 20-report retention limit, normalized evidence recovery after restart and explicit failure on corrupted saved reports.
- API tests cover catalog counts, upload/import/download, persistence across server construction, invalid inputs, upload size, authorization acknowledgement and shared dashboard Origin/custom-header protections.
- CLI tests cover catalog/import output, refusal to overwrite report files and required acknowledgement for network diagnostics.
- `go vet ./...` passes.
- All 11 frontend tests pass: five new recipe/profile suites plus six existing World view suites. New tests exercise UTF-8 encoding round trips, known SHA-256 output, adapted entropy/defang behavior, recipe input/output/step bounds, malformed encodings, explicit unverified JWT output, ambiguous hash hints and username validation.
- TypeScript checking and the Vite production build pass without build warnings. The workbench loads in a separate JavaScript chunk of about 31 kB before gzip, with no added runtime package.
- Windows amd64 and Linux amd64 builds pass. Linux runtime behavior remains untested.

`go test -race ./internal/workbench ./internal/dashboard` could not run because cgo is unavailable in this environment. The race detector is not counted as a passing check.

## Live browser checks

Used an isolated preview server on `http://127.0.0.1:8766` with state in `.godseye/workbench-preview/`, separate from the normal dashboard and Earth console processes. The preview contains four clearly synthetic/local test reports. The server restarted using the final binary and retained all four reports.

Verified the following through the actual UI:

1. A TCP diagnostic connected to the real local preview port and reported an open connection with timing.
2. Uploading a synthetic Nmap XML file produced an HTTPS service observation and graph relationship.
3. An invalid XML upload showed a clear inline error without adding a report.
4. Evidence views switched between findings, observations and a nonblank SVG graph. A selected-node relationship table showed source, relation and target.
5. A synthetic file produced an exact JPEG byte-range candidate. The browser download matched the original six-byte range byte-for-byte, `FFD8FF01FFD9`.
6. Uploading a synthetic IAM policy produced wildcard-action, resource and public-principal review findings.
7. A browser-local Base64 recipe returned `Hello`, and Copy output placed that result on the browser clipboard. Tab from the recipe input moved keyboard focus to the operation select.
8. Manual profile review produced nine unverified links without contacting the profile providers.
9. Tool search filtered the 26-entry catalog to the expected CloudFox coverage and limitation text.
10. Overview, Assets and Checks remained navigable under the new theme. The existing source/HTTPS backend workflows also remain covered by regression tests.

Inspected desktop and 390px mobile screenshots. Document width matched viewport width, including recipe and tool-coverage views; horizontal navigation scroll stays within its own container. The final browser console contained no warnings or errors. The intentional invalid-import test returned its expected HTTP 400.

Screenshots remain local and ignored in `.godseye/qa-workbench/preview-desktop.jpg` and `preview-mobile.jpg`. The theme is black and neutral, with simple button feedback and a reduced-motion override. World view, Earth console, their source/data implementations and their styles were not edited by this workstream; shared navigation preserves both entries.

The CLI also performed a live DNS diagnostic against the previously authorized `polycognition.online` domain. It returned five observations and one review candidate without reaching its deadline. DNS results are point-in-time observations, not a complete assessment of that domain.

## Scope of these results

Importer fixtures verify selected supported formats, not every upstream version or export variant. Imported findings are not validated against a live target. No Nmap, Nuclei, Metasploit or other scanner engine was installed or executed. No radio operations, cloud-provider collection, phishing proxy, exploitation, credential cracking or session interception was tested or added. The [workbench guide](tool-workbench.md) lists the available functionality and omissions for all 26 references.
