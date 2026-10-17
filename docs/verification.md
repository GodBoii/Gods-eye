# Initial CLI verification

## World view verification, 0.3

Verified on 2026-10-17. All backend tests and `go vet ./...` pass, including the new feed-cache coalescing, disk-cache restart, stale/cooldown, invalid/oversized payload and redirect checks. Six frontend tests pass for attributed source helpers, geospatial bounds, orbit propagation, aircraft freshness, pin validation and GeoJSON attribution. TypeScript checking and the production build pass; the separate World view JavaScript chunk is about 64 kB before gzip and loads on demand. The production npm audit reported zero known vulnerabilities at verification time.

Live USGS, NASA EONET, CelesTrak and ADSB.lol requests succeeded without an API key. One browser load showed 53 earthquakes, 54 natural events, 17 station calculations and 17 aircraft reports; subsequent counts changed as the feeds updated. All count claims are point-in-time observations.

Browser checks verified nonblank geographic rendering, layer toggles, map pan/zoom controls, keyboard rotation, coordinate/preset navigation, record filtering, pin creation and reload persistence, and a GeoJSON download containing source attribution. A downloaded snapshot contained 142 features spanning all four feed layers and one clearly labeled demo pin. Browser console inspection showed no warnings or errors. Layouts were inspected at 390px mobile and desktop sizes; no document-level horizontal overflow occurred on mobile. API credentials, paid provider requests and third-party tile requests are absent from this section.

The local CLI/dashboard smoke script was rerun and all 12 checks passed, including scanning, redaction, cancellation, limits, report preservation and inventory cleanup. Layer toggles were also checked while feed requests completed, with reserved layout space to avoid moving controls. Linux cross-build passes; Linux runtime and the race detector remain unverified. See [World view](world-view.md) for provider limits and omitted reference-repository features.

## Dashboard verification, 0.2

The Go dashboard API tests cover inventory persistence, workspace traversal rejection, authorization acknowledgement, unknown JSON fields, Host/Origin and custom-header protections, scan admission, cancellation propagation, the full scan/report lifecycle, redaction, and compact summary responses. Native HTTPS checker tests cover private/reserved address rejection, invalid URLs and cautious header-policy interpretation. `go test ./...` and `go vet ./...` pass.

The React production build passes TypeScript checking. `npm audit --omit=dev` reported zero known vulnerabilities at verification time. This is a dependency database check, not a guarantee of security.

Windows amd64 and Linux amd64 binaries build successfully. Linux runtime behavior has not been exercised on an Ubuntu host in this session.

Browser verification exercised real local asset registration, preparing and launching a source scan, completion, a synthetic credential finding, details expansion, filtering and a JSON download. The synthetic token was withheld from the report. Desktop and 390px mobile layouts were inspected; the document did not overflow horizontally. Browser console inspection showed no warnings or errors during these workflows. History and wide tables may scroll within their own panels on small screens.

The API deliberately returns run summaries during polling and fetches full evidence only for the selected check. Polling slows when idle and pauses network requests in hidden tabs. Inventory persists; run history does not yet survive a server restart.

A concurrency regression test verifies that a stalled report download does not block workspace state requests. Inventory reads are capped before JSON decoding, with a test rejecting oversized saved inventories.

The subsequent [live domain and codebase verification](live-verification-2026-10-16.md) exercised the user's explicitly authorized domain and passed 13 live smoke checks. The initial checks above were followed by actual outbound HTTPS verification; the implemented coverage remains limited to one HEAD response. The race detector limitation below still applies.

## CLI baseline

Verified on 2026-10-16 using Go 1.27.2, Windows amd64, AMD Ryzen 5 5600H. This record covers the built-in secret-pattern scanner and report writers, not the future daemon, network services or external plugins.

## Checks

- `go test ./...` passed, including synthetic secret redaction, Protobuf JSON round trips, stable fingerprints after line insertion, file/byte/finding limits, pre-cancelled scans, invalid input, symlink exclusion, binary coverage reporting, report exit codes and refusal to overwrite an existing report.
- `go vet ./...` passed.
- `go build -trimpath -o bin/godseye.exe ./cmd/godseye` passed.
- `go mod verify` passed.
- Clean, finding-containing and incomplete CLI SARIF reports passed validation against the [official OASIS SARIF 2.1.0 schema](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json), using Python jsonschema with format checking.
- A self-scan completed successfully with no supported credential patterns detected. This is not a security assessment of the full application.
- `go test -race ./...` could not run because cgo and a supported C toolchain were unavailable. Concurrency race detection remains unverified.

## First performance baseline

The benchmark creates 100 text files of 49,152 bytes each, for 4,915,200 input bytes. It scans ordinary text without credential markers using two workers and default limits. File creation is outside the timed section; filesystem caching affects the result.

```text
go test ./internal/secrets -run '^$' -bench BenchmarkScanText -benchtime=2s -count=3

18,299,205 ns/op   268.60 MB/s   12,459,410 B/op   4,990 allocs/op
19,199,427 ns/op   256.01 MB/s   12,459,777 B/op   4,990 allocs/op
19,221,039 ns/op   255.72 MB/s   12,460,000 B/op   4,990 allocs/op
```

A CPU profile showed regex matching consumed a substantial share of scan CPU. Required literal-marker checks now bypass regex evaluation for files that cannot match. Detection fixtures exercise the same filtered matching path.

These are warm-filesystem microbenchmark results. Cold execution, real repositories, many matches, huge directories, storage latency, antivirus activity and other operating systems need separate measurements. The allocations are cumulative per scan, not peak resident memory. No network latency, VPN throughput or production scale claim has been tested.
