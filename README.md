# God's Eye

A local, offline defensive auditing CLI, with an architecture for a broader security and private-networking platform. Original code and rules are Apache-2.0. No account, subscription, API key or paid service is needed.

## Run

Requires Go 1.25 or newer. The current implementation has been built and tested with Go 1.27.2 on Windows.

```powershell
go build -o bin/godseye.exe ./cmd/godseye
.\bin\godseye.exe scan --project my-project C:\path\to\source
.\bin\godseye.exe scan --format sarif --out findings.sarif C:\path\to\source
```

On Linux/macOS, build with `go build -o bin/godseye ./cmd/godseye` and run `./bin/godseye scan /path/to/source`. Flags must precede the directory argument. Reports go to stdout unless `--out` names a new file. Existing output files are never overwritten.

| Exit code | Meaning |
| --- | --- |
| 0 | Completed within configured coverage, no candidates found |
| 1 | Completed, credential candidates found |
| 2 | Invalid arguments, filesystem setup error, or output error |
| 3 | Incomplete coverage, exhausted limit, cancellation or timeout |

## Implemented

- Generated Go Protobuf message bindings for the canonical findings and telemetry contract.
- Two concurrent file workers by default, bounded channels, cancellation checks and input/output-count limits.
- Three original pattern rules for private-key markers, AWS access-key identifiers and GitHub token candidates. Matches require human verification; the tool does not test credentials against a service.
- Source locations, fingerprints independent of line numbers, redacted evidence, and explicit incomplete-scan status.
- Canonical Protobuf JSON findings inside a scan envelope and SARIF 2.1.0 reports.
- Offline operation, root-confined file opens, symlink exclusion, and report files created without overwriting existing files.

The default limits are 10,000 files, 1 MiB per file, a 64 MiB input reservation budget, 1,000 findings and 30 seconds. `scan --help` lists the controls. The budget reserves each discovered file's size plus one byte for growth detection. Files that grow beyond that reservation are omitted with an explicit coverage gap.

## Coverage and limits

This is the first runnable implementation, not the completed platform. It has no daemon, durable job queue, external plugin execution, gRPC server, SAST data-flow analysis, dependency auditing, runtime collection, VPN or proxy deployment yet. The generated schema does not mean all protocol validation and lifecycle behaviors are implemented.

Only UTF-8 text is inspected. Binary/non-UTF-8 content, unreadable or oversized files, and exhausted limits mark a scan incomplete. The directories `.git`, `node_modules`, `vendor`, `.venv`, `bin` and `reports` are policy exclusions and their counts are reported. Symlinks and special files are excluded. Git history, archives and `.gitignore` semantics are not implemented. Other hidden files, including `.env`, are scanned.

Scan an idle local checkout. The scanner confines opens with Go's `os.Root`, but does not create an immutable snapshot or sandbox a hostile, concurrently modified directory. Timeouts are cooperative and cannot interrupt a blocked operating-system filesystem call. Directory enumeration and the Go runtime are not subject to a hard memory sandbox. Fingerprints use rule, path and match ordinal; inserting another match of the same rule before an existing one can change its fingerprint.

Credential values and source excerpts are omitted from reports, but paths and project IDs are retained. A clean result means no supported patterns were found within the stated coverage, not that the project is secure.

## Development

```powershell
go test ./...
go vet ./...
go test -race ./...
```

The race detector requires a supported C compiler on Windows. Protobuf bindings were generated using `protoc-gen-go v1.36.10` and the compiler bundled with `grpcio-tools 1.84.0`. See the generation header for the compiler version. Generate with `--go_out=. --go_opt=module=godseye` and `api/` as the source include root.

- [Architecture and planned monorepo](docs/architecture.md)
- [Plugin protocol and future validation requirements](docs/plugin-protocol.md)
- [Canonical Protobuf schema](api/godseye/v1/plugin.proto)
- [Open-source policy and licensing](docs/open-source.md)
- [Verification results and first scan benchmark](docs/verification.md)

The architecture separates live proxy/VPN traffic from audit workers. It does not promise universal anonymity or claim measured network performance.
