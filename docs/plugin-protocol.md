# Plugin protocol v1

`api/godseye/v1/plugin.proto` defines the exact `UnifiedFinding`, `DebugTelemetryEvent` and `Plugin` service contracts. Protobuf JSON is the unified JSON representation: lowerCamelCase keys, symbolic enum names, decimal strings for 64-bit integers, RFC 3339 timestamps and standard Protobuf duration strings. Omitted optional fields mean unknown; consumers must not substitute false or zero. Unknown enum values and unknown JSON fields fail v1 boundary validation.

This is a contract, not an implemented validator or running scheduler. The first implementation milestone must enforce the rules below and generate bindings from this file. Do not maintain parallel handwritten Go or TypeScript copies of the domain schema.

## Registration and interface

Plugins are executable subprocesses, not Go shared-library plugins. An installation manifest supplies an absolute executable path, SHA-256 digest, argument array, working directory, allowed capabilities, approved permissions, expected plugin ID and supported protocol major. Administrators install manifests outside scanned repositories. Never discover and execute binaries from the target workspace.

The registry validates the manifest, checks the executable digest, starts the process with a minimal environment, and calls `Describe`. Reject ID mismatches, protocol mismatches, unsupported schema versions, zero concurrency and unapproved permissions. Registration occurs at daemon startup or through explicit installation/reload. No daemon recompilation is required.

For the initial local protocol, the daemon reserves a loopback listening socket and passes it to the worker through platform-specific handle inheritance. A launcher-provided short-lived credential authenticates RPCs. Do not place credentials in command-line arguments or logs. Remote workers, if added, require mTLS and project-scoped identities; a bare remote gRPC port is not supported.

The `Plugin` service generates the Go server interface with `Describe` and a server-streaming `Run`. Go plugins implement that generated interface. Python or other plugins use bindings from the same definition. The transport interface intentionally does not expose register, shell execution, arbitrary file read, or network policy mutation RPCs.

The launcher mounts or grants read-only access to one immutable input snapshot and a separate writable output directory. `workspaceSnapshotId`, `findingsSnapshotId` and `policySnapshotId` are opaque IDs mapped by the launcher, not paths to resolve freely. Process and container targets must match pre-authorized identities on the worker host. Resolve PID and start time together immediately before inspection.

## Run lifecycle

1. The daemon persists a run with a unique attempt ID and input digest, then sends `RunRequest` under a deadline no longer than `limits.wallTime`.
2. The worker validates capabilities, target kind, limits and permissions before doing work. Duplicate active run IDs return ALREADY_EXISTS. Unsupported targets return INVALID_ARGUMENT; missing privileges return PERMISSION_DENIED.
3. `RunEvent.sequence` starts at 1 and increments without gaps. Each event has exactly one payload and the matching run ID. Emit progress at least every five seconds during work, including while an external scanner is silent. The worker must drain subprocess output concurrently within size limits.
4. The daemon validates and persists events as they arrive. Apply backpressure through a bounded channel and gRPC flow control. Maximum event size is 1 MiB, including its encoded payload. Findings are never silently dropped. Optional diagnostic sampling must increment dropped counts.
5. Send exactly one final `RunSummary` and close the stream with OK. Counts must match emitted findings and telemetry. A succeeded run has no unexplained coverage gaps or required-engine failures; mark incomplete coverage partial. An OK close without a summary is an interrupted run, never success.
6. Cancellation propagates through the RPC context. Workers stop child processes; the launcher enforces a five-second termination grace and kills the process tree if needed. The daemon records cancellation even if no summary can be delivered. Data from late events cannot change a terminal job.

If the connection fails, keep accepted results tagged incomplete and retry under a new attempt ID if policy permits. The v1 protocol does not resume streams. Persist terminal completion only after the final event and artifact validations succeed. Treat plugin summaries as assertions to verify, not proof.

Local output artifacts must exist under the run output directory, match their digest and declared size, and remain within the output budget. Resolve paths with OS-safe handles; reject absolute paths, traversal, symlinks, junctions and reparse-point escapes. Copy accepted artifacts into immutable managed storage before terminating the worker or reporting completion. Remote artifact transfer is deferred, so v1 path artifacts support co-located workers only.

## Required validation

All text is valid UTF-8, NUL-free and size-bounded. IDs are nonempty and at most 128 bytes. Observation, event, session and run IDs use UUIDs. Project and asset IDs are opaque. Titles are at most 512 bytes, descriptions at most 16 KiB; attribute maps have at most 32 approved keys and 256-byte values. Arrays have explicit limits in the implementation policy and must fit the 1 MiB envelope. Reject non-finite numeric values.

For `UnifiedFinding`:

- Require schemaVersion `1.0`, findingId, runId, projectId, fingerprint, producer, category, ruleId, title, description, severity, asset, evidence, risk and observedAt. IDs must agree with the authenticated request. Producer ID/version must agree with the registration; engine and ruleset versions are required provenance.
- Confidence is finite in [0,1]. CVSS scores are in [0,10], vectors must parse for their declared version, and scores must agree with the vector. EPSS probability and percentile are in [0,1], with a nonfuture source date and a matching advisory ID. Missing messages mean unavailable data.
- Reachability is explicitly unknown, reachable or unreachable. Require a reason for every state; reachable and unreachable need supporting evidence. Missing or unsupported analysis maps to unknown.
- Location lines and columns are one-based, end positions are exclusive, and end cannot precede start. Columns require lines. URIs are normalized percent-encoded workspace-relative paths with no scheme, authority, drive prefix, traversal or encoded traversal. Reject invalid encodings and normalize before deduplication.
- Source findings require at least one location. Dependency findings require a valid package URL, ecosystem and name; an unresolved version remains absent. Runtime findings may use only an asset plus event references. Referenced objects must belong to the same project and run or an explicitly authorized input snapshot.
- Redact secret evidence before transmission. Compute fingerprints from versioned canonical tuples of project, category, rule or advisory, normalized asset/location/package identity, and a stable symbol when available. Use length-delimited fields before hashing. Never hash raw credentials or rely only on line numbers. Preserve each producer's observation when merging duplicates.
- A proposed diff requires at least one file with a validated relative URI and a 64-character lowercase SHA-256 base digest. All modified paths must appear in the file list. Initial patch support covers existing files only; creation, deletion and binary patches need a later contract extension.

For `DebugTelemetryEvent`:

- Require schemaVersion `1.0`, eventId, runId, projectId, producer, hostId, agentSessionId, occurredAt, collectedAt and exactly one payload. Check scope and producer against the request. Monotonic offsets are meaningful only within an agent session, not across hosts.
- A process is required for thread, socket and resource payloads. Its PID is positive and start time is required. Other payloads may describe a service without a process. Span IDs require a valid trace ID; span payloads require both IDs.
- Timestamps use valid Protobuf ranges. Preserve clock uncertainty rather than imposing an invalid cross-host timestamp ordering. Span duration and resource sample interval are nonnegative; resource samples that report CPU require a strictly positive interval.
- Metric values and CPU usage are finite; CPU usage and resource counts are nonnegative. CPU usage is measured in cores and may exceed one on multicore hosts. Unsupported counters are absent, never fabricated as zero.
- Thread frames contain symbols, not stack locals. Endpoint IDs are pseudonymous. Only configured low-cardinality attributes pass validation. Do not ingest arbitrary environment variables, headers or command-line arguments.

Validate RunRequest limits as positive, within deployment maxima and consistent with the RPC deadline. Require exactly one target. Requested capabilities must be a nonempty subset of the descriptor and installation policy. Reject an unspecified enum, missing oneof, unknown reference or out-of-order event with a structured diagnostic and mark the run partial or failed. Do not discard malformed output and report a clean scan.

## SARIF contract

Every finding-producing plugin adapter uses the shared exporter to emit a SARIF 2.1.0 artifact alongside unified findings. The orchestrator also exports a merged report. Pure telemetry collectors emit telemetry normally; if a run requests a SARIF artifact, their report contains zero results until analysis produces findings. Do not encode every metric sample as a SARIF result.

| Internal field | SARIF destination |
| --- | --- |
| Producer engine and version | `runs[].tool.driver.name` and `version` |
| Rule ID and title | `tool.driver.rules[].id` and `shortDescription.text` |
| Finding rule ID and description | `results[].ruleId` and `message.text` |
| Critical/high, medium, low/info | Result `level` error, warning, note; retain original severity in properties |
| Source URI and region | `locations[].physicalLocation.artifactLocation` and `region` |
| Fingerprint | `partialFingerprints["godseye/v1"]` |
| Finding ID | `guid` |
| Run ID, category, confidence, risk | Result `properties` with namespaced keys |
| Related evidence locations | `relatedLocations`; emit codeFlows only for actual ordered flow evidence |
| Verified structured edits | `fixes`; never blindly translate an arbitrary diff into SARIF replacements |
| Failed or partial tool execution | `invocations[].executionSuccessful` false plus tool execution notifications |

Group results by producer engine/version/ruleset. Use URI base IDs for workspace roots, avoiding host-absolute paths. Validate completed reports against the official SARIF 2.1.0 schema. Missing locations are valid for asset-only runtime findings. Preserve package, advisory and telemetry links in namespaced properties rather than inventing source locations.

## Compatibility and verification

Keep package `godseye.v1` stable. Add fields with new numbers, never reuse deleted numbers, and reserve deleted field names/numbers. New required semantics, enum variants that old consumers cannot accept, or new event kinds require negotiated capabilities or a new protocol major. A field being wire-compatible does not make behavior backward-compatible.

Implementation must include fixture round-trips through Protobuf and JSON, invalid-object rejection, deadline/cancellation tests, a crashing plugin, duplicate sequences, oversized messages, symlink escape attempts, redaction fixtures and official-schema SARIF validation. Contract compilation alone does not verify these behaviors.

Generate language bindings with pinned `protoc` and language plugin versions. Compile the source with a descriptor-set output before generation; include Google's standard Protobuf include path. The future Go module path is `godseye`, matching `go_package`; update both together if the project acquires a public module path.
