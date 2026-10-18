# Python backend migration plan

Prepared 18 October 2026. Implementation has started under `backend/`. The Python candidate supports inventory, source scanning and HTTPS response checks; full cutover and Go retirement remain pending. See the [implementation ledger](08-implementation-ledger.md) for executed checks, completed work and remaining gates. Documents 01 through 07 retain the original analysis and migration plan.

The target is a Python replacement for every currently implemented Go backend and CLI capability, with the existing React dashboard and separate Earth console continuing to work. Docker and Docker Desktop are optional operating modes. The completed migration must not invoke the old Go executable as a hidden fallback.

## Read these documents in order

| Document | Purpose |
| --- | --- |
| [Current system analysis](01-current-system-analysis.md) | What exists now, where behavior lives, architectural gaps and migration risks |
| [Python architecture](02-python-architecture.md) | Package structure, framework choices, process ownership, concurrency and security boundaries |
| [Compatibility and feature parity](03-compatibility-and-feature-parity.md) | API, CLI, data, reports, all 26 assessments and behavioral requirements |
| [Step-by-step implementation](04-step-by-step-implementation.md) | Ordered work packages, dependencies, deliverables and completion gates |
| [Docker and local operation](05-docker-and-local-operation.md) | Windows/Linux operation, containers, volumes, host diagnostics and packaging |
| [Validation, cutover and rollback](06-validation-cutover-and-rollback.md) | Comparison tests, performance criteria, release gates and recovery procedure |
| [Source and test index](07-source-and-test-index.md) | Audited source inventory and existing Go test functions to transfer |
| [Implementation ledger](08-implementation-ledger.md) | Current Python implementation, executed verification and outstanding parity gates |

## Recommended decisions

- Keep React/TypeScript/Vite in `apps/web`. Keep the Node/Vite Earth service in `apps/earth` and its port 4173.
- Implement the replacement under `backend/`, using Python 3.13 initially, FastAPI, Pydantic v2, Uvicorn and explicit async network adapters. Resolve and lock supported package versions during the foundation phase.
- Keep port 8765, HTTP routes, field names, polling, local access rules, exported data and CLI command grammar compatible.
- Use one Uvicorn worker. Keep run ownership and JSON writes inside one coordinator. Separate bounded Python worker processes handle expensive synchronous work.
- Keep the existing JSON persistence layout for the first release. A database migration is a separate future project.
- Port a subsystem, compare it with Go using synthetic/local fixtures, then accept it. Cut over the complete backend only after all required capabilities pass.
- Retain the Go source as the comparison implementation during development. Remove the runtime dependency on Go at final acceptance; retain a recoverable Git release for rollback.

## What "no functionality lost" means

Preserve successful workflows, input rejection, limits, cancellation, report identity, redaction, provenance, failure reporting, persisted data and recovery. Preserve browser-local functions too, including recovery downloads that require the original uploaded file. A catalog entry is not enough: its actual assessment and supported import behavior must work.

The target does not include implementing unfinished roadmap items such as a full plugin daemon, broad SAST, a production VPN, or full replacements for the named external security suites. Their schemas and design documents remain available. Missing future features must not be relabeled as migrated working features.

## Evidence and limits

The baseline is commit `4d27de83ad087703b197432ccbf2870a5ea6164c`, application version `0.4.0`. Analysis covered CLI and HTTP handlers, scan/report/storage/network implementations, assessment capabilities and representative high-risk implementations, frontend API consumers, Earth startup configuration, and the existing test inventory. The index records 53 handwritten production Go files, 10,431 production lines, 40 test files and 156 named Go test functions. Generated Protobuf bindings are additional files.

This was a source and documentation analysis. It did not rerun the application test suites, benchmarks, Docker engine or Linux runtime. Existing verification reports are historical evidence, not newly reproduced results. Before implementation, confirm the baseline has not changed and regenerate the test/index inventory if it has.

The most consequential unknowns are Python filesystem confinement on Windows, exact DNS/TLS equivalence, cancellation of synchronous work, installed Nmap execution, and Docker's effect on host-local targets. They are early acceptance gates, not assumptions to postpone until release.
