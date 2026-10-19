# Guided investigations

The dashboard starts in Investigate. Its primary workflow is Add inputs → Confirm context → Review plan → Results. Saved results reopens individual reports. Advanced retains the specialist tools, inventory and coverage catalog. Earth console opens the existing geographic workspace.

## Start with the inputs you have

1. Paste one item per line, up to 20, and optionally attach up to five files of 8 MiB each.
2. Confirm each input's type. Format suggestions are deterministic and editable. Ambiguous text stays Other personal details / context. Uncheck inputs you do not want to include.
3. Review the proposed checks and their scope. Optional crawling starts unchecked. Changing a check clears the authorization confirmation.
4. Start the investigation. Steps run sequentially; a failed step does not prevent later selected steps from running. Each result shows its actual status and available evidence.

| Confirmed input | Selected behavior | Coverage limit |
| --- | --- | --- |
| Website / API URL | HTTPS response check and native page exposure review; optional linked-page crawler | HTTPS required. Exposure rules are a bounded subset, not the full Nuclei engine. Crawler visits at most eight same-origin pages at depth two. |
| Codebase directory | Existing source scanner | Directory inside the server workspace, three credential patterns. No repository cloning, code execution, dependency audit or SAST. |
| Domain | DNS and mail configuration | A/AAAA, NS, MX, SPF and DMARC using the system resolver. |
| Email | DNS and mail configuration of its domain | Does not check mailbox existence, delivery or ownership. |
| Photo / evidence file | File-byte analysis on the local server | SHA-256, MIME, entropy and signature candidates. No face recognition, reverse image search or EXIF location extraction. Use Advanced for capture, IAM and structured report analysis. |
| Profile URL | Manual review link to the supplied HTTP(S) URL | No account lookup or identity verification. |
| Instagram, Facebook, Threads or X username | Platform-specific manual link | Links are candidates, not evidence of account existence or ownership. |
| Person name, phone, address, company, app, other ID or details | Investigation context with an explicit unsupported status | No automated search, enrichment or identity inference. Add a confirmed domain, URL, platform username or evidence file to proceed with supported checks. |

The plan names the native module when relevant and describes whether it makes network requests. The original backend validates targets and enforces its existing network, workspace and input limits. The guided flow uses the existing API and does not install or invoke new external engines.

## Read and retain results

Results distinguish Completed, Limited, Failed, Needs manual review, No automated lookup, Not selected and Stopped. Expand a result to inspect findings, observations and coverage notes. A completed check does not establish that the input is safe or that a person's identity is verified.

The full investigation remains in memory while navigating between dashboard sections. Reloading the tab or starting another investigation discards that grouping. Export investigation downloads JSON containing input values, confirmed types, coverage and every step's outcome. Raw attached files are excluded from the export.

Individual normalized lab reports use the existing persistent store, which retains the newest 20 reports. Source/HTTPS check history uses the existing session-only store, which also retains 20 checks. Saved results separates these stores. Grouping does not survive a reload and cannot be reconstructed from the separate reports alone.

Stop investigation aborts the active client request and prevents remaining steps from starting. For a source/HTTPS check with a known run ID, the client also requests server cancellation. A server operation may have completed before the abort; check Saved results before retrying. Each automated step has a client timeout as well as the backend's existing limits.

## Verification

Validated on 19 October 2026 with the existing Docker dashboard API and the frontend development proxy. Eleven unit tests cover the existing recipes plus input suggestions, confirmed-type routing, deselection, optional crawling, validation, file limits and manual links. The production TypeScript/Vite build passes.

Browser verification used desktop and 390-pixel mobile viewports. It covered an actual source scan, an actual synthetic file upload and saved-report reopen, source failure with continued execution, manual/context statuses, JSON export, input correction, authorization, unchecked tasks, simulated API failure, stopping, navigation and Advanced access. No page runtime errors or horizontal overflow appeared in those checks. Live third-party website assessment and identity lookup were not exercised.

The dashboard container was rebuilt and restarted at port 8765. Its production frontend completed a source scan and opened the resulting check in Saved results at mobile width without runtime errors or horizontal overflow. Completing an investigation requests an immediate workspace refresh.
