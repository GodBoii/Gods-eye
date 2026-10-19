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
| Email | Local address analysis, domain DNS/mail configuration and optional XposedOrNot breach lookup | The breach lookup starts unchecked and sends the address to XposedOrNot when selected. No mailbox probing or ownership check. |
| International phone number | Local E.164 normalization, national/international formats, calling code, numbering-plan region/type and public search links | Include a +country code. Metadata describes numbering plans, not current carrier, active service, owner or location. No phone breach database is connected. |
| Other username / ID | Candidate profile links from supported pinned templates and exact-identifier public search links | Links are unverified. Unsupported handle punctuation/length uses search links only. Numeric IDs need a confirmed platform to establish meaning. No username breach database is connected. |
| Person name | Exact-name public research links and source-verification guidance | Confirm this type manually. Names are not unique; no identity inference or name breach database is connected. |
| Photo / evidence file | File-byte analysis on the local server | SHA-256, MIME, entropy and signature candidates. No face recognition, reverse image search or EXIF location extraction. Use Advanced for capture, IAM and structured report analysis. |
| Profile URL | Manual review link to the supplied HTTP(S) URL | No account lookup or identity verification. |
| Instagram, Facebook, Threads or X username | Platform-specific manual link | Links are candidates, not evidence of account existence or ownership. |
| Address, company, app or other details | Investigation context with an explicit unsupported status | No automated search, enrichment or identity inference. Add a confirmed domain, URL, platform username or evidence file to proceed with supported checks. |

The plan names the native module when relevant and describes whether it makes network requests. The original backend validates targets and enforces its existing network, workspace and input limits. The guided flow uses the existing API and does not install or invoke new external engines.

## Identifier research and breach coverage

Phone analysis runs locally using libphonenumber-js 1.13.15 with full numbering metadata. A pattern match does not establish that a number is assigned or reachable. Local-only numbers require correction to an international format rather than assuming a country. Plain numeric strings remain ambiguous context until you confirm their type.

Email parsing preserves the local part's case, dots and plus tags and lowercases only its domain. It does not merge possible aliases. Username templates do not probe account registration or sign-in. Person names support Unicode. Public Google/Bing query links and profile candidates make no network request until opened, when the destination receives the query. Other inputs are never assumed to belong to a named person.

The optional breach step uses `POST /api/lab/email-breaches` with `{ "email": "name@example.com", "authorized": true }`. The server makes one HTTPS request to the fixed [XposedOrNot check-email endpoint](https://xposedornot.com/api_doc). There is no API key or paid dependency. As documented on 19 October 2026, the provider permits 2 requests/second, 25/hour and 100/day per IP. The app limits starts to one per second and waits at least a minute after a provider 429; hourly/daily caps may require a longer wait. No automatic retries run.

Provider responses have an eight-second timeout and a 256 KiB response limit. Redirects are not followed. Malformed, oversized, unexpected, throttled and unavailable responses fail the step; they are never converted into a no-breach result. A documented not-found response means only that the provider returned no indexed breach. There are no raw password, leaked database, phone, name or username breach searches.

Successful breach reports use the existing evidence store, including source, check time, returned breach names, coverage and account-security next steps. They omit the submitted email, its hash and unrecognized provider fields. The full investigation export retains the input and its association with each report. Domain DNS reports retain the domain as before. Local identifier facts and review links exist only in the in-memory investigation and its export. The separate Python migration candidate does not implement this new endpoint yet; use the default Go dashboard.

## Read and retain results

Results distinguish Completed, Limited, Failed, Needs manual review, No automated lookup, Not selected and Stopped. Expand a result to inspect findings, observations and coverage notes. A completed check does not establish that the input is safe or that a person's identity is verified.

The full investigation remains in memory while navigating between dashboard sections. Reloading the tab or starting another investigation discards that grouping. Export investigation downloads JSON containing input values, confirmed types, coverage and every step's outcome. Raw attached files are excluded from the export.

Individual normalized lab reports use the existing persistent store, which retains the newest 20 reports. Source/HTTPS check history uses the existing session-only store, which also retains 20 checks. Saved results separates these stores. Grouping does not survive a reload and cannot be reconstructed from the separate reports alone.

Stop investigation aborts the active client request and prevents remaining steps from starting. For a source/HTTPS check with a known run ID, the client also requests server cancellation. A server operation may have completed before the abort; check Saved results before retrying. Each automated step has a client timeout as well as the backend's existing limits.

## Verification

Identifier research was checked on 19 October 2026 with 16 frontend tests, the Go suite, Go vet and a production frontend build. Browser checks at 1440 and 390 pixels covered type correction, international phone validation, default-off breach selection, a live lookup using the provider's documented `test@example.com` sample, private saved-report contents, JSON export, expanded source links and continuation after a simulated provider outage. No page errors or horizontal overflow appeared. These checks did not submit real personal identifiers or verify ownership of search results. The production build reports a bundle-size warning after including full phone metadata.

Validated on 19 October 2026 with the existing Docker dashboard API and the frontend development proxy. Eleven unit tests cover the existing recipes plus input suggestions, confirmed-type routing, deselection, optional crawling, validation, file limits and manual links. The production TypeScript/Vite build passes.

Browser verification used desktop and 390-pixel mobile viewports. It covered an actual source scan, an actual synthetic file upload and saved-report reopen, source failure with continued execution, manual/context statuses, JSON export, input correction, authorization, unchecked tasks, simulated API failure, stopping, navigation and Advanced access. No page runtime errors or horizontal overflow appeared in those checks. Live third-party website assessment and identity lookup were not exercised.

The dashboard container was rebuilt and restarted at port 8765. Its production frontend completed a source scan and opened the resulting check in Saved results at mobile width without runtime errors or horizontal overflow. Completing an investigation requests an immediate workspace refresh.
