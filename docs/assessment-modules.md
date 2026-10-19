# Assessment modules

The Assessments tab runs native analysis modules for the 26 requested tool references. These are original, bounded implementations with explicit coverage limits. They do not install or reproduce the full external suites. Nmap additionally supports an optional installed engine. Availability on the current machine is reported separately from native functionality.

Every assessment returns normalized findings, observations, relationships and coverage gaps. The API and CLI call the same dispatcher. Dashboard reports persist in the evidence store; CLI output is written only to stdout or a new output file.

## Run a module

Open Advanced > Specialist tools > Assessments, select a module, read its input instructions, then supply a target, text or file. Confirm authorization and run. For a guided plan from your inputs, start in Investigate. A module's name identifies the related workflow, not proof that the vendor's engine ran. Execution provenance and limitations are included in the result.

Files up to 6 MiB are encoded for the JSON request. The server caps the encoded input at 8 MiB. Individual modules can impose smaller limits. Recovery downloads use the original file retained in the browser tab and are unavailable after reopening a saved report without that file.

```powershell
godseye lab catalog
godseye lab assess --tool nuclei --target https://your-authorized-domain.example/ --authorized
godseye lab assess --tool skipfish --target https://your-authorized-domain.example/ --authorized
godseye lab assess --tool nmap --target your-authorized-host.example --ports 80,443 --authorized
godseye lab assess --tool nmap --engine --target your-authorized-host.example --ports 80,443 --authorized
godseye lab assess --tool wireshark --authorized capture.pcapng
godseye lab assess --tool cloudfox --authorized template.json
godseye lab assess --tool burp --authorized api-evidence.json
```

Flags precede the optional input file. `--out` creates a new report and refuses overwrite. CLI exit 0 means processing completed, 2 means an invalid request or execution/output error, and 3 means the report marks processing limited. Findings can be present with exit 0; read the evidence rather than interpreting exit 0 as secure.

Some evidence-only or defensive modules intentionally mark coverage limited even when parsing completes. Exit 3 therefore requires reading the coverage notes; it does not always mean a runtime failure.

## Implemented coverage

| Module | Added functionality | Input | Remaining limits |
| --- | --- | --- | --- |
| Nmap | Multiple resolved addresses, TCP states, server banners, known-port TLS verification; optional installed Nmap connect/service scan | Host and explicit ports | No NSE, UDP, OS fingerprinting or exploit verification; engine mode uses one pinned address |
| Wireshark | PCAPNG section/interface/enhanced-packet validation and Ethernet conversations, alongside classic PCAP | Capture bytes | No live capture, full dissectors, reassembly or decryption |
| Metasploit | Service-correlated vulnerability/advisory triage and remediation provenance | MetasploitV5 XML | No engine, payloads, sessions, live advisory lookup or exploitability proof |
| Aircrack-ng | 802.11/radiotap beacon protection review and management-event counts | Classic wireless PCAP or Airodump CSV | No live radio operations, injection, cracking or WPA3 enforcement verification |
| Hashcat | Supplied candidate verification against SHA-256/384/512 digests, short-match and reuse review | JSON described below | No Hashcat engine, salted formats or online attempts; sensitive values omitted |
| Skipfish | Same-origin crawling, selected headers, HTTP errors, insecure form/resource references | Explicit root URL | Eight pages, depth two; no scripts, form submission, authenticated flows or mutation testing |
| Foremost | Structurally checked PNG, GIF, uncompressed BMP and PCM WAV ranges | File bytes | 32 artifacts; no decompression, filesystem reconstruction or deleted-block recovery |
| sqlmap | Database error families, error-associated SQL disclosure, captured request/error correlation | One baseline URL or HAR with response content | No sqlmap engine, generated injection probes, database extraction or permission audit |
| hping3 | Fixed repeated TCP samples, success ratio and latency min/median/max | Host and up to eight ports | No raw packet engine, floods, spoofing or application protocol timing |
| Shodan | Indexed CVE assertion provenance, service freshness, TLS expiry and explicit anonymous-service metadata | Export JSON/JSONL; optional exact IP filter | No live API, fresh internet index or independent vulnerability verification |
| spiderdomain | DNS alias/PTR enrichment and zone inventory policy/conflict review | Domain or zone JSON | Upstream name remains unresolved; no takeover proof, zone transfer or exhaustive DNS discovery |
| Maltego | Cross-report entity merging, directed shortest paths and provenance | Normalized report JSON | Exact identities only; no commercial transforms or external collection |
| Airgorah | Wireless security and metadata changes between snapshots | Two Airodump CSV strings in JSON | No active radio workflow or impersonation proof |
| Netcat | Fixed HTTP HEAD, SMTP EHLO/QUIT, Redis PING and Memcached version probes; other ports read banners | Host and up to eight ports | No arbitrary payloads, shells, listeners, relays or TLS negotiation |
| Passive reconnaissance | Scoped historical certificate names and graph; native DNS plus normally verified public TLS SAN collection | Domain, optionally CT JSON | No live CT API query, brute force or requests to discovered names |
| SpiderFoot | Scoped event correlation, parent assertions, module diversity and exposure review | Domain plus official JSON or selected CSV | No module execution, personal profiling or proof of independent sources |
| Sherlock | Response-state, soft-404, canonical/path and freshness evidence review | Explicit profile-observation JSON | No platform enumeration, live lookup, identity inference or account-existence claims |
| recon-ng | Before/after host/IP reconciliation and source-set comparison | Inventory snapshots JSON | No recon-ng runtime or proof that absent hosts were decommissioned |
| BBOT | Scoped recursive-scan evidence graph, parent provenance and missing-coverage frontier | Domain plus infrastructure JSON/JSONL | No live recursive engine or ownership proof |
| CloudFox | Static CloudFormation S3, RDS, security group and IAM checks with resource graph | CloudFormation or IAM JSON | No live cloud inventory or effective-permission simulation; intrinsics can remain unknown |
| Evilginx risk defenses | Session cookies, HSTS, framing, caching and password-form configuration review | URL or HAR | Defensive assessment only; no phishing, credential collection, interception or MFA bypass |
| Caido | Paired capture comparison and owner-defined expected-denial review | Two HARs in JSON | No proxy or replay; differences do not prove authorization bypass |
| Nuclei | Native directory listing, traceback, embedded-source map and cookie configuration rules | One URL; existing report import also retained | No Nuclei engine/template pack or comprehensive vulnerability coverage |
| BloodHound | Cross-collection directed candidate control paths over selected ACL/membership edges | Collection JSON plus exact start/end IDs | No collector, live directory query or proof of effective exploitability |
| CyberChef | Offline JWT policy/lifetime and public-certificate security review; existing browser recipes remain | JWT/PEM inspection JSON | No JWT signature verification, key fetching, private-key processing or full CyberChef engine |
| Burp Suite | Captured API method/path, status, parameter and media-type contract review | OpenAPI 3 plus HAR JSON | No Burp engine, interception, replay or authenticated behavioral testing |

The full current schema hints are returned by `GET /api/lab/capabilities`. `GET /api/lab/catalog` preserves the reference/source/license catalog, with current assessment coverage. `POST /api/lab/assess` accepts:

```json
{"tool":"nuclei","target":"https://your-authorized-domain.example/","input":"","encoding":"text","ports":[],"authorized":true,"runEngine":false}
```

Mutation requests require `X-GodsEye-Request: 1` and the normal loopback Host/Origin protections. Unknown request fields are rejected. At most two assessment requests run concurrently, each with a 45-second deadline. Existing import/diagnostic handlers retain their separate operation limit. Reports are saved through the existing bounded evidence store.

## Offline input examples

These are synthetic schemas, not claims about real targets. Use actual exported evidence when assessing a system.

```json
{"algorithm":"sha256","hashes":["hexadecimal digest"],"candidates":["owner-supplied local candidate"]}
```

```json
{"origin":"example.test","complete":true,"records":[{"name":"@","type":"TXT","value":"v=spf1 -all"}]}
```

Only declare a zone complete if it actually is. Missing-record conclusions otherwise remain unknown.

```json
{"reports":[{"id":"...","tool":"...","nodes":[],"edges":[]}],"from":"exact label","to":"exact label"}
```

The Maltego input accepts the full normalized report objects exported by this application; the abbreviated object above shows the relevant fields.

```json
{"before":"Airodump access-point CSV text","after":"Airodump access-point CSV text"}
```

```json
{"username":"test","profiles":[{"url":"https://example.test/test","status":200,"title":"Example","canonical":"https://example.test/test","observedAt":"2026-10-18T00:00:00Z"}]}
```

```json
{"domain":"example.test","before":[{"host":"a.example.test","ip_address":"192.0.2.1","source":"inventory"}],"after":[]}
```

```json
{"baseline":{"log":{"version":"1.2","entries":[]}},"candidate":{"log":{"version":"1.2","entries":[]}},"expectDenied":["/private"]}
```

```json
{"collections":[{"meta":{"type":"groups","version":6},"data":[]}],"start":"exact ObjectIdentifier","end":"exact ObjectIdentifier"}
```

Provide collected objects and relationships for BloodHound analysis. Display names and reference-only identities cannot substitute for collected endpoint identifiers.

```json
{"kind":"jwt","value":"encoded token","expectedIssuer":"optional issuer","expectedAudience":"optional audience"}
```

```json
{"kind":"pem","value":"public certificate PEM"}
```

```json
{"spec":{"openapi":"3.0.3","paths":{}},"har":{"log":{"version":"1.2","entries":[]}}}
```

## Access and dependencies

The optional Nmap path discovers an installed `nmap` on PATH and runs a fixed argument list against a validated pinned address. It does not accept command strings, executable paths, user templates or shell fragments. Native mode does not require Nmap. No scanner package is silently installed.

Authenticated application testing, live database/cloud/directory inspection, packet collection and hardware-backed wireless work require separate access or collectors. The current modules do not claim to audit those systems solely from a public domain. Source checks still cover the original three credential patterns; dependency/SAST analysis has not been added by these modules.

New network checks require explicit targets, use bounded requests and do not follow redirects. The crawler stays within the root origin and skips query and likely state-changing links. Some diagnostic modules intentionally support local/private fixtures; metadata and other selected special-purpose destinations are rejected. This is a local trusted-user application, not a public multi-tenant scanning service.
