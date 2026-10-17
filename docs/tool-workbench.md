# Security workbench

The workbench adds native diagnostics and offline evidence analysis to God's Eye. The Tools page accounts for all 26 requested references with an explicit implementation mode, upstream link, license observation and limitation. This is not a bundle of 26 installed engines, and it does not reproduce the full feature set of these products.

Open the local dashboard and select Workbench. The security pages use a black, neutral theme with compact navigation, visible keyboard focus and short button feedback. Reduced-motion preferences disable that feedback. World view and Earth console components and their styles are outside this change. The new theme is scoped out of both pages.

## Available workflows

| Workflow | Implemented behavior | Important limits |
| --- | --- | --- |
| Report import | 14 explicit XML, JSON/JSONL and CSV formats; normalized findings, observations, nodes and relationships | Supported fields only; imported results are not independently verified |
| TCP diagnostics | One hostname/IP, 1 to 32 explicit ports, four workers, connection status and elapsed time | One pinned resolved address; no service fingerprinting, raw packets, payloads or subnet sweeps |
| DNS review | A/AAAA, NS, MX, SPF and DMARC with mail-policy review notes | System resolver queries contact DNS infrastructure; no SPF include evaluation, DMARC inheritance, DNSSEC, DKIM guessing or comprehensive domain discovery |
| Capture analysis | Classic Ethernet PCAP, both byte orders and microsecond/nanosecond magic, IPv4/IPv6 conversations, TCP/UDP ports, ICMP counts | No PCAPNG, live capture, payload dissection, reassembly, decryption or IPv6 extension-header decoding |
| File analysis | MIME hint, SHA-256, byte entropy; up to 32 PNG/JPEG/PDF/ordinary ZIP signature candidates | Candidate byte ranges can be false positives or incomplete; no filesystem recovery, archive expansion or malware verdict |
| Cloud policy review | Static AWS IAM JSON review for wildcard actions/resources, public principals, selected sensitive actions and Allow/NotAction | No cloud credentials, provider connection or effective-permission simulation |
| Evidence graph | Search nodes, select a node, display up to 12 neighboring nodes, inspect directed relationship records | Per report; no cross-report correlation or BloodHound attack-path search |
| Data recipes | Chain 1 to 10 of 18 operations inside the browser | 64 KiB input and 256 KiB output; text-oriented encodings; JWT signatures and claims are not verified |
| Profile review | Manual public links from nine pinned Sherlock URL templates | No HTTP lookup, account-existence check, mass profile collection or identity inference |

The recipe operations are Base64 encode/decode, hex encode/decode, URL encode/decode, JSON format/minify, SHA-256/384/512, byte entropy, text defanging, ROT13, JWT inspection, hash-format hints, line sorting and line deduplication. Format hints cannot distinguish algorithms with the same output shape. Recipes and usernames are neither sent to the server nor persisted.

## Compatibility for the requested tools

| Reference | Available support | Not implemented |
| --- | --- | --- |
| Nmap | Native TCP diagnostics and Nmap XML service inventory | Nmap engine, NSE, OS detection |
| Wireshark | Native classic PCAP analysis and TShark packet JSON import | Wireshark dissectors, PCAPNG, live capture |
| Metasploit | MetasploitV5 XML host/service/vulnerability-label import | Exploits, payloads, credentials, loot and sessions |
| Aircrack-ng | Airodump-ng access-point CSV and OPN/WEP review | Radio collection, injection, deauthentication and cracking |
| Hashcat | Native hash-format hints and secure digest operations | Hashcat engine and password cracking |
| Skipfish | Existing HTTPS checks and generic offline HAR review | Skipfish engine, native report format and crawler |
| Foremost | Native file signatures and candidate byte-range recovery | Foremost code, deleted-block and filesystem recovery |
| sqlmap | Batch results CSV; empty technique rows remain observations | Injection execution and data extraction |
| hping3 | Native TCP connection timing | hping runtime, raw packets, spoofing and traffic generation |
| Shodan | Host, banner and search-result JSON/JSONL | Shodan account integration, live search or internet index |
| spiderdomain | Native single-domain DNS review as a related capability | The name remains unidentified; no exact upstream/parity claim |
| Maltego | Native evidence relationship graph | Proprietary transforms, Maltego code, MTGX |
| airgorha | Airgorah identified as the likely intended name; access-point CSV review | Airgorah runtime, GTK UI and Linux radio operations |
| Netcat | Native one-host TCP connectivity | Shell listeners, arbitrary relays and command execution |
| Passive reconnaissance | DNS infrastructure/mail-policy observations | Internet-wide discovery, authenticated data and crawling |
| SpiderFoot | Selected infrastructure event CSV | Module execution and personal-profile harvesting |
| Sherlock | Reused URL templates for manual review | Sherlock request/detection engine |
| recon-ng | Host/IP CSV and relationships | recon-ng modules/runtime |
| BBOT | Scoped infrastructure/finding JSON/JSONL | Recursive scanner and bundled AGPL code |
| CloudFox | Resource/endpoint CSV and native static IAM review | Cloud collection, permission simulation and inventory count matrices |
| Evilginx3 | Excluded; existing HTTPS transport checks remain available | Phishing proxy, credential/session interception and MFA bypass |
| Caido | Related native HTTP archive inspection if exchanges are supplied as HAR | Native Caido exports, proxy and replay |
| Nuclei | JSON/JSONL findings with severity and template identity | Engine execution and template packs |
| BloodHound | v5/v6 collection JSON, sensitive ACL/membership edges, delegation flags | ZIP/OpenGraph imports, collectors and attack-path computation |
| CyberChef | Two adapted helpers and native local recipe chains | Full engine, operation library and encryption suite |
| Burp Suite | Issue XML and generic HAR | Burp runtime, scanner, Intruder, interception and replay |

## Report field contracts

- Nmap: `nmaprun/host/address`, open `ports/port` state, protocol, port ID and service name/product/version. Missing successful run completion produces a coverage note. NSE output is not retained. [Official XML interface](https://nmap.org/book/output-formats-xml-output.html).
- Nuclei: `template-id`, `info.name`, `info.severity`, `matched-at` or `host`. Explicit false matcher results remain observations. Raw requests, responses, extracted results and reproduction commands are omitted. [Engine output definition](https://github.com/projectdiscovery/nuclei/blob/a151a1d54fad0d5ef71f01662b0bb3955a98c7c5/pkg/output/output.go).
- HAR: `log.version` and `log.entries`, request URL/method, response status, header names and elapsed time. No request replay. HTTP and absent HSTS are review candidates rather than definitive policy findings.
- Burp: `issues/issue` name, host, path, severity and confidence. Request/response blobs and embedded HTML descriptions are omitted.
- Shodan: service objects with `ip_str` and `port`, arrays, search `matches` wrappers and host `data` arrays. CVE identifiers are informational candidates, not verified vulnerabilities.
- BBOT: selected `DNS_NAME`, `IP_ADDRESS`, `URL`, `URL_UNVERIFIED`, `OPEN_TCP_PORT`, `STORAGE_BUCKET`, `FINDING` and `VULNERABILITY` events. Positive `scope_distance` events are omitted. [Reviewed event contract](https://github.com/blacklanternsecurity/bbot/blob/a6fb827bb144cdb85b52e142a4d6e14ed5f94b69/bbot/core/event/base.py).
- BloodHound: `meta.version` 5 or 6, `meta.type`, and `data` objects. ObjectIdentifier-based nodes preserve distinct directory objects with the same name. Selected ACE rights, membership and unconstrained-delegation flags produce review evidence.
- Aircrack: Airodump access-point header including BSSID, Privacy and ESSID. Parsing stops at Station MAC. Client stations and Key values are not retained.
- CloudFox: CSV with ARN, Endpoint, Resource or Name; Service/Type, Region, Account/Account ID and Public where available. Endpoint CSV headers were checked against [the upstream implementation](https://github.com/BishopFox/cloudfox/blob/d44899f21302269fc5e7743c662edafe15c7575c/aws/endpoints.go).
- SpiderFoot: Type and Data, with Module provenance. Only listed infrastructure event types are accepted; F/P=1 events are omitted. [Official CSV exporter](https://github.com/smicallef/spiderfoot/blob/master/sfwebui.py).
- recon-ng: host and/or ip_address columns, with host-to-IP edges when valid.
- sqlmap: Target URL, Place, Parameter and Technique(s). A row without a parameter or technique is an observation. [Official results-file header](https://github.com/sqlmapproject/sqlmap/blob/master/lib/core/target.py).
- Metasploit: MetasploitV5 XML nested host services and vulnerability names. Top-level duplicated service records and credential/session/loot content are omitted. [Official exporter](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/db_export.rb).
- TShark: `-T json` array/records with `_source.layers`, frame protocol names and IPv4/IPv6 source/destination metadata. Export JSON from Wireshark when PCAPNG or unsupported capture types need conversion. [Wireshark export documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html).

Malformed or incompatible input fails without saving a report. Each upload is limited to 8 MiB. JSON record streams/arrays over 10,000 records must be split. Each report retains at most 1,000 findings, observations, nodes and edges per collection, with explicit limits/coverage. Output limits may omit evidence. Raw input size and parsed-object allocations are bounded by input policy, not an operating-system memory sandbox.

## Storage, privacy and access

Normalized reports persist as owner-created JSON files in `<state>/evidence/`. Writes use a temporary file, sync and rename. The newest 20 reports are retained; older reports are pruned. Export important results before importing enough reports to trigger retention. Source/HTTPS check history still uses the existing session-only run list.

Raw upload bytes are not saved. Recovery downloads slice the original File in the browser tab; reopening an old report does not recreate file contents. Titles, paths, IPs, directory identifiers and resource names are retained. Normalization is not a universal secret scrubber. URL userinfo, query strings and fragments are removed from normalized targets, and HTTP bodies/cookies/authorization headers are not selected for import.

The workbench uses the dashboard's loopback binding, Host/Origin checks and custom request header. There are at most two simultaneous workbench operations, a 12-second handler context, and 10-second network deadlines. TCP allows explicitly requested local/private targets but rejects unspecified, multicast, link-local and the selected cloud-metadata address range. Other local processes remain trusted. The app is not a multi-user service or a sandbox for hostile local users.

## Source reuse and licensing review

Five upstream repositories were shallow/sparse cloned for review under ignored `.godseye/tool-research/`. No upstream scripts or scanners were executed. These checkouts are research inputs, not a runtime dependency or a redistributed source bundle.

| Repository | Reviewed commit | Reuse |
| --- | --- | --- |
| [CyberChef](https://github.com/gchq/CyberChef) | `cc70a4530b86aff4bc40ccc74b1ad4857eccdca2` | Adapted calculateShannonEntropy from Entropy.mjs and defangURL from DefangURL.mjs; typed standalone functions, normalized zero entropy, fixed options; Apache-2.0 |
| [Sherlock](https://github.com/sherlock-project/sherlock) | `e40a45ec2a074b90703b3b4b842c8a3adbd6ada3` | Nine name/url/regexCheck data entries; MIT |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | `a151a1d54fad0d5ef71f01662b0bb3955a98c7c5` | Output schema reviewed; no engine source copied |
| [BBOT](https://github.com/blacklanternsecurity/bbot) | `a6fb827bb144cdb85b52e142a4d6e14ed5f94b69` | Event/output schema reviewed; no AGPL source copied |
| [CloudFox](https://github.com/BishopFox/cloudfox) | `d44899f21302269fc5e7743c662edafe15c7575c` | Endpoint/resource output reviewed; no AWS SDK or engine source copied |

Full reused licenses are retained in `licenses/cyberchef.txt` and `licenses/sherlock.txt`, with copyrights and upstream paths in source headers and NOTICE. All other new Go analysis code, parsers and native recipe implementations are original Apache-2.0 code.

[Nmap's legal notice](https://nmap.org/book/man-legal.html) describes special embedding/redistribution conditions. [BBOT](https://github.com/blacklanternsecurity/bbot) uses AGPL-3.0. Wireshark, Aircrack and recon-ng have copyleft terms that need separate review before code incorporation. Shodan is a hosted service; Maltego, Caido and [Burp](https://portswigger.net/burp/tc-community) product access does not grant source reuse rights. A related native workflow is not a claim that a proprietary suite has been copied or reproduced. Foremost's exact selected-version license was not established, so none of its source was reused. Engine and rule/data licenses must be checked separately for any future bundling.

## CLI and API

The normal build includes the workbench CLI. Flags precede paths.

```powershell
godseye lab catalog
godseye lab import --format nmap --out evidence.json authorized-assessment.xml
godseye lab import --format nuclei assessment.jsonl
godseye lab file sample.bin
godseye lab pcap authorized-capture.pcap
godseye lab iam policy.json
godseye lab tcp --target 127.0.0.1 --ports 80,443,8765 --authorized
godseye lab dns --target your-domain.example --authorized
```

CLI reports go to stdout or a new exclusive `--out` file and are not added to dashboard history. Exit 0 means processing succeeded, even if findings require review; 2 means invalid input/output failure; 3 means an explicit processing limit or cancellation left partial coverage. Source-scan exit codes remain unchanged. Saved report IDs belong to dashboard reports; standalone CLI report IDs are empty.

The dashboard exposes `GET /api/lab/catalog`, `GET /api/lab/reports`, `GET /api/lab/reports/{id}`, `POST /api/lab/import?format=ID`, `POST /api/lab/file?mode=file|pcap|iam`, and `POST /api/lab/diagnose`. Uploads send raw file bytes. Diagnostics accept mode, target, ports and authorized fields. Mutation requests require `X-GodsEye-Request: 1` in the same loopback origin.
