# Platform scope and native capability plan

The platform organizes source repositories, deployed websites, APIs, backend services, applications, databases, cloud resources, containers and networks. An inventory entry records scope; it is not evidence that an asset has been assessed. Access to private data or authenticated services requires explicit credentials and authorization in a future connector. No system can collect or assess all internet data.

## Available in 0.3

The React dashboard runs on the local Go server. You can register assets, filter the inventory, prepare a check, confirm the authorized target, run or cancel a check, inspect results and export reports. Inventory persists in `.godseye/assets.json`; the last 20 check results remain in memory for the server session. Export reports before stopping the server.

The separate [World view](world-view.md) adds a keyless vector globe, USGS earthquakes, NASA natural events, calculated CelesTrak station positions, a regional ADSB.lol aircraft layer, browser-local pins and GeoJSON export. It reuses two attributed MIT helpers from the God's Eye View reference repository. These geographic layers do not assess the security of registered assets.

Source checks use the existing three credential-pattern rules. Website, API, backend and application checks issue a single HEAD request to an explicit public HTTPS endpoint on port 443. They verify the TLS connection normally, report certificate expiry, and inspect selected response headers. Presence is distinguished from effective policy. Redirects are not followed, response bodies are not collected, and private/local/reserved destinations are rejected after DNS resolution. There is no crawler, injection tester or authentication bypass.

Other asset categories support inventory only. The UI shows that limitation. The dashboard is restricted to 127.0.0.1, checks Host and Origin, requires a custom header for mutations, and does not expose a public multi-user service. Other processes running as the local user remain trusted. This is not a hardened hostile-local-user boundary.

The source checker confines targets to the workspace configured with `serve --root`. The UI cannot request an arbitrary directory outside that workspace. Scan exclusions include `.godseye` and `dist`, in addition to the existing generated/dependency directories. The root is still a live checkout, not an immutable snapshot.

## Operating systems

Windows is supported for the current local CLI and dashboard. Ubuntu LTS is the intended first Linux server target because predictable maintenance is useful for production collectors. Arch is optional, not a prerequisite for defensive security work. Kernel-level telemetry and network routing will require separately tested Linux components and appropriate privileges. Neither a distribution nor a collection of pentesting tools automatically makes the platform secure.

## Tool-list interpretation

The user's latest preference is to build native capabilities, without integrating external tools for now. None of the following tools is bundled, launched or copied into this build. This table records capability ideas, not completed replacements or claims of equivalence.

| Reference tools | Native capability to consider | Status |
| --- | --- | --- |
| Nmap, hping3, netcat | Scoped service inventory, connectivity and protocol diagnostics | Planned; no port sweep or packet generation |
| Wireshark | Offline packet-file analysis and protocol summaries | Planned; no packet capture |
| Metasploit | Reproducible verification of selected findings in isolated test environments | Planned; no exploit runner |
| Aircrack-ng, “airgorha” | Wireless configuration and capture review | Planned; “airgorha” is unidentified, possibly a different wireless project |
| Hashcat | Password-policy and authorized offline hash assessment | Planned; no credential-cracking engine |
| Skipfish, sqlmap, Nuclei | Website/API checks with bounded rules and evidence | HTTPS headers/TLS only today; no injection or exploitation |
| Foremost | File-type identification and authorized offline recovery | Planned |
| Shodan, “spiderdomain”, passive reconnaissance | Public asset discovery with provenance and explicit domain scope | Planned; “spiderdomain” is not an identified repository |
| Maltego, SpiderFoot, Sherlock, recon-ng, BBOT | Evidence-backed asset relationships, public-source enrichment and entity resolution | Planned; no personal-profile collection or mass harvesting |
| CloudFox | Read-only cloud inventory and permission analysis | Planned; requires scoped provider access |
| Evilginx3 | Session-security assessment using controlled test fixtures | No reverse-proxy credential or session-token capture implemented |
| Caido, Burp Suite | Request/response inspection and API test workspaces | Planned; no intercepting proxy or certificate installation |
| BloodHound | Permission and identity relationship graphs | Planned; requires authorized directory data |
| CyberChef | Local encoding, hashing, parsing and data inspection | Planned |

The named tools solve different problems and represent substantial engineering work. Their capabilities should be delivered in tested modules, not represented by nonfunctional buttons or copied branding. Native code should use documented protocols and original tests. Any future source reuse needs exact-version license review and attribution.

## Licensing observations

[Nmap's NPSL](https://nmap.org/npsl/) has additional embedding and redistribution conditions; it should not be treated as a generic permissive dependency. [Nuclei's engine](https://github.com/projectdiscovery/nuclei) is MIT-licensed, but engine and template/data licensing must be evaluated independently. [Burp Community](https://portswigger.net/burp/tc-community) is governed by its software terms; a free edition is not a source-code reuse license. No paid service or commercial tool is required by the current implementation.

## Next implementation modules

1. Durable check history, asset-linked evidence, schema migrations and retention controls.
2. Native dependency inventory, SBOM output and advisory lookups with an offline mode.
3. API schema import and endpoint coverage, then bounded authenticated checks using explicit credential storage.
4. IaC analysis, runtime observations and a graph linking deployments, services and findings.
5. Native diagnostic utilities and isolated verification workflows, selected by actual project needs.

Proxy, VPN, privileged collection and broad reconnaissance remain separate workstreams. The dashboard architecture leaves room for them without claiming they exist.
