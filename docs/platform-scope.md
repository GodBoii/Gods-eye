# Platform scope and native capability plan

The platform organizes source repositories, deployed websites, APIs, backend services, applications, databases, cloud resources, containers and networks. An inventory entry records scope; it is not evidence that an asset has been assessed. Access to private data or authenticated services requires explicit credentials and authorization in a future connector. No system can collect or assess all internet data.

## Available in 0.3

The React dashboard runs on the local Go server. You can register assets, filter the inventory, prepare a check, confirm the authorized target, run or cancel a check, inspect results and export reports. Inventory persists in `.godseye/assets.json`; the last 20 check results remain in memory for the server session. Export reports before stopping the server.

The separate [World view](world-view.md) adds a keyless vector globe, USGS earthquakes, NASA natural events, calculated CelesTrak station positions, a regional ADSB.lol aircraft layer, browser-local pins and GeoJSON export. It reuses two attributed MIT helpers from the God's Eye View reference repository. These geographic layers do not assess the security of registered assets.

Source checks use the existing three credential-pattern rules. Website, API, backend and application checks issue a single HEAD request to an explicit public HTTPS endpoint on port 443. They verify the TLS connection normally, report certificate expiry, and inspect selected response headers. Presence is distinguished from effective policy. Redirects are not followed, response bodies are not collected, and private/local/reserved destinations are rejected after DNS resolution. There is no crawler, injection tester or authentication bypass.

Other asset categories support inventory only. The UI shows that limitation. The dashboard is restricted to 127.0.0.1, checks Host and Origin, requires a custom header for mutations, and does not expose a public multi-user service. Other processes running as the local user remain trusted. This is not a hardened hostile-local-user boundary.

The source checker confines targets to the workspace configured with `serve --root`. The UI cannot request an arbitrary directory outside that workspace. Scan exclusions include `.godseye` and `dist`, in addition to the existing generated/dependency directories. The root is still a live checkout, not an immutable snapshot.

The security workbench now adds report imports, TCP/DNS diagnostics, offline PCAP/file analysis, static AWS IAM policy review, local data recipes and evidence graphs. Its normalized reports persist separately in `<state>/evidence/`, retaining the newest 20. These workflows do not automatically assess an inventory entry. Use Workbench to select the appropriate input or explicit network target. Its black theme is scoped out of World view and Earth console.

## Operating systems

Windows is supported for the current local CLI and dashboard. Ubuntu LTS is the intended first Linux server target because predictable maintenance is useful for production collectors. Arch is optional, not a prerequisite for defensive security work. Kernel-level telemetry and network routing will require separately tested Linux components and appropriate privileges. Neither a distribution nor a collection of pentesting tools automatically makes the platform secure.

## Tool-list interpretation

The [workbench guide](tool-workbench.md) and Tools page now document all 26 requested references. Native subsets and report compatibility are implemented. External scanner engines and commercial product code are not bundled or launched. Two CyberChef algorithms and nine Sherlock URL templates are reused with pinned provenance and full license notices.

| Reference tools | Available capability | Remaining scope |
| --- | --- | --- |
| Nmap, hping3, netcat | Native TCP diagnostics; Nmap service XML import | No raw packets, OS fingerprinting, NSE, shell listeners or scanner engine |
| Wireshark | Classic Ethernet PCAP conversation metadata and TShark JSON | No live capture, PCAPNG, dissectors or reassembly |
| Metasploit | Database XML host/service/vulnerability labels | No exploits, payloads, sessions, credentials or loot |
| Aircrack-ng, Airgorah | Airodump access-point CSV and OPN/WEP review | No radio operations, deauthentication or cracking; Airgorah is the likely intended spelling |
| Hashcat | Hash-format hints and local digest operations | No password-cracking engine |
| Skipfish, sqlmap, Nuclei | HTTPS checks, sqlmap CSV and Nuclei JSON/JSONL evidence | No Skipfish parser, crawler, injection or template execution |
| Foremost | Native file identification and PNG/JPEG/PDF/ZIP recovery candidates | No upstream Foremost code or filesystem recovery |
| Shodan, spiderdomain, passive reconnaissance | Shodan export import; native DNS/mail-policy review | No live Shodan account or hosted index; spiderdomain remains unidentified |
| Maltego, SpiderFoot, Sherlock, recon-ng, BBOT | Evidence graphs, infrastructure report imports and manual profile links | No commercial transforms, recursive execution or automated personal-profile harvesting |
| CloudFox | Resource/endpoint CSV and static IAM policy review | No live cloud collection or effective-permission simulation |
| Evilginx3 | Excluded | No phishing proxy or credential/session capture |
| Caido, Burp Suite | Generic HAR inspection and Burp issue XML | No native Caido project import, proxy, replay or scanner engine |
| BloodHound | Collection JSON ACL/membership edges and delegation review | No collector, ZIP/OpenGraph import or attack-path search |
| CyberChef | Eighteen local recipe operations, two adapted helpers | No full engine or encryption suite |

The named tools solve different problems and represent substantial engineering work. Their capabilities should be delivered in tested modules, not represented by nonfunctional buttons or copied branding. Native code should use documented protocols and original tests. Any future source reuse needs exact-version license review and attribution.

## Licensing observations

[Nmap's NPSL](https://nmap.org/npsl/) has additional embedding and redistribution conditions; it should not be treated as a generic permissive dependency. [Nuclei's engine](https://github.com/projectdiscovery/nuclei) is MIT-licensed, but engine and template/data licensing must be evaluated independently. [Burp Community](https://portswigger.net/burp/tc-community) is governed by its software terms; a free edition is not a source-code reuse license. No paid service or commercial tool is required by the current implementation.

## Next implementation modules

1. Durable source/HTTPS check history, asset-linked evidence and schema migrations. Workbench evidence already persists with a 20-report retention limit.
2. Native dependency inventory, SBOM output and advisory lookups with an offline mode.
3. API schema import and endpoint coverage, then bounded authenticated checks using explicit credential storage.
4. IaC analysis, runtime observations and a graph linking deployments, services and findings.
5. Broader diagnostic coverage and isolated verification workflows, selected by actual project needs.

Proxy, VPN, privileged collection and broad reconnaissance remain separate workstreams. The dashboard architecture leaves room for them without claiming they exist.
