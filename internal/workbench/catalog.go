// SPDX-License-Identifier: Apache-2.0
package workbench

type Tool struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Category  string `json:"category"`
	License   string `json:"license"`
	Source    string `json:"source"`
	Mode      string `json:"mode"`
	Available string `json:"available"`
	Limit     string `json:"limit"`
}

// Available describes implemented behavior, never engine parity or installation.
func Catalog() []Tool {
	return []Tool{
		{"nmap", "Nmap", "Network", "NPSL; separate embedding terms", "https://nmap.org/book/man-legal.html", "Native + import", "TCP connect diagnostics and Nmap XML service inventory", "Nmap is not bundled or launched. No OS fingerprinting or NSE execution."},
		{"wireshark", "Wireshark", "Network", "GPL-2.0-or-later", "https://www.wireshark.org/faq.html", "Native + import", "Classic Ethernet PCAP conversations and TShark JSON metadata", "No live capture, PCAPNG parsing, protocol dissector library or decryption."},
		{"metasploit", "Metasploit Framework", "Assessment", "BSD-style; components vary", "https://github.com/rapid7/metasploit-framework", "Import", "MetasploitV5 database XML host, service and vulnerability labels", "No exploit, payload, session, credential or loot execution/import."},
		{"aircrack", "Aircrack-ng", "Wireless", "GPL-2.0; components vary", "https://github.com/aircrack-ng/aircrack-ng", "Import", "Airodump-ng access-point CSV and weak protection review", "No radio capture, deauthentication, injection or password cracking."},
		{"hashcat", "Hashcat", "Data", "MIT; review selected dependencies", "https://github.com/hashcat/hashcat", "Native subset", "Hash format hints and SHA-256/384/512 in local recipes", "Hash lengths are ambiguous. No cracking engine or proof of password strength."},
		{"skipfish", "Skipfish", "Web", "Apache-2.0", "https://github.com/spinkham/skipfish", "Native subset", "Existing HTTPS response checks and offline HAR review", "No Skipfish engine, crawling, mutation testing or native Skipfish report parser."},
		{"foremost", "Foremost", "Forensics", "Exact upstream license requires version review", "https://foremost.sourceforge.net/", "Native subset", "File signature identification and PNG/JPEG/PDF/ZIP byte-range recovery", "No Foremost source bundled, filesystem reconstruction or deleted-block recovery."},
		{"sqlmap", "sqlmap", "Web", "GPL-2.0 with upstream clarifications", "https://github.com/sqlmapproject/sqlmap", "Import", "sqlmap batch result CSV vulnerability records", "No SQL injection execution or database extraction."},
		{"hping3", "hping3", "Network", "GPL-2.0", "https://github.com/antirez/hping", "Native subset", "TCP connection status and timing for explicit ports", "No raw packets, spoofing, traffic floods or hping engine."},
		{"shodan", "Shodan", "Discovery", "Proprietary hosted service; SDK licenses separate", "https://developer.shodan.io/api", "Import", "Host, service and search-export JSON/JSONL", "No API account required. No hosted internet index or live Shodan search."},
		{"spiderdomain", "Spiderdomain, unresolved name", "Discovery", "No verified upstream identity", "https://www.spiderfoot.net/", "Native subset", "Single-domain DNS records and mail-policy review", "The name could not be tied to a definitive project. No parity claim."},
		{"maltego", "Maltego", "Discovery", "Proprietary desktop platform", "https://www.maltego.com/", "Native subset", "Evidence relationship graph with searchable nodes and typed edges", "No Maltego code, commercial transforms, account data or MTGX parser."},
		{"airgorah", "Airgorah", "Wireless", "MIT", "https://github.com/martin-olivier/airgorah", "Native subset", "Access-point metadata review through Airodump CSV", "Likely match for airgorha. Linux radio functions are not integrated."},
		{"netcat", "Netcat", "Network", "Varies by implementation", "https://nmap.org/ncat/", "Native subset", "One-host TCP connectivity without external binaries", "No shell listeners, command execution, arbitrary relays or netcat binary."},
		{"passive-recon", "Passive reconnaissance", "Discovery", "Methodology; native Apache-2.0 implementation", "https://www.rfc-editor.org/rfc/rfc1035", "Native", "DNS A/AAAA, NS, MX, SPF and DMARC observations", "System DNS queries contact infrastructure. No CT feed, subdomain brute-force or internet-wide collection."},
		{"spiderfoot", "SpiderFoot", "Discovery", "MIT", "https://github.com/smicallef/spiderfoot", "Import", "Infrastructure event CSV and evidence nodes", "Only selected infrastructure event types. No 200-module automation or personal-data collection."},
		{"sherlock", "Sherlock", "Discovery", "MIT", "https://github.com/sherlock-project/sherlock", "Reused data subset", "Pinned public-profile URL templates for manual username review", "Generated links are unverified. No automated account-existence or identity claims."},
		{"recon-ng", "recon-ng", "Discovery", "GPL-3.0", "https://github.com/lanmaster53/recon-ng", "Import", "Host/IP CSV relationships", "No marketplace modules, credentials or recon-ng runtime."},
		{"bbot", "BBOT", "Discovery", "AGPL-3.0", "https://github.com/blacklanternsecurity/bbot", "Import", "Scoped infrastructure and finding event JSON/JSONL", "No recursive scanner execution or bundled AGPL code."},
		{"cloudfox", "CloudFox", "Cloud", "MIT", "https://github.com/BishopFox/cloudfox", "Native + import", "CloudFox resource/endpoint CSV and static AWS IAM policy review", "No provider connection, inventory count-matrix parser or effective permission simulation."},
		{"evilginx3", "Evilginx3", "Session security", "Upstream project; not bundled", "https://attack.mitre.org/software/S9003/", "Excluded", "Existing HTTPS checks can review TLS and transport headers", "Credential/session interception, phishing proxy and MFA bypass functionality are not provided."},
		{"caido", "Caido", "Web", "Proprietary core; SDK licenses separate", "https://docs.caido.io/", "Native subset", "Generic HAR 1.2 inspection if HTTP exchanges are converted to HAR", "Native Caido exports are not supported. No intercepting proxy or request replay."},
		{"nuclei", "Nuclei", "Assessment", "MIT engine; templates licensed separately", "https://github.com/projectdiscovery/nuclei", "Import", "Nuclei JSON/JSONL findings with normalized severities", "No Nuclei execution, template engine or downloaded rule pack."},
		{"bloodhound", "BloodHound", "Identity", "Apache-2.0 CE; collectors have separate licenses", "https://github.com/SpecterOps/BloodHound", "Native + import", "v5/v6 collection JSON, ACL and group edges, delegation flags", "No directory collection, graph database or attack-path search."},
		{"cyberchef", "CyberChef", "Data", "Apache-2.0", "https://github.com/gchq/CyberChef", "Reused code subset", "Browser-local recipe chains, encoding, hashing, entropy and JWT inspection", "Two adapted helper algorithms. No full CyberChef engine or encryption suite."},
		{"burp", "Burp Suite", "Web", "Proprietary product; Community terms apply", "https://portswigger.net/burp/tc-community", "Import", "Burp issue XML and HTTP archive review", "No Burp engine, scanner, intruder or intercepting proxy."},
	}
}
