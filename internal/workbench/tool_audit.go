// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

type ToolCapability struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Coverage        string `json:"coverage"`
	InputHelp       string `json:"inputHelp"`
	InputKind       string `json:"inputKind"`
	Limit           string `json:"limit"`
	Engine          string `json:"engine"`
	EngineAvailable bool   `json:"engineAvailable"`
}

type toolAssessment struct {
	capability ToolCapability
	run        func(context.Context, ToolRequest) (*Report, error)
}

var toolAssessments = []toolAssessment{
	{ToolCapability{ID: "airgorah", Coverage: "Wireless snapshot comparison for protection downgrades and AP metadata changes", InputKind: "json", InputHelp: `JSON {"before":"Airodump AP CSV text","after":"Airodump AP CSV text"}; leave target empty.`, Limit: "1000 records per snapshot. Offline evidence only; no radio operations or impersonation proof."}, auditAirgorah},
	{ToolCapability{ID: "netcat", Coverage: "Fixed read-only service protocol probes and bounded response confirmation", InputKind: "host", InputHelp: "One hostname/IP and1 to8 ports. Known ports use HTTP HEAD, SMTP EHLO, Redis PING or Memcached version; others read banners.", Limit: "No arbitrary payloads, shell, listeners, relay, TLS negotiation or netcat engine."}, auditNetcat},
	{ToolCapability{ID: "passive-recon", Coverage: "Scoped CT evidence, native DNS and verified public TLS SAN collection", InputKind: "domain-or-json", InputHelp: "One authorized ASCII/punycode domain. Optional crt.sh-style JSON array makes the assessment offline.", Limit: "No CT API query, brute-force, discovered-host requests or complete asset inventory. Historical names do not prove live services."}, auditPassiveRecon},
	{ToolCapability{ID: "shodan", Coverage: "Indexed service exposure, CVE assertion, freshness and TLS expiry triage", InputKind: "file", InputHelp: "Shodan host/search/service JSON or JSONL. Optional target is one exact IP filter.", Limit: "Offline index evidence only; no live Shodan API, fresh collection or independent vulnerability verification."}, auditShodan},
	{ToolCapability{ID: "spiderdomain", Coverage: "DNS alias/PTR enrichment and offline DNS zone inventory review", InputKind: "domain-or-json", InputHelp: `One ASCII domain, or JSON {"origin":"example.test","complete":true,"records":[{"name":"@","type":"TXT","value":"v=spf1 -all"}]}. Absolute DNS names end in a dot.`, Limit: "Upstream identity unresolved. No takeover proof, zone transfer, DNSSEC or exhaustive discovery."}, auditSpiderdomain},
	{ToolCapability{ID: "maltego", Coverage: "Cross-report entity correlation, directed paths and relationship provenance", InputKind: "json", InputHelp: `JSON {"reports":[normalized report objects],"from":"optional node label","to":"optional node label"}. Leave target empty.`, Limit: "20 reports and1000 combined nodes/edges; exact entity matches only. No commercial transforms or external collection."}, auditMaltego},
	{ToolCapability{ID: "foremost", Coverage: "Structurally checked PNG, GIF, BMP and WAV byte-range recovery", InputKind: "file", InputHelp: "Upload bytes containing embedded images/audio. Leave the live target empty.", Limit: "32 artifact maximum; no decompression, disk/deleted-block recovery or full file decoder."}, auditForemost},
	{ToolCapability{ID: "skipfish", Coverage: "Bounded same-origin crawling and per-page HTTP/browser configuration review", InputKind: "url", InputHelp: "Root HTTP or HTTPS page; visits up to8 pages at depth2, without queries or form submission.", Limit: "No JavaScript execution, authenticated flows, injection probes or Skipfish engine."}, auditSkipfish},
	{ToolCapability{ID: "hping3", Coverage: "Repeated TCP connect stability measurements and latency statistics", InputKind: "host", InputHelp: "One hostname or IP, at most8 explicit ports;3 fixed samples per port.", Limit: "No raw packets, spoofing, floods, application payloads or hping engine."}, auditHping3},
	{ToolCapability{ID: "wireshark", Coverage: "Offline classic PCAP and PCAPNG Ethernet conversation analysis", InputKind: "file", InputHelp: "Upload classic Ethernet PCAP or PCAPNG with interface declarations and enhanced packet blocks.", Limit: "No live capture, full dissectors, reassembly or decryption."}, auditWireshark},
	{ToolCapability{ID: "aircrack", Coverage: "Offline 802.11/radiotap beacon security and management-event analysis", InputKind: "file", InputHelp: "Upload Airodump CSV or classic wireless PCAP, without a live target.", Limit: "No radio capture, injection, deauthentication generation, cracking or WPA3 enforcement proof."}, auditAircrack},
	{ToolCapability{ID: "hashcat", Coverage: "Bounded offline verification of supplied password candidates against unsalted digests", InputKind: "json", InputHelp: `JSON: {"algorithm":"sha256","hashes":["hex digest"],"candidates":["local candidate"]}. SHA-384/512 also supported; no live target.`, Limit: "At most256 hashes,4096 candidates,1million combinations. No Hashcat engine or salted formats; secrets are omitted from reports."}, auditHashcat},
	{ToolCapability{ID: "sqlmap", Coverage: "Database error disclosure and captured request/error correlation", InputKind: "url-or-har", InputHelp: "One target URL for a baseline GET, or a HAR file with response content.", Limit: "No injection probes, SQLMap engine, database extraction or database permission audit."}, auditSQLMap},
	{ToolCapability{ID: "metasploit", Coverage: "Service-correlated vulnerability triage with validated advisory references", InputKind: "file", InputHelp: "MetasploitV5 XML evidence file, without a live target.", Limit: "Imported candidates require independent verification; no exploit, payload or session execution."}, auditMetasploit},
	{ToolCapability{ID: "nmap", Coverage: "Multi-address TCP, service banners and TLS; optional installed Nmap service detection", InputKind: "host", InputHelp: "One hostname or IP and 1 to 32 explicit ports.", Limit: "No UDP, NSE, OS fingerprinting or exploit execution.", Engine: "nmap"}, auditNmap},
	{ToolCapability{ID: "nuclei", Coverage: "Native HTTP exposure rules for directory listings, debug pages, embedded source maps and cookie configuration", InputKind: "url", InputHelp: "Explicit HTTP or HTTPS page to assess.", Limit: "Native rules only; no external template pack or Nuclei engine."}, auditNuclei},
}

func ToolCapabilities() []ToolCapability {
	result := make([]ToolCapability, 0, len(toolAssessments))
	for _, tool := range Catalog() {
		for _, spec := range toolAssessments {
			if spec.capability.ID != tool.ID {
				continue
			}
			capability := spec.capability
			capability.Name = tool.Name
			if capability.Engine != "" {
				_, err := exec.LookPath(capability.Engine)
				capability.EngineAvailable = err == nil
			}
			result = append(result, capability)
			break
		}
	}
	return result
}

// AuditTool dispatches only reviewed implementations; callers cannot submit a
// command line. Explicit authorization applies to every tool for a consistent
// API, including analyses of uploaded evidence.
func AuditTool(ctx context.Context, request ToolRequest) (*Report, error) {
	if !request.Authorized {
		return nil, fmt.Errorf("confirm ownership or authorization for this assessment")
	}
	if len(request.Input) > MaxInput {
		return nil, fmt.Errorf("tool input exceeds the 8 MiB limit")
	}
	if len(request.Target) > 4096 {
		return nil, fmt.Errorf("target exceeds 4096 bytes")
	}
	if len(request.Ports) > 32 {
		return nil, fmt.Errorf("provide at most 32 explicit ports")
	}
	for _, spec := range toolAssessments {
		if spec.capability.ID != request.Tool {
			continue
		}
		if request.RunEngine && spec.capability.Engine == "" {
			return nil, fmt.Errorf("this assessment does not execute an external engine")
		}
		ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		report, err := spec.run(ctx, request)
		if err != nil {
			return nil, err
		}
		if report == nil {
			return nil, fmt.Errorf("assessment returned no evidence")
		}
		if err := ctx.Err(); err != nil {
			report.Limited = true
			report.gap("Assessment was cancelled or reached its deadline.")
		}
		return report, nil
	}
	return nil, fmt.Errorf("unknown or unavailable assessment tool")
}
