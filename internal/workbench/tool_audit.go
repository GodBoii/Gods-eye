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
	for _, spec := range toolAssessments {
		capability := spec.capability
		if capability.Engine != "" {
			_, err := exec.LookPath(capability.Engine)
			capability.EngineAvailable = err == nil
		}
		result = append(result, capability)
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
