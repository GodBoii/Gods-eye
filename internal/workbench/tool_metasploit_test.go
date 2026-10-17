// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditMetasploitEvidenceCorrelation(t *testing.T) {
	input := `<MetasploitV5><hosts><host><address>192.0.2.1</address><services><service><id>7</id><port>443</port><proto>tcp</proto><name>https</name><state>open</state></service></services><vulns><vuln><name>Vendor issue secret-password</name><service-id>7</service-id><info>Authorization: Bearer secret-token</info><refs><ref>CVE-2024-12345</ref><ref><name>URL-https://vendor.example/advisory?token=secret-query</name></ref><ref>CVE-2024-12345</ref></refs></vuln></vulns><creds><password>secret-credential</password></creds></host></hosts></MetasploitV5>`
	r, err := auditMetasploit(context.Background(), ToolRequest{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Target != "tcp://192.0.2.1:443" || r.Findings[0].Severity != "info" {
		t.Fatalf("unexpected findings: %+v", r.Findings)
	}
	refs, serviceEdges := 0, 0
	for _, n := range r.Nodes {
		if n.Kind == "advisory reference" {
			refs++
		}
	}
	for _, e := range r.Edges {
		if e.Relation == "reported vulnerability candidate" {
			serviceEdges++
		}
	}
	if refs != 2 || serviceEdges != 1 {
		t.Fatalf("reference deduplication or graph failed: %+v", r)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-password", "secret-token", "secret-query", "secret-credential"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("retained secret %s", secret)
		}
	}
	if !strings.Contains(r.Findings[0].Detail, "Unverified") || !strings.Contains(r.Findings[0].Detail, "vendor fixes") {
		t.Fatal("missing provenance or remediation")
	}
}

func TestAuditMetasploitNeverCorrelatesAnotherHostsService(t *testing.T) {
	input := `<MetasploitV5><hosts><host><address>192.0.2.1</address><services><service><id>5</id><port>22</port><proto>tcp</proto></service></services></host><host><address>192.0.2.2</address><vulns><vuln><name>candidate</name><service-id>5</service-id><refs><ref>CVE-bogus</ref><ref>javascript:alert(1)</ref></refs></vuln></vulns></host></hosts></MetasploitV5>`
	r, err := auditMetasploit(context.Background(), ToolRequest{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Target != "192.0.2.2" {
		t.Fatalf("wrong host correlation: %+v", r.Findings)
	}
	for _, n := range r.Nodes {
		if n.Kind == "advisory reference" {
			t.Fatal("invalid advisory retained")
		}
	}
	if !strings.Contains(strings.Join(r.Gaps, " "), "missing service ID") {
		t.Fatal("missing association gap")
	}
}

func TestAuditMetasploitRejectsInvalidReports(t *testing.T) {
	tests := []struct {
		name string
		req  ToolRequest
	}{
		{"engine", ToolRequest{RunEngine: true}},
		{"live target", ToolRequest{Target: "https://example.com"}},
		{"empty", ToolRequest{}},
		{"wrong root", ToolRequest{Input: `<report/>`}},
		{"no hosts", ToolRequest{Input: `<MetasploitV5/>`}},
		{"bad IP", ToolRequest{Input: `<MetasploitV5><hosts><host><address>example.com</address></host></hosts></MetasploitV5>`}},
		{"invalid protocol", ToolRequest{Input: `<MetasploitV5><hosts><host><address>192.0.2.1</address><services><service><port>80</port><proto>shell</proto></service></services></host></hosts></MetasploitV5>`}},
		{"invalid port", ToolRequest{Input: `<MetasploitV5><hosts><host><address>192.0.2.1</address><services><service><port>65536</port><proto>tcp</proto></service></services></host></hosts></MetasploitV5>`}},
		{"duplicate IDs", ToolRequest{Input: `<MetasploitV5><hosts><host><address>192.0.2.1</address><services><service><id>1</id><port>80</port><proto>tcp</proto></service><service><id>1</id><port>81</port><proto>tcp</proto></service></services></host></hosts></MetasploitV5>`}},
		{"missing vuln name", ToolRequest{Input: `<MetasploitV5><hosts><host><address>192.0.2.1</address><vulns><vuln/></vulns></host></hosts></MetasploitV5>`}},
		{"multiple documents", ToolRequest{Input: `<MetasploitV5/><MetasploitV5/>`}},
		{"external entity", ToolRequest{Input: `<!DOCTYPE x [<!ENTITY x SYSTEM "file:///secret">]><MetasploitV5><hosts><host><address>&x;</address></host></hosts></MetasploitV5>`}},
		{"oversize", ToolRequest{Input: strings.Repeat(" ", MaxInput+1)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := auditMetasploit(context.Background(), tt.req); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestAuditMetasploitCollectionAndCancellation(t *testing.T) {
	input := `<MetasploitV5><hosts><host><address>192.0.2.1</address><vulns>` + strings.Repeat(`<vuln><name>candidate</name></vuln>`, maxRecords+5) + `</vulns></host></hosts></MetasploitV5>`
	r, err := auditMetasploit(context.Background(), ToolRequest{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited {
		t.Fatal("collection was not marked limited")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditMetasploit(ctx, ToolRequest{Input: input}); err == nil {
		t.Fatal("cancelled operation accepted")
	}
}
