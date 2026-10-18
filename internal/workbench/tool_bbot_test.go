// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestBBOTCoverageAndProvenance(t *testing.T) {
	input := `{"id":"root","type":"DNS_NAME","data":"example.test","scope_distance":0,"parent":"root"}
{"id":"api","parent":"root","type":"DNS_NAME","data":"api.example.test","resolved_hosts":["192.0.2.8"],"scope_distance":0}
{"id":"ip","parent":"api","type":"IP_ADDRESS","data":"192.0.2.8"}
{"id":"url","source":"api","type":"URL","data":"https://api.example.test/path?token=SECRET#PRIVATE"}
{"id":"url","source":"api","type":"URL","data":"https://api.example.test/path?token=SECRET#PRIVATE"}
{"id":"forgotten","parent":"missing","type":"DNS_NAME_UNRESOLVED","data":"forgotten.example.test"}
{"id":"foreign","parent":"root","type":"DNS_NAME","data":"example.test.attacker.test"}
{"id":"bad","parent":"root","type":"DNS_NAME","data":"excluded.example.test","tags":["false-positive"]}
{"id":"far","type":"DNS_NAME","data":"distant.example.test","scope_distance":1}
{"id":"unowned","type":"IP_ADDRESS","data":"203.0.113.8"}
{"type":"EMAIL_ADDRESS","data":"private@person.test"}`
	r, err := auditBBOT(context.Background(), ToolRequest{Target: "example.test", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(r)
	for _, private := range []string{"SECRET", "PRIVATE", "attacker.test", "excluded.example.test", "distant.example.test", "203.0.113.8", "private@person.test"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("leaked omitted data %q", private)
		}
	}
	foundURL, apiFrontier, forgottenFrontier := 0, 0, 0
	for _, o := range r.Observations {
		if o.Kind == "URL" {
			foundURL++
		}
		if o.Kind == "coverage frontier" && o.Target == "api.example.test" {
			apiFrontier++
		}
		if o.Kind == "coverage frontier" && o.Target == "forgotten.example.test" {
			forgottenFrontier++
		}
	}
	if foundURL != 1 || apiFrontier != 0 || forgottenFrontier != 2 {
		t.Fatalf("wrong dedup or frontier: %+v", r.Observations)
	}
	if len(r.Findings) != 0 || len(r.Edges) < 3 {
		t.Fatalf("expected evidence edges without vulnerability claims: %+v", r)
	}
	if !strings.Contains(strings.Join(r.Gaps, " "), "Dangling") {
		t.Fatal("missing dangling provenance gap")
	}
}

func TestBBOTCyclesAndConflictingIDs(t *testing.T) {
	input := `[
{"id":"a","parent":"b","type":"DNS_NAME","data":"a.example.test"},
{"id":"b","parent":"a","type":"DNS_NAME","data":"b.example.test"},
{"id":"conflict","type":"DNS_NAME","data":"good.example.test"},
{"id":"conflict","type":"DNS_NAME","data":"other.example.test"},
{"id":"ip","parent":"conflict","type":"IP_ADDRESS","data":"192.0.2.9"}]
`
	r, err := auditBBOT(context.Background(), ToolRequest{Target: "example.test", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Edges) != 2 {
		t.Fatalf("cycles should remain bounded directed evidence: %+v", r.Edges)
	}
	for _, n := range r.Nodes {
		if strings.Contains(n.Label, "good.") || strings.Contains(n.Label, "other.") || n.Kind == "ip" {
			t.Fatalf("conflicting ID trusted: %+v", n)
		}
	}
}

func TestBBOTValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  ToolRequest
	}{
		{"no scope", ToolRequest{Input: `[]`}},
		{"URL scope", ToolRequest{Target: "https://example.test", Input: `[]`}},
		{"empty", ToolRequest{Target: "example.test", Input: `[]`}},
		{"engine", ToolRequest{Target: "example.test", RunEngine: true, Input: `[]`}},
		{"ports", ToolRequest{Target: "example.test", Ports: []int{443}, Input: `[]`}},
		{"malformed", ToolRequest{Target: "example.test", Input: `[{`}},
		{"wrong field type", ToolRequest{Target: "example.test", Input: `{"type":"DNS_NAME","data":"example.test","parent":{}}`}},
		{"too many", ToolRequest{Target: "example.test", Input: strings.Repeat("{\"type\":\"DNS_NAME\",\"data\":\"example.test\"}\n", 1001)}},
		{"oversized", ToolRequest{Target: "example.test", Input: strings.Repeat("x", MaxInput+1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := auditBBOT(context.Background(), tc.req); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditBBOT(ctx, ToolRequest{Target: "example.test", Input: `[]`}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestBBOTParentScopeAndExcludedResolution(t *testing.T) {
	input := `{"id":"excluded","type":"DNS_NAME","data":"false.example.test","false_positive":true,"resolved_hosts":["192.0.2.4"]}
{"id":"ip","parent":"excluded","type":"IP_ADDRESS","data":"192.0.2.4"}
{"type":"OPEN_TCP_PORT","data":"192.0.2.4:443"}
{"type":"URL_UNVERIFIED","data":"https://user:password@example.test/"}
{"type":"DNS_NAME","data":"example.test"}`
	r, err := auditBBOT(context.Background(), ToolRequest{Target: "example.test", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Nodes) != 1 || r.Nodes[0].Label != "example.test" {
		t.Fatalf("untrusted resolution expanded scope: %+v", r.Nodes)
	}
}
