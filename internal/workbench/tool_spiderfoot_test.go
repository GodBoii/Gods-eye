// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSpiderfootJSONCorrelation(t *testing.T) {
	// Children precede parents, matching exports whose timestamps are reversed.
	input := `[
 {"event_type":"TCP_PORT_OPEN","data":"192.0.2.4:5432","source_data":"192.0.2.4","module":"sfp_portscan_tcp","false_positive":0,"scan_target":"example.test"},
 {"event_type":"IP_ADDRESS","data":"192.0.2.4","source_data":"api.example.test","module":"sfp_dnsresolve","false_positive":0},
 {"event_type":"INTERNET_NAME","data":"api.example.test","source_data":"example.test","module":"sfp_dns","false_positive":0},
 {"event_type":"INTERNET_NAME","data":"API.EXAMPLE.TEST.","source_data":"example.test","module":"sfp_ct","false_positive":0},
 {"event_type":"INTERNET_NAME","data":"api.example.test","source_data":"example.test","module":"sfp_ct","false_positive":1},
 {"event_type":"LINKED_URL_INTERNAL","data":"https://api.example.test/docs?token=SECRET#private","source_data":"api.example.test","module":"sfp_spider","false_positive":0}
]`
	r, err := auditSpiderfoot(context.Background(), ToolRequest{Target: "example.test", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET", "token=", "#private"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("retained sensitive URL data: %s", secret)
		}
	}
	if len(r.Findings) != 2 {
		t.Fatalf("expected exposure and flag conflict, got %+v", r.Findings)
	}
	diversity := false
	for _, obs := range r.Observations {
		if obs.Kind == "source diversity" && strings.Contains(obs.Value, "2 distinct") {
			diversity = true
		}
	}
	if !diversity {
		t.Fatal("missing deduplicated module diversity summary")
	}
	nodes := map[string]bool{}
	for _, node := range r.Nodes {
		nodes[node.ID] = true
	}
	if len(r.Edges) < 4 {
		t.Fatalf("missing parent correlations: %+v", r.Edges)
	}
	for _, edge := range r.Edges {
		if !nodes[edge.Source] || !nodes[edge.Target] {
			t.Fatalf("dangling edge: %+v", edge)
		}
	}
}

func TestSpiderfootScopeAndPrivacy(t *testing.T) {
	input := `[
 {"event_type":"INTERNET_NAME","data":"ok.example.test","source_data":"a person SECRET","module":"sfp_test"},
 {"event_type":"INTERNET_NAME","data":"badexample.test","source_data":"example.test","module":"sfp_test"},
 {"event_type":"INTERNET_NAME","data":"other.example.test","source_data":"example.test","scan_target":"other.test"},
 {"event_type":"IP_ADDRESS","data":"192.0.2.5","source_data":"outside.test"},
 {"event_type":"IP_ADDRESS","data":"192.0.2.6","source_data":"example.test","false_positive":1},
 {"event_type":"TCP_PORT_OPEN","data":"192.0.2.5:3306","source_data":"192.0.2.5"},
 {"event_type":"EMAILADDR","data":"SECRET@example.test","source_data":"example.test"},
 {"event_type":"LINKED_URL_INTERNAL","data":"https://user:SECRET@example.test/","source_data":"example.test"},
 {"event_type":"INTERNET_NAME","data":"newline.example.test\nSECRET","source_data":"example.test"}
]`
	r, err := auditSpiderfoot(context.Background(), ToolRequest{Target: "example.test", Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Observations) != 1 || r.Observations[0].Target != "ok.example.test" || len(r.Findings) != 0 {
		t.Fatalf("unscoped evidence retained: %+v", r)
	}
	if len(r.Edges) != 1 || r.Edges[0].Relation != "domain scope contains" {
		t.Fatalf("invalid source label linked: %+v", r.Edges)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "SECRET") {
		t.Fatal("personal or malformed source data leaked")
	}
}

func TestSpiderfootCSVAndIPv6(t *testing.T) {
	input := "Updated,Type,Module,Source,F/P,Data\nnow,IPV6_ADDRESS,sfp_dns,example.test,0,2001:db8::1\nnow,TCP_PORT_OPEN,sfp_scan,2001:db8::1,0,[2001:db8::1]:443\n"
	r, err := auditSpiderfoot(context.Background(), ToolRequest{Target: "example.test", Input: base64.StdEncoding.EncodeToString([]byte(input)), Encoding: "base64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Observations) != 2 || len(r.Edges) != 2 {
		t.Fatalf("IPv6 correlation missing: %+v", r)
	}
}

func TestSpiderfootBoundaryValidation(t *testing.T) {
	for _, input := range []string{
		`[]`, `[{"type":"INTERNET_NAME","data":"example.test"}]`,
		`[{"event_type":"INTERNET_NAME","data":"example.test","false_positive":2}]`,
		`[{"event_type":"INTERNET_NAME","data":"example.test"}] {}`,
		"Type,Data,F/P\nINTERNET_NAME,example.test,unknown\n",
		"Type,Data\nINTERNET_NAME,example.test,extra\n",
		"Type,Data,Data\nINTERNET_NAME,a,b\n",
	} {
		if _, err := auditSpiderfoot(context.Background(), ToolRequest{Target: "example.test", Input: input}); err == nil {
			t.Fatalf("accepted malformed input: %s", input)
		}
	}
	for _, req := range []ToolRequest{
		{Input: "Type,Data\nINTERNET_NAME,example.test\n"},
		{Target: "https://example.test", Input: "[]"},
		{Target: "192.0.2.1", Input: "[]"},
		{Target: "example.test", RunEngine: true},
		{Target: "example.test", Ports: []int{80}},
	} {
		if _, err := auditSpiderfoot(context.Background(), req); err == nil {
			t.Fatalf("accepted invalid request: %+v", req)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditSpiderfoot(ctx, ToolRequest{}); err != context.Canceled {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestSpiderfootRecordAndGraphCaps(t *testing.T) {
	var csv strings.Builder
	csv.WriteString("Type,Data,Source\n")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&csv, "INTERNET_NAME,host%d.example.test,example.test\n", i)
	}
	r, err := auditSpiderfoot(context.Background(), ToolRequest{Target: "example.test", Input: csv.String()})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited || len(r.Nodes) > maxRecords || len(r.Edges) > maxRecords {
		t.Fatalf("graph collection limit not enforced: %+v", r)
	}
	csv.WriteString("INTERNET_NAME,extra.example.test,example.test\n")
	if _, err := auditSpiderfoot(context.Background(), ToolRequest{Target: "example.test", Input: csv.String()}); err == nil {
		t.Fatal("accepted more than 1000 input rows")
	}
}
