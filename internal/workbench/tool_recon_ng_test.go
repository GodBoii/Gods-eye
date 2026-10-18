// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestReconNGReconciliation(t *testing.T) {
	input := `{"domain":"EXAMPLE.COM.","before":[{"host":"a.example.com","ip_address":"192.0.2.1"},{"host":"old.example.com","ip_address":"192.0.2.2"},{"host":"same.example.com","ip_address":"::ffff:192.0.2.8"}],"after":[{"host":"A.EXAMPLE.COM.","ip_address":"192.0.2.3","source":"dns"},{"host":"a.example.com","ip_address":"192.0.2.4","source":"cmdb"},{"host":"new.example.com","ip_address":"2001:db8::1"},{"host":"same.example.com","ip_address":"192.0.2.8"}]}`
	req := ToolRequest{Input: input, Target: "example.com"}
	r, err := auditReconNG(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "1 added, 1 absent, 1 with address changes") {
		t.Fatal(r.Summary)
	}
	if len(r.Findings) != 1 || r.Findings[0].Severity != "info" {
		t.Fatalf("findings: %+v", r.Findings)
	}
	if len(r.Nodes) != 10 || len(r.Edges) != 7 {
		t.Fatalf("graph: %d nodes, %d edges", len(r.Nodes), len(r.Edges))
	}
	if len(r.Gaps) != 2 || r.InputSHA256 == "" {
		t.Fatalf("missing scope limits or digest: %+v", r)
	}
	kinds := map[string]int{}
	for _, o := range r.Observations {
		kinds[o.Kind]++
	}
	for _, k := range []string{"inventory host added", "inventory host absent", "inventory addresses changed", "inventory host unchanged"} {
		if kinds[k] != 1 {
			t.Fatalf("%s: %+v", k, kinds)
		}
	}
	r2, err := auditReconNG(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Observations, r2.Observations) || !reflect.DeepEqual(r.Edges, r2.Edges) {
		t.Fatal("non-deterministic comparison")
	}
}

func TestReconNGRejectsInvalidInput(t *testing.T) {
	valid := `{"domain":"example.com","before":[],"after":[]}`
	cases := map[string]ToolRequest{
		"engine":           {Input: valid, RunEngine: true},
		"target scope":     {Input: valid, Target: "other.example.com"},
		"invalid JSON":     {Input: `{`},
		"empty input":      {},
		"null":             {Input: `null`},
		"null array":       {Input: `{"domain":"example.com","before":null,"after":[]}`},
		"missing array":    {Input: `{"domain":"example.com","after":[]}`},
		"unknown property": {Input: `{"domain":"example.com","before":[],"after":[],"email":"person@example.com"}`},
		"trailing JSON":    {Input: valid + ` {}`},
		"trailing garbage": {Input: valid + ` bad`},
		"wildcard":         {Input: `{"domain":"*.example.com","before":[],"after":[]}`},
		"IP scope":         {Input: `{"domain":"192.0.2.1","before":[],"after":[]}`},
		"wrong encoding":   {Input: valid, Encoding: "binary"},
		"bad base64":       {Input: "%%%", Encoding: "base64"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := auditReconNG(context.Background(), req); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
	for name, row := range map[string]reconNGRecord{
		"outside domain":   {Host: "evil-example.com", IP: "192.0.2.1"},
		"suffix confusion": {Host: "example.com.evil.org", IP: "192.0.2.1"},
		"URL":              {Host: "https://example.com", IP: "192.0.2.1"},
		"empty host":       {IP: "192.0.2.1"},
		"empty address":    {Host: "example.com"},
		"CIDR":             {Host: "example.com", IP: "192.0.2.0/24"},
		"zone":             {Host: "example.com", IP: "fe80::1%eth0"},
		"person source":    {Host: "example.com", IP: "192.0.2.1", Source: "alice@example.com"},
		"invalid label":    {Host: "bad_.example.com", IP: "192.0.2.1"},
		"long label":       {Host: strings.Repeat("a", 64) + ".example.com", IP: "192.0.2.1"},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(map[string]any{"domain": "example.com", "before": []reconNGRecord{}, "after": []reconNGRecord{row}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := auditReconNG(context.Background(), ToolRequest{Input: string(b)}); err == nil {
				t.Fatal("accepted invalid row")
			}
		})
	}
}

func TestReconNGBoundsAndCancellation(t *testing.T) {
	rows := make([]reconNGRecord, 1001)
	for i := range rows {
		rows[i] = reconNGRecord{Host: "example.com", IP: "192.0.2.1"}
	}
	b, err := json.Marshal(map[string]any{"domain": "example.com", "before": rows[:500], "after": rows[500:]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditReconNG(context.Background(), ToolRequest{Input: string(b)}); err == nil {
		t.Fatal("accepted 1,001 rows")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditReconNG(ctx, ToolRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := auditReconNG(context.Background(), ToolRequest{Input: strings.Repeat("x", MaxInput+1)}); err == nil {
		t.Fatal("accepted oversized input")
	}
}

func TestReconNGDeduplicatesAndNormalizes(t *testing.T) {
	input := `{"domain":"example.com","before":[],"after":[{"host":"example.com","ip_address":"2001:db8::1","source":"a"},{"host":"EXAMPLE.COM.","ip_address":"2001:0db8:0:0:0:0:0:1","source":"b"},{"host":"example.com","ip_address":"2001:db8::1","source":"a"}]}`
	r, err := auditReconNG(context.Background(), ToolRequest{Input: base64.StdEncoding.EncodeToString([]byte(input)), Encoding: "base64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Nodes) != 2 || len(r.Edges) != 1 || len(r.Findings) != 0 {
		t.Fatalf("normalization failed: %+v", r)
	}
	if strings.Contains(r.Summary, "3 added") {
		t.Fatal("duplicates counted as hosts")
	}
}
