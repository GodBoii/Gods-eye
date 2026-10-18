// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func maltegoRequest(t *testing.T, reports []Report, from, to string) ToolRequest {
	t.Helper()
	data, err := json.Marshal(map[string]any{"reports": reports, "from": from, "to": to})
	if err != nil {
		t.Fatal(err)
	}
	return ToolRequest{Tool: "maltego", Input: string(data)}
}

func TestMaltegoCrossReportGraph(t *testing.T) {
	reports := []Report{
		{Nodes: []Node{{"a", "domain", "example.test"}, {"b", "ip", "192.0.2.1"}}, Edges: []Edge{{"a", "b", "resolves-to"}}},
		{Nodes: []Node{{"x", "ip", "192.0.2.1"}, {"y", "service", "https"}}, Edges: []Edge{{"x", "y", "offers"}}},
	}
	r, err := auditMaltego(context.Background(), maltegoRequest(t, reports, "example.test", "https"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Nodes) != 3 || len(r.Edges) != 2 {
		t.Fatalf("unexpected graph: %+v", r)
	}
	hops, mergedProvenance := 0, false
	for _, o := range r.Observations {
		if o.Kind == "relationship path hop" {
			hops++
		}
		if o.Kind == "entity provenance" && o.Target == "192.0.2.1" && strings.Contains(o.Value, `"reports":[1,2]`) {
			mergedProvenance = true
		}
	}
	if hops != 2 || !mergedProvenance {
		t.Fatalf("missing path/provenance: %+v", r.Observations)
	}
	// Evidence can be shared by reports with completely unrelated original IDs.
	reports = append(reports, reports[0])
	r, err = auditMaltego(context.Background(), maltegoRequest(t, reports, "", ""))
	if err != nil || len(r.Edges) != 2 {
		t.Fatalf("edge deduplication failed: %v", err)
	}
}

func TestMaltegoDirectionCyclesAndDisconnected(t *testing.T) {
	reports := []Report{{Nodes: []Node{{"a", "entity", "a"}, {"b", "entity", "b"}, {"c", "entity", "c"}, {"d", "entity", "d"}}, Edges: []Edge{{"a", "b", "next"}, {"b", "a", "next"}, {"b", "c", "next"}, {"a", "c", "direct"}}}}
	for _, tt := range []struct {
		from, to string
		hops     int
		absent   bool
	}{
		{"a", "c", 1, false}, {"c", "a", 0, true}, {"a", "d", 0, true}, {"a", "a", 0, false},
	} {
		t.Run(tt.from+"-"+tt.to, func(t *testing.T) {
			r, err := auditMaltego(context.Background(), maltegoRequest(t, reports, tt.from, tt.to))
			if err != nil {
				t.Fatal(err)
			}
			hops, absent := 0, false
			for _, o := range r.Observations {
				if o.Kind == "relationship path hop" {
					hops++
				}
				if strings.HasPrefix(o.Value, "No directed path") {
					absent = true
				}
			}
			if hops != tt.hops || absent != tt.absent {
				t.Fatalf("unexpected path: %+v", r.Observations)
			}
		})
	}
}

func TestMaltegoDistinctKindsAndRedaction(t *testing.T) {
	reports := []Report{{Nodes: []Node{{"a", "domain", "same"}, {"b", "person", "same"}, {"c", "url", "https://user:secret@example.test/path?token=secret#secret"}}, Findings: []Finding{{Detail: "body secret"}}}}
	r, err := auditMaltego(context.Background(), maltegoRequest(t, reports, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Nodes) != 3 {
		t.Fatal("different kinds merged")
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") || strings.Contains(string(data), "body") {
		t.Fatal("source secrets retained")
	}
	if _, err := auditMaltego(context.Background(), maltegoRequest(t, reports, "same", "same")); err == nil {
		t.Fatal("ambiguous label accepted")
	}
}

func TestMaltegoRejectInvalidCollections(t *testing.T) {
	valid := Report{Nodes: []Node{{"a", "domain", "a"}}}
	for name, req := range map[string]ToolRequest{
		"empty":            maltegoRequest(t, nil, "", ""),
		"too many reports": maltegoRequest(t, make([]Report, 21), "", ""),
		"duplicate id":     maltegoRequest(t, []Report{{Nodes: []Node{{"a", "domain", "a"}, {"a", "ip", "b"}}}}, "", ""),
		"invalid id":       maltegoRequest(t, []Report{{Nodes: []Node{{"a b", "domain", "a"}}}}, "", ""),
		"empty label":      maltegoRequest(t, []Report{{Nodes: []Node{{"a", "domain", ""}}}}, "", ""),
		"dangling":         maltegoRequest(t, []Report{{Nodes: valid.Nodes, Edges: []Edge{{"a", "b", "next"}}}}, "", ""),
		"missing relation": maltegoRequest(t, []Report{{Nodes: valid.Nodes, Edges: []Edge{{"a", "a", ""}}}}, "", ""),
		"partial path":     maltegoRequest(t, []Report{valid}, "a", ""),
		"unknown endpoint": maltegoRequest(t, []Report{valid}, "a", "b"),
		"malformed":        {Input: `{"reports":[{"nodes":"bad"}]}`},
		"unknown fields":   {Input: `{"reports":[],"unexpected":true}`},
		"trailing":         {Input: `{"reports":[]} {}`},
		"engine":           {RunEngine: true, Input: `{}`},
		"live":             {Target: "example.test", Input: `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := auditMaltego(context.Background(), req); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestMaltegoBoundsAndCancellation(t *testing.T) {
	report := Report{}
	for i := 0; i < 1000; i++ {
		report.Nodes = append(report.Nodes, Node{fmt.Sprint(i), "entity", fmt.Sprint(i)})
	}
	r, err := auditMaltego(context.Background(), maltegoRequest(t, []Report{report}, "", ""))
	if err != nil || len(r.Nodes) != 1000 {
		t.Fatalf("boundary rejected: %v", err)
	}
	report.Nodes = append(report.Nodes, Node{"extra", "entity", "extra"})
	if _, err := auditMaltego(context.Background(), maltegoRequest(t, []Report{report}, "", "")); err == nil {
		t.Fatal("collection cap ignored")
	}
	report = Report{Limited: true}
	for i := 0; i < 35; i++ {
		report.Nodes = append(report.Nodes, Node{fmt.Sprint(i), "entity", fmt.Sprint(i)})
		if i > 0 {
			report.Edges = append(report.Edges, Edge{fmt.Sprint(i - 1), fmt.Sprint(i), "next"})
		}
	}
	r, err = auditMaltego(context.Background(), maltegoRequest(t, []Report{report}, "0", "34"))
	if err != nil || !r.Limited {
		t.Fatalf("long path not marked limited: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditMaltego(ctx, maltegoRequest(t, []Report{report}, "", "")); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
}
