// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIntelligenceConnectsSourcesWithoutInventingOwnership(t *testing.T) {
	old := newReport("nuclei", "Imported candidate", []byte("original"))
	old.ID, old.CreatedAt = "old", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	old.finding("medium", "Exposure", "https://EXAMPLE.test:443/api?token=SECRET", "Candidate detail")
	old.edge(old.node("domain", "example.test"), old.node("ip", "192.0.2.1"), "resolves to")
	newer := newReport("burp", "Another imported candidate", []byte("second"))
	newer.ID, newer.CreatedAt = "new", old.CreatedAt.Add(time.Hour)
	newer.finding("high", "Exposure", "https://example.test/api", "Candidate detail")
	newer.finding("critical", "Separate issue", "https://other.test/API", "Different advisory")
	result := buildIntelligence([]*Report{newer, old}, time.Now())
	if result.ReportCount != 2 || len(result.Findings) != 2 || len(result.Entities) != 3 || len(result.Relations) != 1 {
		t.Fatalf("unexpected correlation: %+v", result)
	}
	if result.Findings[0].Severity != "critical" {
		t.Fatal("triage is not severity ordered")
	}
	f := result.Findings[1]
	if len(f.References) != 2 || f.Severity != "high" || f.FirstSeen != old.CreatedAt || f.LastSeen != newer.CreatedAt || strings.Contains(f.Target, "SECRET") {
		t.Fatalf("deduplication lost provenance/redaction: %+v", f)
	}
	if f.References[0].InputSHA256 != newer.InputSHA256 || f.References[1].Severity != "medium" {
		t.Fatal("source metadata lost")
	}
	for _, e := range result.Entities {
		if e.Label == "example.test" && (len(e.ReportIDs) != 2 || e.FindingCount != 1) {
			t.Fatalf("duplicate inflated entity counts: %+v", e)
		}
	}
}

func TestIntelligencePreservesDistinctPathsDetailsAndOpaqueIDs(t *testing.T) {
	r := newReport("fixture", "", nil)
	r.ID = "fixture"
	for _, target := range []string{"https://a.test/API", "https://a.test/api", "https://a.test:8443/api", "person@example.test", "./Case/File", "./case/file"} {
		r.finding("low", "Issue", target, "first advisory")
	}
	r.finding("high", "Issue", "https://a.test/api", "second advisory")
	result := buildIntelligence([]*Report{r}, time.Now())
	if len(result.Findings) != 7 || len(result.Entities) != 4 {
		t.Fatalf("overmerged distinct evidence: %+v", result)
	}
	for _, e := range result.Entities {
		if strings.Contains(e.Label, "@") && e.Kind == "host" {
			t.Fatal("email was inferred to be infrastructure")
		}
	}
	for _, tc := range []struct{ value, kind, label string }{
		{"https://[2001:db8::1]:443/a?q=secret", "host", "2001:db8::1"},
		{"[2001:db8::1]:22", "host", "2001:db8::1"},
		{"Example.Test.", "host", "example.test"},
		{"arn:aws:iam::123:role/Test", "target", "arn:aws:iam::123:role/Test"},
		{"source:123", "target", "source:123"},
		{"source:project", "target", "source:project"},
		{"C:/project", "target", "C:/project"},
		{"opaque-label", "target", "opaque-label"},
		{"https://localhost/a", "host", "localhost"},
		{"localhost:22", "host", "localhost"},
	} {
		kind, label := intelligenceIdentity(tc.value)
		if kind != tc.kind || label != tc.label {
			t.Fatalf("%s became %s / %s", tc.value, kind, label)
		}
	}
}

func TestIntelligenceLimitsAndEmptyArrays(t *testing.T) {
	empty := buildIntelligence(nil, time.Now())
	if empty.Entities == nil || empty.Findings == nil || empty.Relations == nil || empty.Reports == nil {
		t.Fatal("empty collections must be arrays")
	}
	r := newReport("fixture", "", nil)
	for i := 0; i < intelligenceLimit+1; i++ {
		r.Findings = append(r.Findings, Finding{Title: fmt.Sprint(i), Target: "example.test", Severity: "invalid"})
	}
	result := buildIntelligence([]*Report{r}, time.Now())
	if !result.Limited || len(result.Findings) != intelligenceLimit || result.Findings[0].Severity != "info" {
		t.Fatal("limit or unknown severity not handled")
	}
}

func TestIntelligenceSurvivesStoreRestart(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Import("nuclei", []byte(`{"template-id":"fixture","host":"https://example.test/","info":{"name":"Candidate","severity":"high"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(r); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := restored.Intelligence(time.Now())
	if result.ReportCount != 1 || len(result.Findings) != 1 || result.Findings[0].References[0].ReportID != r.ID {
		t.Fatal("stored provenance lost")
	}
}
