// SPDX-License-Identifier: Apache-2.0
package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"godseye/internal/webcheck"
	"godseye/internal/workbench"
)

func TestIntelligenceAPIUsesRetainedSourcesAndRequestGuards(t *testing.T) {
	app, err := New(context.Background(), t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler("127.0.0.1:8765", t.TempDir())
	imported := invoke(handler, "POST", "/api/lab/import?format=nuclei", `{"template-id":"fixture","host":"https://example.test/?token=SECRET","info":{"name":"Candidate","severity":"high"}}`)
	if imported.Code != 201 {
		t.Fatal(imported.Body.String())
	}
	response := invoke(handler, "GET", "/api/lab/intelligence?download=1", "")
	var result workbench.Intelligence
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.Findings) != 1 || result.ReportCount != 1 {
		t.Fatal(response.Body.String())
	}
	if strings.Contains(response.Body.String(), "SECRET") || !strings.Contains(response.Header().Get("Content-Disposition"), "godseye-intelligence.json") {
		t.Fatal("redaction or export failed")
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765/api/lab/intelligence", nil)
	request.Header.Set("Origin", "https://untrusted.test")
	guarded := httptest.NewRecorder()
	handler.ServeHTTP(guarded, request)
	if guarded.Code != 403 {
		t.Fatal("intelligence bypassed Origin guard")
	}
}

func TestSourceCheckPersistsNormalizedEvidenceAcrossRestart(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "fixture.txt"), []byte("-----BEGIN PRIVATE KEY-----"), 0600); err != nil {
		t.Fatal(err)
	}
	app, err := New(context.Background(), root, state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &Run{ID: "fixture", Target: ".", Kind: "source", Status: "running", StartedAt: time.Now(), cancel: cancel}
	app.execute(ctx, run, root)
	if run.Status != "completed" || run.FindingCount != 1 {
		t.Fatalf("unexpected scan: %+v", run)
	}
	restored, err := New(context.Background(), root, state)
	if err != nil {
		t.Fatal(err)
	}
	result := restored.evidence.Intelligence(time.Now())
	if result.ReportCount != 1 || len(result.Findings) != 1 || result.Findings[0].References[0].Tool != "source-scan" {
		t.Fatalf("scan evidence not durable: %+v", result)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "BEGIN PRIVATE KEY") || strings.Contains(string(data), root) {
		t.Fatal("source content or absolute workspace path leaked")
	}
}

func TestRunEvidenceDistinguishesResponseReviewAndPartialCoverage(t *testing.T) {
	run := &Run{Kind: "website", Target: "https://example.test/?token=SECRET", Status: "cancelled", Checks: []webcheck.Check{{Name: "CSP", Status: "review", Detail: "Missing"}}, ReviewCount: 1}
	r := runEvidence(run)
	if !r.Limited || len(r.Findings) != 1 || r.Findings[0].Severity != "low" || strings.Contains(r.Findings[0].Target, "SECRET") {
		t.Fatalf("review or redaction incorrect: %+v", r)
	}
}

func TestEvidencePersistenceFailureMarksCompletedScanPartial(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	app, err := New(context.Background(), root, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(state, "evidence")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &Run{ID: "fixture", Target: ".", Kind: "source", Status: "running", StartedAt: time.Now(), cancel: cancel}
	app.execute(ctx, run, root)
	if run.Status != "partial" || !strings.Contains(strings.Join(run.Gaps, " "), "could not be saved") {
		t.Fatalf("persistence failure was hidden: %+v", run)
	}
}
