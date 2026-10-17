// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDNSResolverFailureMarksIncomplete(t *testing.T) {
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fixture resolver outage")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	report, err := DNS(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Limited || len(report.Observations) != 0 || len(report.Findings) != 0 || len(report.Gaps) < 5 {
		t.Fatalf("resolver outage reported incorrectly: %+v", report)
	}
}

func TestAssessmentTransportScopeAndRedaction(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer server.Close()
	response, err := fetchAuditURL(context.Background(), server.URL+"/?token=PRIVATE_FIXTURE")
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != 302 || requests != 1 || strings.Contains(response.URL, "PRIVATE_FIXTURE") {
		t.Fatalf("scope or URL redaction failed: %+v", response)
	}
	for _, target := range []string{"file:///tmp/x", "http://user:pass@example.com/", "http://169.254.169.254/", "http://100.100.100.200/", "http://[::]/"} {
		if _, err := fetchAuditURL(context.Background(), target); err == nil {
			t.Errorf("accepted unsafe target %q", target)
		}
	}
}

func TestAssessmentTransportBoundsAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", auditBodyLimit+8)))
	}))
	defer server.Close()
	response, err := fetchAuditURL(context.Background(), server.URL)
	if err != nil || !response.Truncated || len(response.Body) != auditBodyLimit {
		t.Fatalf("body cap failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fetchAuditURL(ctx, server.URL); err == nil {
		t.Fatal("cancelled request executed")
	}
}

func TestToolAssessmentBoundary(t *testing.T) {
	for _, request := range []ToolRequest{{Tool: "nuclei"}, {Tool: "unknown", Authorized: true}, {Tool: "nuclei", Authorized: true, RunEngine: true}, {Tool: "nmap", Authorized: true, Ports: make([]int, 33)}} {
		if _, err := AuditTool(context.Background(), request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
	for _, request := range []ToolRequest{{Encoding: "base64", Input: "!"}, {Encoding: "invalid", Input: "x"}} {
		if _, err := toolInput(request); err == nil {
			t.Fatal("invalid encoding accepted")
		}
	}
	if _, err := runAuditEngine(context.Background(), "powershell", nil); err == nil {
		t.Fatal("arbitrary executable accepted")
	}
}
