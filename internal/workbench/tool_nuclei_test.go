// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNucleiNativeExposureRules(t *testing.T) {
	tests := []struct {
		name, path, contentType, body, title string
		status                               int
	}{
		{"directory listing", "/", "text/html", `<title>Index of /private/</title><a href="../">Parent Directory</a>`, "Directory listing exposed", 200},
		{"listing text alone", "/", "text/html", `<p>Index of /private/</p>`, "", 200},
		{"commented listing", "/", "text/html", `<!-- <title>Index of /</title><a href="../">Parent</a> -->`, "", 200},
		{"listing in denied page", "/", "text/html", `<title>Index of /</title><a href="../">Parent</a>`, "", 403},
		{"python error", "/", "text/html", "Traceback (most recent call last)\nFile &quot;/app/main.py&quot;, line 42", "Application debug traceback exposed", 500},
		{"traceback word alone", "/", "text/html", `Traceback example`, "", 200},
		{"source map", "/main.js.map", "application/json", `{"version":3,"sources":["main.ts"],"mappings":"AAAA","sourcesContent":["export const x = 1;"]}`, "Source map exposes embedded source", 200},
		{"map without embedded source", "/main.js.map", "application/json", `{"version":3,"sources":["main.ts"],"mappings":"AAAA"}`, "", 200},
		{"map absent", "/main.js.map", "application/json", `{"version":3,"sources":["main.ts"],"mappings":"AAAA","sourcesContent":["x"]}`, "", 404},
		{"json not map endpoint", "/data.json", "application/json", `{"version":3,"sources":["main.ts"],"mappings":"AAAA","sourcesContent":["x"]}`, "", 200},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests++
				if req.Method != http.MethodGet || req.URL.Path != tc.path {
					t.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
				}
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			report, err := auditNuclei(context.Background(), ToolRequest{Target: server.URL + tc.path, Authorized: true})
			if err != nil {
				t.Fatal(err)
			}
			if requests != 1 {
				t.Fatalf("expected one request; got %d", requests)
			}
			if tc.title == "" && len(report.Findings) != 0 || tc.title != "" && (len(report.Findings) != 1 || report.Findings[0].Title != tc.title) {
				t.Fatalf("expected title %q; got %#v", tc.title, report.Findings)
			}
			if len(report.Gaps) == 0 || !strings.Contains(report.Summary, "one URL") {
				t.Fatal("missing coverage limits or findings summary")
			}
		})
	}
}

func TestNucleiCookieEvidenceDoesNotRetainValues(t *testing.T) {
	r := newReport("nuclei", "", nil)
	response := &AuditResponse{URL: "https://example.com/", Header: http.Header{"Set-Cookie": {"__Host-auth=private-cookie-secret; Path=/wrong; SameSite=None"}}}
	nucleiCookieRules(r, response)
	if len(r.Findings) != 3 {
		t.Fatalf("expected three attribute findings, got %#v", r.Findings)
	}
	for _, finding := range r.Findings {
		if strings.Contains(finding.Detail, "private-cookie-secret") || strings.Contains(finding.Detail, "__Host-auth") {
			t.Fatal("cookie evidence retained a name or value")
		}
	}
	r = newReport("nuclei", "", nil)
	response.Header.Set("Set-Cookie", "__Host-auth=secret; Secure; Path=/; HttpOnly; SameSite=Lax")
	nucleiCookieRules(r, response)
	if len(r.Findings) != 0 {
		t.Fatalf("valid cookie attributes reported: %#v", r.Findings)
	}
}

func TestNucleiRequestModes(t *testing.T) {
	if _, err := auditNuclei(context.Background(), ToolRequest{RunEngine: true}); err == nil {
		t.Fatal("unsupported engine silently accepted")
	}
	if _, err := auditNuclei(context.Background(), ToolRequest{Target: "https://example.com", Input: "{}"}); err == nil {
		t.Fatal("ambiguous request accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditNuclei(ctx, ToolRequest{Target: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("cancelled request accepted")
	}
}
