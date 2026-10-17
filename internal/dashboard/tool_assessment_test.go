// SPDX-License-Identifier: Apache-2.0
package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"godseye/internal/workbench"
)

func TestToolAssessmentAPIExecutesAndPersists(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	app, err := New(context.Background(), root, state)
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler("127.0.0.1:8765", t.TempDir())
	health := invoke(handler, "GET", "/api/health", "")
	if health.Code != 200 || !strings.Contains(health.Body.String(), "tool-assessments-v1") {
		t.Fatal("missing server capability handshake", health.Body.String())
	}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>Index of /private</title><a href="../">Parent Directory</a>`))
	}))
	defer page.Close()
	data, err := json.Marshal(workbench.ToolRequest{Tool: "nuclei", Target: page.URL, Authorized: true})
	if err != nil {
		t.Fatal(err)
	}
	response := invoke(handler, "POST", "/api/lab/assess", string(data))
	var report workbench.Report
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &report) != nil || report.ID == "" || len(report.Findings) != 1 {
		t.Fatal(response.Code, response.Body.String())
	}
	reopened, err := New(context.Background(), root, state)
	if err != nil {
		t.Fatal(err)
	}
	download := invoke(reopened.Handler("127.0.0.1:8765", t.TempDir()), "GET", "/api/lab/reports/"+report.ID+"?download=1", "")
	if download.Code != 200 || !strings.Contains(download.Header().Get("Content-Disposition"), report.ID) {
		t.Fatal("tool report failed persistence/export", download.Body.String())
	}
	for _, body := range []string{`{"tool":"nuclei","target":"` + page.URL + `","authorized":false}`, `{"tool":"unknown","authorized":true}`, `{"tool":"nuclei","authorized":true,"command":"whoami"}`, `{} {}`} {
		response := invoke(handler, "POST", "/api/lab/assess", body)
		if response.Code != 400 {
			t.Fatal("invalid assessment request accepted", response.Code, response.Body.String())
		}
	}
	list := invoke(handler, "GET", "/api/lab/capabilities", "")
	var capabilities []workbench.ToolCapability
	if list.Code != 200 || json.Unmarshal(list.Body.Bytes(), &capabilities) != nil || len(capabilities) != len(workbench.ToolCapabilities()) {
		t.Fatal("invalid capability API")
	}
}
