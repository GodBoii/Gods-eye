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

func TestWorkbenchAPIAndPersistence(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	app, err := New(context.Background(), root, state)
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler("127.0.0.1:8765", t.TempDir())
	response := invoke(handler, "GET", "/api/lab/catalog", "")
	var catalog struct {
		Tools   []workbench.Tool
		Formats []workbench.Format
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &catalog) != nil || len(catalog.Tools) != 26 || len(catalog.Formats) != 14 {
		t.Fatal("invalid catalog", response.Body.String())
	}
	response = invoke(handler, "POST", "/api/lab/import?format=nuclei", `{"template-id":"fixture","info":{"name":"Fixture","severity":"medium"},"host":"https://example.test/?token=SECRET","request":"SECRET"}`)
	if response.Code != 201 || strings.Contains(response.Body.String(), "SECRET") {
		t.Fatal(response.Code, response.Body.String())
	}
	var report workbench.Report
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	restored, err := New(context.Background(), root, state)
	if err != nil {
		t.Fatal(err)
	}
	handler = restored.Handler("127.0.0.1:8765", t.TempDir())
	response = invoke(handler, "GET", "/api/lab/reports/"+report.ID+"?download=1", "")
	if response.Code != 200 || !strings.Contains(response.Header().Get("Content-Disposition"), report.ID) {
		t.Fatal("download/restart failed", response.Body.String())
	}
	for _, tc := range []struct {
		path, body string
		status     int
	}{
		{"/api/lab/import?format=nmap", `<issues/>`, 400},
		{"/api/lab/diagnose", `{"mode":"tcp","target":"127.0.0.1","ports":[80],"authorized":false}`, 400},
		{"/api/lab/diagnose", `{"mode":"tcp","target":"169.254.169.254","ports":[80],"authorized":true}`, 400},
		{"/api/lab/file?mode=iam", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, 201},
		{"/api/lab/file?mode=bad", "fixture", 400},
		{"/api/lab/import?format=nuclei", strings.Repeat("x", workbench.MaxInput+1), 413},
	} {
		response = invoke(handler, "POST", tc.path, tc.body)
		if response.Code != tc.status {
			t.Fatal(tc.path, response.Code, response.Body.String())
		}
	}
	for _, tc := range []struct{ origin, header string }{{"https://evil.test", "1"}, {"", ""}} {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8765/api/lab/file?mode=file", strings.NewReader("fixture"))
		request.Header.Set("Origin", tc.origin)
		request.Header.Set("X-GodsEye-Request", tc.header)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 403 {
			t.Fatal("workbench bypassed dashboard protections")
		}
	}
}
