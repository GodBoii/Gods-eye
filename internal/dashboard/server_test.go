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
)

func invoke(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://127.0.0.1:8765"+path, strings.NewReader(body))
	request.Header.Set("X-GodsEye-Request", "1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestServerInventoryAndBoundaries(t *testing.T) {
	root := t.TempDir()
	state := t.TempDir()
	app, err := New(context.Background(), root, state)
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler("127.0.0.1:8765", t.TempDir())
	result := invoke(handler, "POST", "/api/assets", `{"name":"Local project","kind":"source","target":".","owner":"Me"}`)
	if result.Code != 201 {
		t.Fatal(result.Code, result.Body.String())
	}
	restored, err := New(context.Background(), root, state)
	if err != nil || len(restored.assets) != 1 {
		t.Fatal("inventory did not persist", err)
	}
	for _, body := range []string{`{"target":"..","kind":"source","authorized":true}`, `{"target":".","kind":"source","authorized":false}`, `{"target":"db","kind":"database","authorized":true}`, `{"target":".","kind":"source","authorized":true,"unknown":1}`} {
		if response := invoke(handler, "POST", "/api/runs", body); response.Code != 400 {
			t.Fatal("invalid request accepted", response.Code)
		}
	}
	for _, test := range []struct{ host, origin, header string }{{"evil.example", "", "1"}, {"127.0.0.1:8765", "https://evil.example", "1"}, {"127.0.0.1:8765", "", ""}} {
		request := httptest.NewRequest("POST", "http://127.0.0.1:8765/api/runs", strings.NewReader(`{}`))
		request.Host = test.host
		request.Header.Set("Origin", test.origin)
		request.Header.Set("X-GodsEye-Request", test.header)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 403 {
			t.Fatal("cross-origin request not blocked")
		}
	}
}

func TestScanWorkflowAndReports(t *testing.T) {
	root := t.TempDir()
	token := "AKIA" + strings.Repeat("A", 16)
	if err := os.WriteFile(filepath.Join(root, "candidate.txt"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app, err := New(ctx, root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler("127.0.0.1:8765", t.TempDir())
	response := invoke(handler, "POST", "/api/runs", `{"target":".","kind":"source","authorized":true}`)
	if response.Code != 202 {
		t.Fatal(response.Body.String())
	}
	var started struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response = invoke(handler, "GET", "/api/runs/"+started.ID, "")
		var result Run
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Status == "completed" {
			if result.FindingCount != 1 || len(result.Findings) != 1 {
				t.Fatal("missing candidate")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scan did not complete", result.Status)
		}
		time.Sleep(5 * time.Millisecond)
	}
	summary := invoke(handler, "GET", "/api/state", "")
	if strings.Contains(summary.Body.String(), "Private key") || strings.Contains(summary.Body.String(), "AWS access key identifier") {
		t.Fatal("polling endpoint leaked full finding payload")
	}
	for _, format := range []string{"json", "sarif"} {
		download := invoke(handler, "GET", "/api/runs/"+started.ID+"/report?format="+format, "")
		if download.Code != 200 || !json.Valid(download.Body.Bytes()) || strings.Contains(download.Body.String(), token) {
			t.Fatal("invalid or unredacted report")
		}
	}
}

func TestSingleRunAdmissionAndCancel(t *testing.T) {
	app, err := New(context.Background(), t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.runs = []*Run{{ID: "held", Status: "running", cancel: cancel}}
	handler := app.Handler("127.0.0.1:8765", t.TempDir())
	response := invoke(handler, "POST", "/api/runs", `{"target":".","kind":"source","authorized":true}`)
	if response.Code != 409 {
		t.Fatal("concurrency limit not enforced")
	}
	if response := invoke(handler, "POST", "/api/runs/held/cancel", ""); response.Code != 200 {
		t.Fatal("cancel failed")
	}
	if ctx.Err() == nil || app.runs[0].Status != "cancelling" {
		t.Fatal("cancellation did not propagate")
	}
}

type blockedReportWriter struct {
	header  http.Header
	entered chan struct{}
	release chan struct{}
}

func (w *blockedReportWriter) Header() http.Header { return w.header }
func (w *blockedReportWriter) WriteHeader(int)     {}
func (w *blockedReportWriter) Write(data []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(data), nil
}

func TestSlowReportDoesNotBlockStateRequests(t *testing.T) {
	app, err := New(context.Background(), t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app.runs = []*Run{{ID: "finished", Status: "completed", jsonReport: []byte(`{}`)}}
	handler := app.Handler("127.0.0.1:8765", t.TempDir())
	writer := &blockedReportWriter{http.Header{}, make(chan struct{}), make(chan struct{})}
	finished := make(chan struct{})
	go func() {
		handler.ServeHTTP(writer, httptest.NewRequest("GET", "http://127.0.0.1:8765/api/runs/finished/report?format=json", nil))
		close(finished)
	}()
	defer func() { close(writer.release); <-finished }()
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("report download never started")
	}
	stateDone := make(chan int, 1)
	go func() { stateDone <- invoke(handler, "GET", "/api/state", "").Code }()
	select {
	case status := <-stateDone:
		if status != 200 {
			t.Fatalf("state request returned %d", status)
		}
	case <-time.After(time.Second):
		t.Fatal("slow report download blocked the workspace state request")
	}
}

func TestInventorySizeLimit(t *testing.T) {
	file := filepath.Join(t.TempDir(), "assets.json")
	if err := os.WriteFile(file, []byte(strings.Repeat(" ", (1<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAssets(file); err == nil || !strings.Contains(err.Error(), "storage limit") {
		t.Fatalf("oversized inventory was not rejected: %v", err)
	}
}
