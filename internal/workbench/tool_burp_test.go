// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func burpFixture(t *testing.T, method, path string, status int, contentType string) ToolRequest {
	t.Helper()
	spec := `{"openapi":"3.0.3","servers":[{"url":"https://api.example.test/v1"}],"security":[{"bearer":[]}],"paths":{"/users/{id}":{"parameters":[{"name":"expand","in":"query","required":true}],"get":{"responses":{"200":{"content":{"application/json":{}}},"4XX":{"description":"error"}}}},"/health":{"get":{"security":[],"responses":{"default":{"content":{"text/*":{}}}}}},"/unseen":{"post":{"responses":{"204":{"description":"done"}}}}}}`
	var specValue any
	if err := json.Unmarshal([]byte(spec), &specValue); err != nil {
		t.Fatal(err)
	}
	har := map[string]any{"log": map[string]any{"version": "1.2", "entries": []any{map[string]any{"request": map[string]any{"method": method, "url": "https://api.example.test/v1" + path}, "response": map[string]any{"status": status, "content": map[string]any{"mimeType": contentType}}}}}}
	input, err := json.Marshal(map[string]any{"spec": specValue, "har": har})
	if err != nil {
		t.Fatal(err)
	}
	return ToolRequest{Input: string(input)}
}

func TestBurpContractEvidence(t *testing.T) {
	cases := []struct {
		name, method, path, mime, title string
		status, findings                int
	}{
		{"secure templated", "GET", "/users/42?expand=super-secret", "application/json; charset=utf-8", "", 200, 0},
		{"required parameter", "GET", "/users/42?other=super-secret", "application/json", "Required query parameter absent", 200, 1},
		{"status mismatch", "GET", "/users/42?expand=super-secret", "application/json", "Undocumented API response status", 302, 1},
		{"response media", "GET", "/users/42?expand=super-secret", "text/html", "API response content-type mismatch", 200, 1},
		{"method mismatch", "POST", "/users/42?expand=super-secret", "application/json", "Captured endpoint outside resolved API contract", 200, 1},
		{"status range", "GET", "/users/42?expand=super-secret", "text/plain", "", 404, 0},
		{"default and public", "GET", "/health?access_token=super-secret", "text/plain", "", 503, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := auditBurp(context.Background(), burpFixture(t, tc.method, tc.path, tc.status, tc.mime))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Findings) != tc.findings {
				t.Fatalf("findings=%+v", r.Findings)
			}
			if tc.title != "" && r.Findings[0].Title != tc.title {
				t.Fatalf("unexpected finding: %+v", r.Findings)
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "super-secret") || strings.Contains(string(encoded), "access_token") {
				t.Fatal("query leaked")
			}
			if !r.Limited {
				t.Fatal("offline report must be limited")
			}
			if tc.name == "default and public" && !strings.Contains(string(encoded), "public by declaration") {
				t.Fatal("missing public declaration observation")
			}
		})
	}
}

func TestBurpInvalidAndCancelled(t *testing.T) {
	valid := burpFixture(t, "GET", "/users/1?expand=yes", 200, "application/json")
	cases := []ToolRequest{{Input: "{}"}, {Input: "null"}, {Input: valid.Input + "{}"}, {Input: `{"spec":{},"har":{},"extra":1}`}, {Input: `{"spec":{},"spec":{},"har":{}}`}, {Input: strings.Repeat("x", MaxInput+1)}, {Input: valid.Input, RunEngine: true}, {Input: valid.Input, Target: "https://api.example.test/path"}}
	for i, req := range cases {
		if _, err := auditBurp(context.Background(), req); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditBurp(ctx, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

func TestBurpUnresolvedAndOriginFilter(t *testing.T) {
	req := burpFixture(t, "GET", "/users/1?expand=yes", 200, "application/json")
	req.Input = strings.Replace(req.Input, `"url":"https://api.example.test/v1"`, `"url":"https://{host}/v1"`, 1)
	r, err := auditBurp(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited || !strings.Contains(strings.Join(r.Gaps, " "), "unresolved") {
		t.Fatalf("missing unresolved gap: %+v", r)
	}
	req = burpFixture(t, "GET", "/users/1?expand=yes", 200, "application/json")
	req.Target = "https://other.example.test"
	r, err = auditBurp(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || !strings.Contains(r.Summary, "0 captured") {
		t.Fatalf("scope ignored: %+v", r)
	}
	req = burpFixture(t, "GET", "/users/1?expand=yes", 200, "application/json")
	req.Input = strings.Replace(req.Input, `"200":{"content":{"application/json":{}}}`, `"200":{"$ref":"https://external.example/response"}`, 1)
	r, err = auditBurp(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.Gaps, " "), "response references") {
		t.Fatal("external response ref was not disclosed")
	}
}

func TestBurpPathPriorityAndParameterOverride(t *testing.T) {
	req := burpFixture(t, "GET", "/users/current", 200, "application/json")
	var bundle map[string]any
	if err := json.Unmarshal([]byte(req.Input), &bundle); err != nil {
		t.Fatal(err)
	}
	spec := bundle["spec"].(map[string]any)
	paths := spec["paths"].(map[string]any)
	paths["/users/current"] = map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "ok"}}}}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	req.Input = string(data)
	r, err := auditBurp(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("concrete route did not override template: %+v", r.Findings)
	}
	delete(paths, "/users/current")
	paths["/users/{id}"].(map[string]any)["get"].(map[string]any)["parameters"] = []any{map[string]any{"name": "expand", "in": "query", "required": false}}
	data, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	req.Input = string(data)
	r, err = auditBurp(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("operation parameter override ignored: %+v", r.Findings)
	}
}

func TestBurpCollectionBounds(t *testing.T) {
	req := burpFixture(t, "GET", "/users/1?expand=yes", 200, "application/json")
	var bundle map[string]any
	if err := json.Unmarshal([]byte(req.Input), &bundle); err != nil {
		t.Fatal(err)
	}
	log := bundle["har"].(map[string]any)["log"].(map[string]any)
	entry := log["entries"].([]any)[0]
	entries := make([]any, maxRecords+1)
	for i := range entries {
		entries[i] = entry
	}
	log["entries"] = entries
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	req.Input = string(data)
	if _, err := auditBurp(context.Background(), req); err == nil {
		t.Fatal("oversize capture accepted")
	}
	log["entries"] = []any{entry}
	paths := map[string]any{}
	for i := 0; i < 501; i++ {
		paths[fmt.Sprintf("/p%d", i)] = map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "ok"}}}, "post": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "ok"}}}}
	}
	bundle["spec"].(map[string]any)["paths"] = paths
	data, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	req.Input = string(data)
	if _, err := auditBurp(context.Background(), req); err == nil {
		t.Fatal("oversize operation set accepted")
	}
}
