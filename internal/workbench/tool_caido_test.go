// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func caidoFixture(t *testing.T, urls []string, statuses []int, bodies []string) map[string]any {
	t.Helper()
	entries := make([]any, len(urls))
	for i := range urls {
		content := map[string]any{"mimeType": "text/html;secret=MIMESECRET"}
		if bodies != nil {
			content["text"] = bodies[i]
		}
		entries[i] = map[string]any{"request": map[string]any{"method": "GET", "url": urls[i], "headers": []any{map[string]any{"name": "Authorization", "value": "HEADERSECRET"}}, "cookies": []any{map[string]any{"name": "session", "value": "COOKIESECRET"}}}, "response": map[string]any{"status": statuses[i], "content": content}}
	}
	return map[string]any{"log": map[string]any{"version": "1.2", "entries": entries}}
}

func caidoRequest(t *testing.T, a, b map[string]any, denied []string) ToolRequest {
	t.Helper()
	doc := map[string]any{"baseline": a, "candidate": b}
	if denied != nil {
		doc["expectDenied"] = denied
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return ToolRequest{Tool: "caido", Input: string(data)}
}

func TestCaidoComparisonContractAndPrivacy(t *testing.T) {
	a := caidoFixture(t, []string{"https://EXAMPLE.com:443/private?token=QUERYSECRET"}, []int{403}, []string{"BODYSECRET forbidden"})
	b := caidoFixture(t, []string{"https://example.com/private?token=OTHERSECRET"}, []int{200}, []string{"BODYSECRET <form>login</form>"})
	req := caidoRequest(t, a, b, []string{"/private"})
	r, err := auditCaido(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited || len(r.Findings) != 1 || r.Findings[0].Severity != "info" {
		t.Fatalf("expected one unverified review candidate: %+v", r)
	}
	if !strings.Contains(r.Findings[0].Detail, "not confirmed") || !strings.Contains(strings.Join(r.Gaps, " "), "Login/error pages") {
		t.Fatal("missing login-page/verification qualification")
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"QUERYSECRET", "OTHERSECRET", "BODYSECRET", "COOKIESECRET", "HEADERSECRET", "MIMESECRET", "token="} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("report leaked %s", secret)
		}
	}
	req = caidoRequest(t, a, b, nil)
	r, err = auditCaido(context.Background(), req)
	if err != nil || len(r.Findings) != 0 {
		t.Fatal("status difference alone must not produce a vulnerability", err)
	}
}

func TestCaidoOriginScopeAndAmbiguity(t *testing.T) {
	tests := []struct {
		name         string
		urlsA, urlsB []string
		scope        string
		matched      bool
	}{
		{"different origins", []string{"https://a.example/p"}, []string{"https://b.example/p"}, "", false},
		{"default port normalized", []string{"https://a.example:443/p"}, []string{"https://a.example/p"}, "", true},
		{"scope exclusion", []string{"https://a.example/p"}, []string{"https://a.example/p"}, "https://b.example", false},
		{"query ambiguity", []string{"https://a.example/p?a=1", "https://a.example/p?a=2"}, []string{"https://a.example/p?a=3"}, "", false},
		{"encoded paths distinct", []string{"https://a.example/a%2Fb"}, []string{"https://a.example/a/b"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusesA, statusesB := make([]int, len(tt.urlsA)), make([]int, len(tt.urlsB))
			for i := range statusesA {
				statusesA[i] = 403
			}
			for i := range statusesB {
				statusesB[i] = 200
			}
			req := caidoRequest(t, caidoFixture(t, tt.urlsA, statusesA, nil), caidoFixture(t, tt.urlsB, statusesB, nil), []string{"/p"})
			req.Target = tt.scope
			r, err := auditCaido(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, o := range r.Observations {
				if o.Kind == "capture comparison" {
					count++
				}
			}
			if (count == 1) != tt.matched {
				t.Fatalf("matched %d: %+v", count, r)
			}
			if !tt.matched && len(r.Findings) != 0 {
				t.Fatal("unmatched evidence produced candidate")
			}
		})
	}
}

func TestCaidoBodyEncodingAndMissing(t *testing.T) {
	a := caidoFixture(t, []string{"https://a.example/p"}, []int{200}, []string{"same body"})
	b := caidoFixture(t, []string{"https://a.example/p"}, []int{200}, []string{"unused"})
	entry := b["log"].(map[string]any)["entries"].([]any)[0].(map[string]any)
	content := entry["response"].(map[string]any)["content"].(map[string]any)
	content["text"] = base64.StdEncoding.EncodeToString([]byte("same body"))
	content["encoding"] = "base64"
	r, err := auditCaido(context.Background(), caidoRequest(t, a, b, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Observations[2].Value, "equal=true") {
		t.Fatalf("base64 not compared correctly: %+v", r.Observations)
	}
	delete(content, "text")
	delete(content, "encoding")
	r, err = auditCaido(context.Background(), caidoRequest(t, a, b, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Observations[2].Value, "unavailable") {
		t.Fatal("missing bodies considered equal")
	}
	content["text"] = "%%invalid"
	content["encoding"] = "base64"
	if _, err = auditCaido(context.Background(), caidoRequest(t, a, b, nil)); err == nil {
		t.Fatal("invalid base64 accepted")
	}
	content["text"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", auditBodyLimit+1)))
	if _, err = auditCaido(context.Background(), caidoRequest(t, a, b, nil)); err == nil {
		t.Fatal("oversized decoded body accepted")
	}
}

func TestCaidoValidationAndCancellation(t *testing.T) {
	a := caidoFixture(t, []string{"https://a.example/p"}, []int{200}, nil)
	valid := caidoRequest(t, a, a, nil)
	tests := []struct {
		name string
		req  ToolRequest
	}{
		{"engine", ToolRequest{RunEngine: true, Input: valid.Input}},
		{"empty", ToolRequest{}},
		{"unknown", ToolRequest{Input: `{"baseline":{},"candidate":{},"command":"secret"}`}},
		{"duplicate", ToolRequest{Input: `{"baseline":{},"baseline":{},"candidate":{}}`}},
		{"trailing", ToolRequest{Input: valid.Input + ` {}`}},
		{"null", ToolRequest{Input: `{"baseline":null,"candidate":null}`}},
		{"scope path", ToolRequest{Input: valid.Input, Target: "https://a.example/path"}},
		{"userinfo", ToolRequest{Input: valid.Input, Target: "https://user:secret@a.example"}},
		{"query denial", caidoRequest(t, a, a, []string{"/p?secret=x"})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := auditCaido(context.Background(), tt.req); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditCaido(ctx, valid); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
	a["log"].(map[string]any)["version"] = "1.1"
	if _, err := auditCaido(context.Background(), caidoRequest(t, a, a, nil)); err == nil {
		t.Fatal("wrong HAR version accepted")
	}
}
