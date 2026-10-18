// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func evilginxHas(r *Report, title string) bool {
	for _, f := range r.Findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

func TestEvilginxBaselinePrivacy(t *testing.T) {
	requests := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" {
			t.Errorf("method %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Add("Set-Cookie", "private_session_name=PRIVATE_COOKIE_VALUE; Path=/")
		_, err := w.Write([]byte(`<form action="http://example.org/PRIVATE_ACTION" method="get"><input type="password" value="PRIVATE_PASSWORD"></form>`))
		if err != nil {
			t.Error(err)
		}
	}))
	defer s.Close()
	r, err := auditEvilginx3(context.Background(), ToolRequest{Target: s.URL + "/?token=PRIVATE_QUERY", Authorized: true})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || !r.Limited || !evilginxHas(r, "Session-like cookie lacks Secure") || !evilginxHas(r, "Password form uses insecure transport") || !evilginxHas(r, "Password form uses GET submission") {
		t.Fatalf("unexpected report: %+v", r)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private_session_name", "PRIVATE_COOKIE_VALUE", "PRIVATE_PASSWORD", "PRIVATE_ACTION", "PRIVATE_QUERY"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("retained %s", secret)
		}
	}
}

func TestEvilginxCookieReview(t *testing.T) {
	for _, tc := range []struct {
		name, cookie string
		weak         bool
	}{
		{"secure", "__Host-session=secret; Path=/; Secure; HttpOnly; SameSite=Lax", false},
		{"weak", "session=secret; Path=/", true},
		{"deleted", "session=secret; Max-Age=0", false},
		{"expired", "session=secret; Expires=Thu, 01 Jan 1970 00:00:00 GMT", false},
		{"static analytics", "analytics=secret", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReport("evilginx3", "", nil)
			evilginxReview(r, &AuditResponse{URL: "https://example.org/", Status: 200, Header: http.Header{"Set-Cookie": {tc.cookie}, "Strict-Transport-Security": {"max-age=31536000"}, "Content-Type": {"text/html"}, "Content-Security-Policy": {"frame-ancestors 'none'"}, "Cache-Control": {"no-store"}}})
			if evilginxHas(r, "Session-like cookie lacks Secure") != tc.weak {
				t.Fatalf("findings %+v", r.Findings)
			}
			if !tc.weak && len(r.Findings) != 0 {
				t.Fatalf("false positive %+v", r.Findings)
			}
		})
	}
}

func TestEvilginxHARValidationAndCancellation(t *testing.T) {
	for _, input := range []string{`{}`, `{"log":{"entries":[]}}`, `{"log":{"entries":[{}]}}`, `{"log":{"entries":[{"request":{"url":"https://example.org"},"response":{"status":200,"headers":[],"content":{"text":"!!!","encoding":"base64"}}}]}}`} {
		if _, err := auditEvilginx3(context.Background(), ToolRequest{Input: input}); err == nil {
			t.Errorf("accepted malformed HAR %s", input)
		}
	}
	valid := `{"log":{"entries":[{"request":{"url":"https://example.org/PRIVATE_PATH?secret=PRIVATE_QUERY"},"response":{"status":200,"headers":[{"name":"Strict-Transport-Security","value":"max-age=0"},{"name":"Set-Cookie","value":"session=PRIVATE_VALUE; HttpOnly"}]}}]}}`
	r, err := auditEvilginx3(context.Background(), ToolRequest{Input: valid})
	if err != nil {
		t.Fatal(err)
	}
	if !evilginxHas(r, "HSTS is absent, invalid or disabled") {
		t.Fatal("disabled HSTS missed")
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "PRIVATE_") {
		t.Fatal("HAR retained private evidence")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditEvilginx3(ctx, ToolRequest{Input: valid}); err != context.Canceled {
		t.Fatalf("cancel error %v", err)
	}
	if _, err := auditEvilginx3(context.Background(), ToolRequest{RunEngine: true}); err == nil {
		t.Fatal("engine accepted")
	}
	if _, err := auditEvilginx3(context.Background(), ToolRequest{Target: "http://127.0.0.1"}); err == nil {
		t.Fatal("authorization missing")
	}
}

func TestEvilginxHSTSParsing(t *testing.T) {
	for _, tc := range []struct {
		value string
		age   int64
		ok    bool
	}{{"max-age=0", 0, true}, {"max-age=60; includeSubDomains", 60, true}, {"max-age=60; max-age=1", 0, false}, {"max-age=-1", 0, false}, {"max-age=forever", 0, false}} {
		age, ok := evilginxHSTSAge([]string{tc.value})
		if age != tc.age || ok != tc.ok {
			t.Errorf("%q got %d %v", tc.value, age, ok)
		}
	}
}
