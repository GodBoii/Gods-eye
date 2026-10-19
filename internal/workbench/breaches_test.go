// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type breachTransport func(*http.Request) (*http.Response, error)

func (f breachTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testBreachChecker(status int, body string) *BreachChecker {
	return &BreachChecker{client: &http.Client{Transport: breachTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}}
}

func TestEmailBreachResults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		count  int
		fail   bool
	}{
		{"found", 200, `{"status":"success","email":"Private+Tag@example.com","breaches":[["Example","Example","Other"]],"password":"SECRET"}`, 2, false},
		{"not found", 404, `{"Error":"Not found","email":null}`, 0, false},
		{"not found 200", 200, `{"Error":"Not found","email":null}`, 0, false},
		{"empty success", 200, `{"status":"success","breaches":[]}`, 0, false},
		{"unexpected 404", 404, `{}`, 0, true},
		{"html", 404, `<html>Not found</html>`, 0, true},
		{"missing breaches", 200, `{"status":"success"}`, 0, true},
		{"provider error", 200, `{"Error":"Hidden"}`, 0, true},
		{"wrong shape", 200, `{"status":"success","breaches":["Example"]}`, 0, true},
		{"empty name", 200, `{"status":"success","breaches":[[""]]}`, 0, true},
		{"redirect", 302, `{}`, 0, true},
		{"rate limit", 429, `{}`, 0, true},
		{"outage", 503, `{}`, 0, true},
		{"oversized", 200, strings.Repeat("x", (256<<10)+1), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := testBreachChecker(tc.status, tc.body)
			report, err := checker.Check(context.Background(), "Private+Tag@example.com")
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.fail {
				return
			}
			if len(report.Findings) != tc.count {
				t.Fatalf("wrong breach count: %+v", report)
			}
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"Private", "SECRET", "Tag@example.com"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatal("saved report retained submitted address or raw provider data")
				}
			}
			if !strings.Contains(string(encoded), breachSource) || len(report.Gaps) == 0 {
				t.Fatal("missing source or coverage")
			}
		})
	}
}

func TestEmailBreachRequestBoundary(t *testing.T) {
	checker := testBreachChecker(200, `{"status":"success","breaches":[]}`)
	for _, email := range []string{"a..b@example.com", ".a@example.com", "a.@example.com", "a@localhost", "a@-example.com", "a@example-.com", "a@example.com/path", "a\r\n@example.com", strings.Repeat("x", 65) + "@example.com"} {
		if _, err := checker.Check(context.Background(), email); err == nil {
			t.Fatalf("accepted %q", email)
		}
	}
	checker.client.Transport = breachTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.xposedornot.com" || r.URL.Scheme != "https" || r.URL.Query().Encode() != "" || r.Header.Get("User-Agent") == "" {
			t.Fatal("unexpected provider request")
		}
		if !strings.HasSuffix(r.URL.Path, "/A+tag?x@example.com") {
			t.Fatal("email did not stay within the encoded path")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"success","breaches":[]}`))}, nil
	})
	if _, err := checker.Check(context.Background(), "A+tag?x@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := checker.Check(context.Background(), "other@example.com"); err == nil {
		t.Fatal("missing request throttle")
	}
	checker.next = time.Time{}
	checker.client.Transport = breachTransport(func(r *http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	if _, err := checker.Check(context.Background(), "other@example.com"); err == nil || strings.Contains(err.Error(), "other@example.com") {
		t.Fatal("provider transport errors must fail without disclosing the address")
	}
	checker.next = time.Time{}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := checker.Check(cancelled, "other@example.com"); err == nil {
		t.Fatal("ignored cancellation")
	}
	if NewBreachChecker().client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects must not forward email")
	}
}
