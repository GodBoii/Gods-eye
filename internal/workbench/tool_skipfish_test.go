// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSkipfishCrawlScopeAndSafePaths(t *testing.T) {
	outsideRequests := 0
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideRequests++ }))
	defer outside.Close()
	requests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests[req.URL.RequestURI()]++
		if req.Method != "GET" {
			t.Errorf("unexpected method %s", req.Method)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch req.URL.Path {
		case "/":
			fmt.Fprintf(w, `<a href='/about#section'>about</a><a href='/about'>duplicate</a>
<a href='%s/escape'>external</a><a href='//%s/protocol'>protocol relative</a>
<a href='/logout'>logout</a><a href='/%%64elete'>encoded delete</a><a href='/%%2564elete'>nested delete</a>
<a href='/read?token=SECRET'>query</a><a href='/read?'>empty query</a><a href='http://user:pass@%s/credentials'>credentials</a>
<a href='/redirect'>redirect</a><form action='/submit' method='post'><input name='x'></form>
<!-- <a href='/comment'>hidden</a> --><script>var x="<a href='/script'>";</script>
<a title=" href='/fake'" href='/real'>real</a><a href='/asset.zip'>asset</a>`, outside.URL, strings.TrimPrefix(outside.URL, "http://"), req.Host)
		case "/about":
			fmt.Fprint(w, `<a href='/nested'>next</a>`)
		case "/nested":
			fmt.Fprint(w, `<a href='/too-deep'>depth</a>`)
		case "/redirect":
			w.Header().Set("Location", outside.URL)
			w.WriteHeader(http.StatusFound)
		case "/real":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	r, err := auditSkipfish(context.Background(), ToolRequest{Target: server.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if outsideRequests != 0 {
		t.Fatalf("fetched outside origin %d times", outsideRequests)
	}
	want := map[string]bool{"/": true, "/about": true, "/redirect": true, "/real": true, "/nested": true}
	if len(requests) != len(want) {
		t.Fatalf("unexpected requests: %+v", requests)
	}
	for endpoint, count := range requests {
		if !want[endpoint] || count != 1 {
			t.Errorf("unexpected requests: %+v", requests)
		}
	}
	if !r.Limited || !strings.Contains(r.Summary, "5 URLs") {
		t.Fatalf("incorrect coverage: %+v", r)
	}
	foundError, foundHeaders := false, false
	for _, f := range r.Findings {
		foundError = foundError || f.Title == "HTTP error response"
		foundHeaders = foundHeaders || f.Title == "Missing Content-Security-Policy header"
	}
	if !foundError || !foundHeaders {
		t.Fatalf("expected error/header review findings: %+v", r.Findings)
	}
}

func TestSkipfishPageCapAndCancellation(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			for i := 0; i < 20; i++ {
				fmt.Fprintf(w, `<a href='/page%d'>page</a>`, i)
			}
		}
	}))
	defer server.Close()
	r, err := auditSkipfish(context.Background(), ToolRequest{Target: server.URL + "/"})
	if err != nil || !r.Limited || requests != 8 {
		t.Fatalf("page cap: requests=%d report=%+v err=%v", requests, r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = auditSkipfish(ctx, ToolRequest{Target: server.URL + "/"})
	if err != nil || !r.Limited || requests != 8 || !strings.Contains(r.Summary, "0 URLs") {
		t.Fatalf("cancel: %+v %v requests=%d", r, err, requests)
	}
}

func TestSkipfishBodyBaseAndNonHTMLLimits(t *testing.T) {
	for _, tc := range []struct {
		name, body, media string
		limited           bool
	}{
		{"base", `<base href='https://example.test/'><a href='/hidden'>link</a>`, "text/html", true},
		{"non-html", `<a href='/hidden'>link</a>`, "text/plain", false},
		{"truncated", strings.Repeat(" ", auditBodyLimit+1), "text/html", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", tc.media)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			r, err := auditSkipfish(context.Background(), ToolRequest{Target: server.URL})
			if err != nil || r.Limited != tc.limited || requests != 1 {
				t.Fatalf("report=%+v err=%v requests=%d", r, err, requests)
			}
		})
	}
}

func TestSkipfishMarkupAndValidation(t *testing.T) {
	for _, req := range []ToolRequest{{RunEngine: true}, {Input: "report"}, {Target: "http://example.test/?secret=x"}, {Target: "http://example.test/logout"}, {Target: "http://example.test/admin"}, {Target: "http://user:pass@example.test/"}, {Target: "file:///tmp/test"}} {
		if _, err := auditSkipfish(context.Background(), req); err == nil {
			t.Fatalf("accepted unsafe request %+v", req)
		}
	}
	base, err := url.Parse("https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	r := newReport("skipfish", "fixture", nil)
	skipfishInsecureMarkup(r, base, skipfishMarkup(`<form action="http://example.test/submit"></form><img src='http://example.test/a.png'><script src='http://example.test/script.js'>"<form action='http://example.test/ignored'>"</script><!-- <iframe src='http://other.test'> -->`))
	if len(r.Findings) != 2 {
		t.Fatalf("expected form and resource findings: %+v", r.Findings)
	}
	clean := skipfishMarkup(`<script> var x = "<a href='/fake'>"`)
	if strings.Contains(clean, "fake") {
		t.Fatalf("unclosed script contents retained: %q", clean)
	}
}
