// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPassiveReconScopeAndHistoricalEvidence(t *testing.T) {
	input := `[{"name_value":"example.com\napi.example.com\n*.example.com\napi.example.com\nnotexample.com\nexample.com.attacker.test\ninternal.private.test", "common_name":"API.EXAMPLE.COM.","not_before":"2020-01-01T00:00:00", "not_after":"2021-01-01T00:00:00", "issuer_name":"CN=public issuer", "serial_number":"abc"},{"name_value":"secret.other.test","not_before":"invalid"}]`
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	r, err := auditPassiveCertificates(context.Background(), "example.com", []byte(input), now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tool != "passive-recon" || r.Limited || len(r.Findings) != 0 {
		t.Fatalf("unexpected report: %+v", r)
	}
	names, wildcard, expired := 0, false, false
	for _, obs := range r.Observations {
		if obs.Kind == "CT certificate name" || obs.Kind == "CT wildcard pattern" {
			names++
		}
		wildcard = wildcard || obs.Kind == "CT wildcard pattern"
		expired = expired || strings.Contains(obs.Value, "Expired historical certificate")
	}
	if names != 3 || !wildcard || !expired {
		t.Fatalf("names=%d wildcard=%v expired=%v", names, wildcard, expired)
	}
	serialized, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{"attacker.test", "notexample.com", "internal.private.test", "secret.other.test", "CN=public issuer"} {
		if strings.Contains(string(serialized), excluded) {
			t.Errorf("report leaked excluded source value %q", excluded)
		}
	}
	if len(r.Edges) != 6 {
		t.Fatalf("expected deduplicated graph edges, got %d", len(r.Edges))
	}
}

func TestPassiveScopedName(t *testing.T) {
	for _, tc := range []struct {
		input, scope, want string
		wildcard           bool
	}{
		{"WWW.Example.COM.", "example.com", "www.example.com", false},
		{"*.example.com", "example.com", "*.example.com", true},
		{"*.*.example.com", "example.com", "", false},
		{"evil-example.com", "example.com", "", false},
		{"example.com.evil.test", "example.com", "", false},
		{"https://api.example.com", "example.com", "", false},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", "xn--bcher-kva.example", false},
		{"bücher.example", "xn--bcher-kva.example", "", false},
		{"1.2.3.4", "3.4", "", false},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, wildcard := passiveScopedName(tc.input, tc.scope)
			if got != tc.want || wildcard != tc.wildcard {
				t.Fatalf("got %q,%v want %q,%v", got, wildcard, tc.want, tc.wildcard)
			}
		})
	}
}

func TestPassiveReconRejectsInvalidRequests(t *testing.T) {
	for _, req := range []ToolRequest{
		{Target: "example.com", Input: "[]"},
		{Authorized: true, Target: "https://example.com", Input: "[]"},
		{Authorized: true, Target: "example.com", Input: "[]", RunEngine: true},
		{Authorized: true, Target: "example.com", Input: "[]", Ports: []int{443}},
		{Authorized: true, Target: "example.com", Encoding: "text"},
		{Authorized: true, Target: "example.com", Input: "[]", Encoding: "unsupported"},
		{Authorized: true, Target: "localhost", Input: "[]"},
		{Authorized: true, Target: "1.2.3.4", Input: "[]"},
	} {
		if _, err := auditPassiveRecon(context.Background(), req); err == nil {
			t.Errorf("accepted invalid request: %+v", req)
		}
	}
	for _, data := range []string{"", " ", "{}", "[", "[{}", "[] {}", "[{\"name_value\":3}]"} {
		if _, err := auditPassiveCertificates(context.Background(), "example.com", []byte(data), time.Now()); err == nil {
			t.Errorf("accepted malformed input %q", data)
		}
	}
}

func TestPassiveReconDatesAndCancellation(t *testing.T) {
	input := `[{"name_value":"api.example.com","not_before":"wrong","not_after":"2026-01-01"},{"name_value":"future.example.com","not_before":"2030-01-01T00:00:00Z","not_after":"2031-01-01T00:00:00Z"},{"name_value":"reverse.example.com","not_before":"2025-01-01","not_after":"2020-01-01"}]`
	r, err := auditPassiveCertificates(context.Background(), "example.com", []byte(input), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited {
		t.Fatal("invalid dates must mark assessment incomplete")
	}
	future := false
	for _, obs := range r.Observations {
		future = future || strings.Contains(obs.Value, "Validity begins in the future")
	}
	if !future {
		t.Fatal("future certificate interval was not reported")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditPassiveRecon(ctx, ToolRequest{Authorized: true, Target: "example.com", Input: input}); err != context.Canceled {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestPassiveReconRecordLimitAndNameLimit(t *testing.T) {
	input := "[" + strings.Repeat(`{"name_value":"example.com","not_before":"2020-01-01","not_after":"2021-01-01"},`, 1000) + `{"name_value":"omitted.example.com"}]`
	r, err := auditPassiveCertificates(context.Background(), "example.com", []byte(input), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited || !strings.Contains(r.Summary, "Reviewed 1000 CT records") {
		t.Fatalf("record limit was not reported: %+v", r)
	}
	for _, node := range r.Nodes {
		if node.Label == "omitted.example.com" {
			t.Fatal("read beyond record limit")
		}
	}
	encoded, err := json.Marshal([]passiveCertificateRecord{{Names: strings.Repeat("api.example.com\n", 1001), NotBefore: "2020-01-01", NotAfter: "2021-01-01"}})
	if err != nil {
		t.Fatal(err)
	}
	r, err = auditPassiveCertificates(context.Background(), "example.com", encoded, time.Now())
	if err != nil || !r.Limited {
		t.Fatalf("name limit missing: %v %+v", err, r)
	}
	if _, err := auditPassiveCertificates(context.Background(), "example.com", []byte(strings.Repeat(" ", MaxInput+1)), time.Now()); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestPassiveReconPublicTLSAddressPolicy(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true}, {"2606:4700:4700::1111", true}, {"127.0.0.1", false}, {"10.1.2.3", false}, {"::1", false}, {"fd00::1", false}, {"169.254.169.254", false}, {"100.100.100.200", false}, {"100.64.0.1", false}, {"224.0.0.1", false}, {"::ffff:127.0.0.1", false},
	} {
		if got := passivePublicAddress(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("public address %s=%v want %v", tc.ip, got, tc.want)
		}
	}
}
