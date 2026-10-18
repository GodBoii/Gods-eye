// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func runDomainZone(t *testing.T, complete bool, records ...domainRecord) *Report {
	t.Helper()
	data, err := json.Marshal(domainZone{Origin: "example.test", Complete: complete, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	r, err := auditSpiderdomain(context.Background(), ToolRequest{Input: base64.StdEncoding.EncodeToString(data), Encoding: "base64"})
	if err != nil {
		t.Fatal(err)
	}
	if r.InputSHA256 != digest(data) || r.Tool != "spiderdomain" {
		t.Fatalf("missing evidence identity: %+v", r)
	}
	return r
}

func domainHasFinding(r *Report, title string) bool {
	for _, f := range r.Findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

func TestSpiderdomainZoneConfiguration(t *testing.T) {
	r := runDomainZone(t, true,
		domainRecord{"@", "A", "192.0.2.1"},
		domainRecord{"@", "TXT", "v=spf1 +all"},
		domainRecord{"@", "TXT", "v=spf1 -all"},
		domainRecord{"_dmarc", "TXT", "v=DMARC1; p=none"},
		domainRecord{"*", "A", "192.0.2.2"},
		domainRecord{"web", "CNAME", "missing"},
		domainRecord{"web", "TXT", "configuration"},
		domainRecord{"loop", "CNAME", "loop"},
	)
	for _, title := range []string{"SPF permits every sender", "Multiple SPF records supplied", "DMARC is in monitoring mode", "Wildcard DNS record supplied", "Alias target absent from supplied zone", "CNAME conflicts with other record data", "Self-referencing CNAME"} {
		if !domainHasFinding(r, title) {
			t.Errorf("missing finding %q: %+v", title, r.Findings)
		}
	}
	if r.Limited {
		t.Fatal("small complete inventory should not be marked truncated")
	}
	if len(r.Edges) < 5 || len(r.Nodes) < 5 {
		t.Fatal("missing domain relationship evidence")
	}
	if strings.Contains(strings.ToLower(r.Summary), "takeover verified") {
		t.Fatal("inventory cannot prove takeover")
	}
}

func TestSpiderdomainZoneCompletenessAndMailValidation(t *testing.T) {
	partial := runDomainZone(t, false, domainRecord{"web", "CNAME", "missing"})
	if !partial.Limited || len(partial.Findings) != 0 {
		t.Fatalf("partial inventory inferred absence: %+v", partial)
	}
	complete := runDomainZone(t, true, domainRecord{"@", "A", "192.0.2.1"})
	if !domainHasFinding(complete, "No SPF policy in supplied complete inventory") || !domainHasFinding(complete, "No DMARC policy in supplied complete inventory") {
		t.Fatal("complete inventory absence not reviewed")
	}
	for _, tc := range []struct{ value, title string }{
		{"v=DMARC1; rua=mailto:reports@example.test", "DMARC policy tag is missing"},
		{"v=DMARC1; p=invalid", "Invalid DMARC policy value"},
	} {
		r := runDomainZone(t, true, domainRecord{"_dmarc", "TXT", tc.value})
		if !domainHasFinding(r, tc.title) {
			t.Fatalf("missing %s", tc.title)
		}
	}
	healthy := runDomainZone(t, true, domainRecord{"@", "TXT", "v=spf1 -all"}, domainRecord{"_dmarc", "TXT", "v=DMARC1; p=reject"}, domainRecord{"@", "CAA", `0 issue "ca.example"`})
	if len(healthy.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", healthy.Findings)
	}
}

func TestSpiderdomainRejectsInvalidInventory(t *testing.T) {
	for _, input := range []string{
		`{}`, `{"origin":"127.0.0.1","records":[{"name":"@","type":"A","value":"192.0.2.1"}]}`,
		`{"origin":"example.test","unknown":true,"records":[]}`,
		`{"origin":"example.test","records":[{"name":"other.test.","type":"A","value":"192.0.2.1"}]}`,
		`{"origin":"example.test","records":[{"name":"@","type":"A","value":"not-ip"}]}`,
		`{"origin":"example.test","records":[{"name":"@","type":"AAAA","value":"192.0.2.1"}]}`,
		`{"origin":"example.test","records":[{"name":"@","type":"RRSIG","value":"invalid"}]}`,
		`{"origin":"example.test","records":[{"name":"@","type":"CNAME","value":"https://example.test"}]}`,
		`{"origin":"example.test","records":[{"name":"@","type":"TXT","value":""}]}`,
		`{"origin":"example.test","records":[{"name":"@","type":"A","value":"192.0.2.1"}]} {}`,
	} {
		if _, err := auditSpiderdomain(context.Background(), ToolRequest{Input: input}); err == nil {
			t.Errorf("accepted invalid input: %s", input)
		}
	}
	records := make([]domainRecord, 1001)
	for i := range records {
		records[i] = domainRecord{"@", "TXT", "record"}
	}
	data, err := json.Marshal(domainZone{Origin: "example.test", Records: records})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditDomainZone(context.Background(), data); err == nil {
		t.Fatal("accepted too many records")
	}
}

func TestSpiderdomainRequestAndCancellation(t *testing.T) {
	for _, req := range []ToolRequest{
		{Target: "https://example.test", Authorized: true},
		{Target: "example.test"},
		{Input: "{}", Target: "example.test"},
		{Input: "{}", RunEngine: true},
		{Input: "{}", Ports: []int{443}},
		{Encoding: "text", Target: "example.test", Authorized: true},
		{Input: "invalid", Encoding: "base64"},
	} {
		if _, err := auditSpiderdomain(context.Background(), req); err == nil {
			t.Errorf("accepted invalid request: %+v", req)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditSpiderdomain(ctx, ToolRequest{Target: "example.test", Authorized: true}); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
}

type fakeDomainResolver struct {
	reverseCalls         int
	cnameErr, reverseErr error
}

func (f *fakeDomainResolver) LookupCNAME(context.Context, string) (string, error) {
	return "edge.provider.test.", f.cnameErr
}
func (f *fakeDomainResolver) LookupAddr(context.Context, string) ([]string, error) {
	f.reverseCalls++
	return []string{"ptr.provider.test."}, f.reverseErr
}

func TestSpiderdomainLiveEnrichmentBounds(t *testing.T) {
	r := newReport("spiderdomain", "fixture", nil)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"} {
		r.observe("A / AAAA", "example.test", ip)
	}
	resolver := &fakeDomainResolver{}
	enrichDomainDNS(context.Background(), r, "example.test", resolver)
	if resolver.reverseCalls != 4 || !r.Limited {
		t.Fatalf("reverse budget not applied: calls=%d report=%+v", resolver.reverseCalls, r)
	}
	if len(r.Edges) != 5 {
		t.Fatalf("missing alias/reverse edges: %+v", r.Edges)
	}
	for _, tc := range []struct {
		err     error
		limited bool
	}{
		{&net.DNSError{IsNotFound: true}, false}, {&net.DNSError{IsTimeout: true}, true},
	} {
		r := newReport("spiderdomain", "fixture", nil)
		r.observe("A / AAAA", "example.test", "192.0.2.1")
		resolver := &fakeDomainResolver{cnameErr: tc.err, reverseErr: tc.err}
		enrichDomainDNS(context.Background(), r, "example.test", resolver)
		if r.Limited != tc.limited {
			t.Fatalf("lookup failure classification incorrect: %+v", r)
		}
	}
}
