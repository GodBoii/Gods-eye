// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sherlockRequest(t *testing.T, username string, profiles ...sherlockProfile) ToolRequest {
	t.Helper()
	data, err := json.Marshal(map[string]any{"username": username, "profiles": profiles})
	if err != nil {
		t.Fatal(err)
	}
	return ToolRequest{Input: string(data)}
}

func TestSherlockResponseStatesAndPrivacy(t *testing.T) {
	profiles := []sherlockProfile{}
	for _, status := range []int{200, 301, 401, 403, 404, 410, 429, 500} {
		profiles = append(profiles, sherlockProfile{URL: "https://example.test/private_user", Status: status, Title: "Private Name private@example.test", ObservedAt: time.Now().UTC().Format(time.RFC3339)})
	}
	r, err := auditSherlock(context.Background(), sherlockRequest(t, "private_user", profiles...))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited || len(r.Observations) != len(profiles) {
		t.Fatalf("missing bounded evidence: %+v", r)
	}
	for i, want := range []string{"account existence remains unverified", "destination was not verified", "access blocked", "access blocked", "missing resource", "missing resource", "rate limited", "server failure"} {
		if !strings.Contains(r.Observations[i].Value, want) {
			t.Errorf("status %d: %s", profiles[i].Status, r.Observations[i].Value)
		}
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private_user", "Private Name", "private@example.test", "https://example.test"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("report retained private profile data: %s", secret)
		}
	}
	if r.InputSHA256 != "" {
		t.Fatal("private input fingerprint retained")
	}
}

func TestSherlockSoft404CanonicalAndFreshness(t *testing.T) {
	profile := sherlockProfile{URL: "https://example.test/other", Status: 200, Title: "Page Not Found | Example", Canonical: "https://login.example.test/", ObservedAt: time.Now().Add(-31 * 24 * time.Hour).UTC().Format(time.RFC3339)}
	r, err := auditSherlock(context.Background(), sherlockRequest(t, "test", profile))
	if err != nil {
		t.Fatal(err)
	}
	for _, title := range []string{"Profile path differs from supplied username", "Canonical URL differs from profile URL", "Possible soft 404 response", "Stale profile observation"} {
		found := false
		for _, f := range r.Findings {
			found = found || f.Title == title
		}
		if !found {
			t.Errorf("missing %s", title)
		}
	}
	profile.Canonical = "https://example.test/test/"
	profile.URL = "https://example.test/test"
	profile.Title = "Normal profile"
	profile.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	r, err = auditSherlock(context.Background(), sherlockRequest(t, "test", profile))
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("normal evidence produced errors: %+v %v", r, err)
	}
}

func TestSherlockRejectsMalformedAndScopedInput(t *testing.T) {
	valid := sherlockProfile{URL: "https://example.test/test", Status: 200, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, raw := range []string{"http://example.test/test", "https://user:pass@example.test/test", "https://example.test/test?token=secret", "https://example.test/test#fragment", "https://example.test/test?", "https://example.test/a%40b.test", "file:///test", "https://example.test/a%0Ab"} {
		profile := valid
		profile.URL = raw
		if _, err := auditSherlock(context.Background(), sherlockRequest(t, "test", profile)); err == nil {
			t.Errorf("accepted URL %q", raw)
		}
	}
	for _, username := range []string{"", "@test", "a@example.test", "../test", strings.Repeat("a", 65), "测试"} {
		if _, err := auditSherlock(context.Background(), sherlockRequest(t, username, valid)); err == nil {
			t.Errorf("accepted username %q", username)
		}
	}
	for _, timestamp := range []string{"", "yesterday", "1999-01-01T00:00:00Z", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)} {
		profile := valid
		profile.ObservedAt = timestamp
		if _, err := auditSherlock(context.Background(), sherlockRequest(t, "test", profile)); err == nil {
			t.Errorf("accepted timestamp %q", timestamp)
		}
	}
	for _, status := range []int{0, 199, 600} {
		profile := valid
		profile.Status = status
		if _, err := auditSherlock(context.Background(), sherlockRequest(t, "test", profile)); err == nil {
			t.Errorf("accepted status %d", status)
		}
	}
	invalidCanonical := valid
	invalidCanonical.Canonical = "https://example.test/?email=secret"
	requests := []ToolRequest{
		{}, {RunEngine: true}, {Target: "https://example.test/test"}, {Input: "{} {}"}, {Input: `{"username":"test","profiles":[],"extra":true}`},
		{Input: strings.Repeat("a", 256<<10+1)}, {Input: "?", Encoding: "base64"},
		sherlockRequest(t, "test"), sherlockRequest(t, "test", make([]sherlockProfile, 33)...), sherlockRequest(t, "test", invalidCanonical),
	}
	for i, req := range requests {
		if _, err := auditSherlock(context.Background(), req); err == nil {
			t.Errorf("accepted malformed request %d", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditSherlock(ctx, sherlockRequest(t, "test", valid)); err == nil {
		t.Fatal("ignored context cancellation")
	}
}
