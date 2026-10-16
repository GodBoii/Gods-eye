// SPDX-License-Identifier: Apache-2.0
package webcheck

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestDestinationPolicy(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "172.16.1.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "198.18.0.1", "192.0.2.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2001:db8::1", "2002:7f00:1::"} {
		if publicIP(netip.MustParseAddr(value)) {
			t.Errorf("allowed reserved address %s", value)
		}
	}
	for _, value := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(value)) {
			t.Errorf("rejected public address %s", value)
		}
	}
}

func TestInspectRejectsUnsafeURLs(t *testing.T) {
	for _, target := range []string{"http://example.com", "https://user:password@example.com", "https://example.com/?token=secret", "https://example.com:8080", "https://127.0.0.1", "https://[::1]"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := Inspect(ctx, target, "website")
		cancel()
		if err == nil {
			t.Errorf("accepted %s", target)
		}
	}
}

func TestEvaluateDoesNotClaimFullProtection(t *testing.T) {
	response := &http.Response{StatusCode: 302, Header: http.Header{}}
	response.Header.Set("Strict-Transport-Security", "max-age=0")
	response.Header.Set("X-Content-Type-Options", "nosniff")
	checks := Evaluate(response, "api", time.Now())
	seen := map[string]Check{}
	for _, check := range checks {
		seen[check.Name] = check
	}
	if seen["Strict-Transport-Security"].Status == "pass" {
		t.Fatal("header presence treated as effective policy")
	}
	if seen["X-Content-Type-Options"].Status != "pass" {
		t.Fatal("nosniff not recognized")
	}
	if _, exists := seen["Browser content policy"]; exists {
		t.Fatal("browser policy applied to API unconditionally")
	}
	if seen["Coverage"].Status != "limited" {
		t.Fatal("missing limited coverage notice")
	}
}
