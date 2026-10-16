// SPDX-License-Identifier: Apache-2.0
package webcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Inspect performs one HEAD request. It neither crawls nor follows redirects.
func Inspect(ctx context.Context, target, kind string) ([]Check, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("use an HTTPS URL without credentials, query parameters or fragments")
	}
	if u.Port() != "" && u.Port() != "443" {
		return nil, fmt.Errorf("only HTTPS port 443 is supported")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed")
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("DNS returned no addresses")
		}
		for _, ip := range addresses {
			if !publicIP(ip) {
				return nil, fmt.Errorf("private, local and reserved destinations are not supported")
			}
		}
		dialer := net.Dialer{Timeout: 5 * time.Second}
		// Connect to the validated address directly, preventing a second DNS lookup.
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "GodsEye/0.2 authorized-header-check")
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTPS request failed: %w", err)
	}
	defer response.Body.Close()
	return Evaluate(response, kind, time.Now()), nil
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/23", "2002::/16", "64:ff9b::/96"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

func Evaluate(response *http.Response, kind string, now time.Time) []Check {
	checks := []Check{{"HTTP response", "observed", fmt.Sprintf("HEAD returned HTTP %d. Redirects were not followed.", response.StatusCode)}}
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		expiry := response.TLS.PeerCertificates[0].NotAfter
		state := "pass"
		if expiry.Before(now.Add(30 * 24 * time.Hour)) {
			state = "review"
		}
		checks = append(checks, Check{"TLS certificate", state, "Certificate expires " + expiry.UTC().Format("2006-01-02") + ". Connection used normal certificate verification."})
	}
	for _, header := range []struct{ name, detail string }{{"Strict-Transport-Security", "Check that the policy has an appropriate max-age and domain scope."}, {"X-Content-Type-Options", "Expected nosniff to reduce MIME-type confusion."}} {
		value := response.Header.Get(header.name)
		state := "observed"
		detail := "Header is present. " + header.detail
		if value == "" {
			state = "review"
			detail = "Header is absent. " + header.detail
		}
		if header.name == "X-Content-Type-Options" && !strings.EqualFold(strings.TrimSpace(value), "nosniff") {
			state = "review"
		}
		if header.name == "X-Content-Type-Options" && strings.EqualFold(strings.TrimSpace(value), "nosniff") {
			state = "pass"
		}
		checks = append(checks, Check{header.name, state, detail})
	}
	if kind == "website" || kind == "application" {
		state := "observed"
		detail := "Content-Security-Policy is present; policy effectiveness has not been evaluated."
		if response.Header.Get("Content-Security-Policy") == "" {
			state = "review"
			detail = "Content-Security-Policy is absent on this response. Review whether this endpoint serves browser content."
		}
		checks = append(checks, Check{"Browser content policy", state, detail})
	}
	checks = append(checks, Check{"Coverage", "limited", "One unauthenticated HEAD response only. No crawling, injection tests, authenticated routes or application-logic verification."})
	return checks
}
