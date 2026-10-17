// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const auditBodyLimit = 1 << 20

// AuditResponse contains bounded response evidence, not a browser session.
type AuditResponse struct {
	URL       string
	Status    int
	Header    http.Header
	Body      []byte
	Truncated bool
}

func validateAuditURL(target string) (*url.URL, error) {
	if len(target) > 4096 {
		return nil, fmt.Errorf("target URL exceeds 4096 bytes")
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(target, "\r\n\x00") {
		return nil, fmt.Errorf("provide an HTTP or HTTPS URL without user credentials or a fragment")
	}
	if !validHost(u.Hostname()) {
		return nil, fmt.Errorf("invalid target hostname")
	}
	return u, nil
}

// fetchAuditURL never follows a redirect or performs a second DNS lookup while
// dialing. Private/loopback fixtures are permitted; metadata addresses are not.
func fetchAuditURL(ctx context.Context, target string) (*AuditResponse, error) {
	u, err := validateAuditURL(target)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	transport := &http.Transport{
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    4 * time.Second,
		ResponseHeaderTimeout:  4 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 {
			return nil, fmt.Errorf("target DNS resolution failed")
		}
		for _, ip := range addresses {
			if !diagnosticAddress(ip) {
				return nil, fmt.Errorf("target resolves to an unsupported special-purpose address")
			}
		}
		var lastErr error
		for i, ip := range addresses {
			if i >= 4 {
				break
			}
			connection, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not construct assessment request")
	}
	request.Header.Set("User-Agent", "GodsEye/0.4 authorized-assessment")
	response, err := client.Do(request)
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			return nil, fmt.Errorf("target request failed: %w", urlError.Err)
		}
		return nil, fmt.Errorf("target request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, auditBodyLimit+1))
	if err != nil {
		return nil, fmt.Errorf("could not read target response")
	}
	truncated := len(body) > auditBodyLimit
	if truncated {
		body = body[:auditBodyLimit]
	}
	return &AuditResponse{URL: Target(u.String()), Status: response.StatusCode, Header: response.Header.Clone(), Body: body, Truncated: truncated}, nil
}
