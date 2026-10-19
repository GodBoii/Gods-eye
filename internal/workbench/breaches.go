// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const breachSource = "https://xposedornot.com/api_doc"

var breachEmailPattern = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}$")

// BreachChecker queries only the fixed public provider. The submitted address
// and the raw provider response are never included in persisted reports.
type BreachChecker struct {
	client *http.Client
	mu     sync.Mutex
	next   time.Time
}

func NewBreachChecker() *BreachChecker {
	return &BreachChecker{client: &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    4 * time.Second,
			ResponseHeaderTimeout:  4 * time.Second,
			MaxResponseHeaderBytes: 32 << 10,
			DisableKeepAlives:      true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *BreachChecker) Check(ctx context.Context, email string) (*Report, error) {
	email = strings.TrimSpace(email)
	parts := strings.Split(email, "@")
	if len(email) > 254 || len(parts) != 2 || len(parts[0]) > 64 || strings.HasPrefix(parts[0], ".") || strings.HasSuffix(parts[0], ".") || strings.Contains(parts[0], "..") || !breachEmailPattern.MatchString(email) {
		return nil, fmt.Errorf("provide a valid email address up to 254 characters")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Reserve a slot without holding the mutex across network I/O. No queue,
	// retries or per-address cache accumulate personal identifiers in memory.
	c.mu.Lock()
	if time.Now().Before(c.next) {
		c.mu.Unlock()
		return nil, fmt.Errorf("breach lookup is cooling down; wait at least one second, or retry later after a provider limit")
	}
	c.next = time.Now().Add(time.Second)
	c.mu.Unlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.xposedornot.com/v1/check-email/"+url.PathEscape(email), nil)
	if err != nil {
		return nil, fmt.Errorf("could not construct breach lookup")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "GodsEye/0.4 exposure-review")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("XposedOrNot lookup failed or timed out; no exposure conclusion is available")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests {
		c.mu.Lock()
		c.next = time.Now().Add(time.Minute)
		c.mu.Unlock()
		return nil, fmt.Errorf("XposedOrNot rate limit reached; retry after the provider window resets. Free limits include hourly and daily caps")
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotFound {
		return nil, fmt.Errorf("XposedOrNot returned HTTP %d; no exposure conclusion is available", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	if err != nil || len(body) > 256<<10 {
		return nil, fmt.Errorf("could not read a bounded XposedOrNot response")
	}
	var result struct {
		Breaches [][]string `json:"breaches"`
		Error    string     `json:"Error"`
		Status   string     `json:"status"`
	}
	if json.Unmarshal(body, &result) != nil {
		return nil, fmt.Errorf("XposedOrNot returned invalid JSON; no exposure conclusion is available")
	}
	notFound := result.Error == "Not found" && len(result.Breaches) == 0
	if !notFound && (response.StatusCode != http.StatusOK || result.Error != "" || result.Status != "success" || result.Breaches == nil) {
		return nil, fmt.Errorf("XposedOrNot returned an unrecognized response; no exposure conclusion is available")
	}
	report := newReport("email-breaches", "No indexed breach returned by XposedOrNot. This does not establish that the address has never been exposed.", nil)
	report.observe("source", "XposedOrNot", breachSource)
	report.observe("checked at", "XposedOrNot", report.CreatedAt.Format(time.RFC3339))
	seen := make(map[string]bool)
	for _, group := range result.Breaches {
		for _, name := range group {
			if strings.TrimSpace(name) == "" || len(name) > 512 {
				return nil, fmt.Errorf("XposedOrNot returned an invalid breach name; no exposure conclusion is available")
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			if len(seen) > maxRecords {
				return nil, fmt.Errorf("XposedOrNot response exceeds the breach record limit")
			}
			report.finding("medium", "Reported breach: "+name, "queried email", "XposedOrNot associates the submitted address with this breach. Confirm the source and incident details. No passwords or leaked records were retrieved.")
		}
	}
	if len(seen) > 0 {
		report.Summary = fmt.Sprintf("XposedOrNot returned %d indexed breaches for the submitted email address.", len(seen))
		report.observe("next steps", "account security", "Review affected services, replace reused passwords and enable multi-factor authentication. A historical breach does not prove current account access.")
	}
	report.observe("lookup result", "XposedOrNot", fmt.Sprintf("%d indexed breaches returned", len(seen)))
	report.gap("Coverage is limited to XposedOrNot's public email index. Missing, withheld and newer breaches may not appear. Phone numbers, names and usernames were not checked against breach databases.")
	report.gap("The submitted email was sent to XposedOrNot over HTTPS. It is omitted from this saved report; export the investigation to retain its input association.")
	return report, nil
}
