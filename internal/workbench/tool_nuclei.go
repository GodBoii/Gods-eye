// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// auditNuclei executes a small, explicit native ruleset. It does not execute
// Nuclei templates or treat imported assertions as independently verified.
func auditNuclei(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine {
		return nil, fmt.Errorf("Nuclei engine execution is not implemented; use native checks or import a Nuclei report")
	}
	if req.Input != "" {
		if req.Target != "" {
			return nil, fmt.Errorf("choose a target for native checks or input for report import")
		}
		data, err := toolInput(req)
		if err != nil {
			return nil, err
		}
		return Import("nuclei", data)
	}
	response, err := fetchAuditURL(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	r := newReport("nuclei", "Native HTTP exposure rules executed against one explicitly requested URL.", response.Body)
	r.observe("HTTP status", response.URL, fmt.Sprint(response.Status))
	r.observe("rule set", response.URL, "directory listing; embedded-source v3 source map; debug traceback; cookie transport attributes")
	nucleiExposureRules(r, response)
	nucleiCookieRules(r, response)
	if response.Truncated {
		r.Limited = true
		r.gap("Response body exceeded the fetch limit; body rules examined only the retained prefix.")
	}
	r.gap("Only four native rule families run on one response. No Nuclei engine, templates, crawling, authenticated flows, exploit execution or backend/database audit. A clean result does not establish security.")
	r.Summary = fmt.Sprintf("Native HTTP rules completed: %d configuration or exposure findings at one URL.", len(r.Findings))
	return r, nil
}

func nucleiExposureRules(r *Report, response *AuditResponse) {
	body := string(response.Body)
	// Restrict HTML signatures to declared HTML and remove comments so examples
	// hidden in comments do not become findings.
	if strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/html") {
		body = regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(body, "")
		listingTitle := regexp.MustCompile(`(?is)<title>\s*(?:Index of|Directory listing for)\s+[^<]+</title>`)
		parentLink := regexp.MustCompile(`(?is)<a\s+[^>]*href\s*=\s*["'](?:\.\./|\?C=[NMSD];O=[AD])["'][^>]*>`)
		if response.Status >= 200 && response.Status < 300 && listingTitle.MatchString(body) && parentLink.MatchString(body) {
			r.finding("medium", "Directory listing exposed", response.URL, "Successful HTML response contains an autoindex title and parent/sort navigation links. Review whether the listed directory should be public; no linked files were fetched.")
		}
		python := strings.Contains(body, "Traceback (most recent call last)") && regexp.MustCompile(`File (?:&quot;|\")[^\n<]+(?:&quot;|\"), line [0-9]+`).MatchString(body)
		php := strings.Contains(body, "Fatal error:") && strings.Contains(body, "Stack trace:") && regexp.MustCompile(`(?i)\bon line\s+[0-9]+`).MatchString(body)
		django := strings.Contains(body, "You're seeing this error because you have <code>DEBUG = True</code>") && strings.Contains(body, "Traceback")
		if python || php || django {
			r.finding("medium", "Application debug traceback exposed", response.URL, "Response contains matching traceback and implementation-location/debug-mode signatures. Verify that this is a live error page rather than documentation. Stack contents are omitted to avoid retaining secrets.")
		}
	}
	u, err := url.Parse(response.URL)
	if err != nil || response.Status < 200 || response.Status >= 300 || !strings.HasSuffix(strings.ToLower(u.Path), ".map") || response.Truncated {
		return
	}
	var sourceMap struct {
		Version        int       `json:"version"`
		Sources        []string  `json:"sources"`
		Mappings       *string   `json:"mappings"`
		SourcesContent []*string `json:"sourcesContent"`
	}
	if json.Unmarshal(response.Body, &sourceMap) != nil || sourceMap.Version != 3 || sourceMap.Mappings == nil || len(sourceMap.Sources) == 0 || len(sourceMap.Sources) != len(sourceMap.SourcesContent) {
		return
	}
	for _, source := range sourceMap.SourcesContent {
		if source != nil && strings.TrimSpace(*source) != "" {
			r.finding("low", "Source map exposes embedded source", response.URL, "Successful response is a version 3 source map with embedded nonempty sourcesContent. Public source maps may be intentional; review for proprietary code or secrets. Source contents are not retained as findings.")
			return
		}
	}
}

func nucleiCookieRules(r *Report, response *AuditResponse) {
	u, err := url.Parse(response.URL)
	if err != nil {
		return
	}
	// net/http parses separate Set-Cookie fields, quoted values, expiry dates,
	// and attribute case. Never retain cookie names or values in evidence.
	cookies := (&http.Response{Header: response.Header}).Cookies()
	for _, cookie := range cookies {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			continue
		}
		if u.Scheme == "https" && !cookie.Secure {
			r.finding("low", "Cookie lacks Secure attribute", response.URL, "An HTTPS response sets a nonempty cookie without Secure. Its value can travel over HTTP if an applicable HTTP URL is visited. Cookie purpose and exploitability require review; values are omitted.")
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			r.finding("low", "SameSite=None cookie lacks Secure", response.URL, "A nonempty cookie uses SameSite=None without Secure; modern browsers reject this combination. Review cross-site login and embedded application behavior. Values are omitted.")
		}
		if strings.HasPrefix(cookie.Name, "__Host-") && (!cookie.Secure || cookie.Path != "/" || cookie.Domain != "") || strings.HasPrefix(cookie.Name, "__Secure-") && !cookie.Secure {
			r.finding("low", "Cookie prefix requirements violated", response.URL, "A __Host- or __Secure- cookie violates its required Secure, Path, or Domain attributes. Browsers may reject this cookie; verify the authentication flow. Values are omitted.")
		}
	}
}
