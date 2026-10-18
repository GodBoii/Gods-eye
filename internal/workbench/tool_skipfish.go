// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"fmt"
	"html"
	"mime"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const skipfishPageLimit = 8

// This crawler issues GET requests only. URL filtering reduces accidental state
// changes, but cannot make an application with state-changing GET routes safe.
func auditSkipfish(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine {
		return nil, fmt.Errorf("Skipfish engine execution is not implemented; use the bounded native crawler")
	}
	if req.Input != "" {
		return nil, fmt.Errorf("native crawling requires a target URL, without report input")
	}
	root, err := validateAuditURL(req.Target)
	if err != nil {
		return nil, err
	}
	if !skipfishSafeURL(root) {
		return nil, fmt.Errorf("crawler target must have no query, credentials or potentially state-changing path")
	}
	if root.Path == "" {
		root.Path = "/"
	}
	r := newReport("skipfish", "Bounded native web crawl.", nil)
	r.gap("At most eight same-origin URLs and two link levels are fetched with GET. Redirects, query URLs, forms, authentication, JavaScript, APIs, backend/database access and exploit payloads are not exercised. GET path filtering is heuristic; no result establishes security.")
	r.gap("Conservative markup extraction is not a browser HTML parser; malformed HTML and dynamic links can be missed. Non-HTML responses are recorded without parsing their bodies.")
	type page struct {
		u     *url.URL
		depth int
	}
	queue := []page{{root, 0}}
	seen := map[string]bool{root.String(): true}
	fetched := 0
	for len(queue) > 0 {
		if ctx.Err() != nil {
			r.Limited = true
			r.gap("Crawl cancelled before all queued URLs were assessed.")
			break
		}
		item := queue[0]
		queue = queue[1:]
		response, fetchErr := fetchAuditURL(ctx, item.u.String())
		if fetchErr != nil {
			r.Limited = true
			r.observe("fetch failure", item.u.String(), "Response could not be assessed.")
			r.gap("One or more URLs could not be fetched; endpoint coverage is incomplete.")
			continue
		}
		fetched++
		r.observe("crawled endpoint", response.URL, fmt.Sprintf("GET status %d; depth %d", response.Status, item.depth))
		r.node("url", response.URL)
		if response.Status >= 400 {
			r.finding("info", "HTTP error response", response.URL, fmt.Sprintf("GET returned HTTP %d. Verify whether the response is expected; this alone is not a vulnerability.", response.Status))
		}
		if response.Status >= 300 && response.Status < 400 {
			r.gap("Redirect responses were recorded without following their Location headers.")
			continue
		}
		if response.Truncated {
			r.Limited = true
			r.gap("A response exceeded 1 MiB; only the retained prefix was examined.")
		}
		media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaErr != nil || (media != "text/html" && media != "application/xhtml+xml") {
			continue
		}
		skipfishHeaders(r, response)
		body := skipfishMarkup(string(response.Body))
		if regexp.MustCompile(`(?i)<base\b`).MatchString(body) {
			r.Limited = true
			r.gap("HTML with a base element was inspected but its links were not crawled because browser URL resolution may differ.")
			skipfishInsecureMarkup(r, item.u, body)
			continue
		}
		skipfishInsecureMarkup(r, item.u, body)
		for _, tag := range regexp.MustCompile(`(?is)<a\b(?:[^>"']|"[^"]*"|'[^']*')*>`).FindAllString(body, -1) {
			href := skipfishAttribute(tag, "href")
			candidate, parseErr := url.Parse(href)
			if parseErr != nil || href == "" || strings.HasPrefix(href, "//") || candidate.RawQuery != "" || candidate.ForceQuery || candidate.User != nil {
				continue
			}
			candidate = item.u.ResolveReference(candidate)
			candidate.Fragment, candidate.RawFragment = "", ""
			if !strings.EqualFold(candidate.Scheme, root.Scheme) || !strings.EqualFold(candidate.Host, root.Host) || !skipfishSafeURL(candidate) || seen[candidate.String()] {
				continue
			}
			if item.depth >= 2 || len(seen) >= skipfishPageLimit {
				r.Limited = true
				r.gap("The eight-URL or two-link-depth crawl limit omitted additional eligible links.")
				continue
			}
			seen[candidate.String()] = true
			queue = append(queue, page{candidate, item.depth + 1})
			r.edge(r.node("url", item.u.String()), r.node("url", candidate.String()), "links to")
		}
	}
	r.Summary = fmt.Sprintf("Native web crawl fetched %d URLs; %d configuration or response review findings.", fetched, len(r.Findings))
	return r, nil
}

func skipfishSafeURL(u *url.URL) bool {
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || len(u.String()) > 4096 {
		return false
	}
	decoded := strings.ToLower(u.Path)
	// Decode nested escapes too so encoded path segments cannot bypass the filter.
	for i := 0; i < 4; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return false
		}
		if next == decoded {
			break
		}
		decoded = next
	}
	if strings.Contains(decoded, "%") || strings.ContainsAny(decoded, "\\;\x00\r\n") {
		return false
	}
	for _, word := range []string{"logout", "log-out", "signout", "sign-out", "delete", "remove", "destroy", "revoke", "reset", "unsubscribe", "checkout", "purchase", "payment", "transfer", "execute", "shutdown", "token", "secret", "password", "credential", "session", "apikey", "api-key", "confirm", "activate", "disable", "enable", "update", "create", "submit", "admin"} {
		if strings.Contains(decoded, word) {
			return false
		}
	}
	switch strings.ToLower(path.Ext(decoded)) {
	case "", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp":
		return true
	default:
		return false
	}
}

func skipfishMarkup(body string) string {
	body = regexp.MustCompile(`(?s)<!--.*?(?:-->|$)`).ReplaceAllString(body, "")
	return regexp.MustCompile(`(?is)<(?:script|style|textarea)\b[^>]*>.*?(?:</(?:script|style|textarea)\s*>|$)`).ReplaceAllStringFunc(body, func(block string) string {
		// Preserve opening script tags for mixed-content review, never their body.
		if end := strings.IndexByte(block, '>'); end >= 0 {
			return block[:end+1]
		}
		return ""
	})
}

func skipfishAttribute(tag, name string) string {
	start := strings.IndexAny(tag, " \t\r\n")
	if start < 0 {
		return ""
	}
	pattern := `(?is)([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?`
	for _, match := range regexp.MustCompile(pattern).FindAllStringSubmatch(tag[start:], -1) {
		if !strings.EqualFold(match[1], name) {
			continue
		}
		for _, value := range match[2:] {
			if value != "" {
				return strings.TrimSpace(html.UnescapeString(value))
			}
		}
		return ""
	}
	return ""
}

func skipfishHeaders(r *Report, response *AuditResponse) {
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"} {
		if response.Header.Get(header) == "" {
			r.finding("low", "Missing "+header+" header", response.URL, "HTML response lacks this defense-in-depth header. Review application requirements; absence alone does not prove exploitability.")
		}
	}
	if strings.HasPrefix(response.URL, "https://") && response.Header.Get("Strict-Transport-Security") == "" {
		r.finding("low", "Missing Strict-Transport-Security header", response.URL, "HTTPS HTML response lacks HSTS; review deployment before enabling it.")
	}
}

func skipfishInsecureMarkup(r *Report, base *url.URL, body string) {
	if base.Scheme != "https" {
		return
	}
	for _, tag := range regexp.MustCompile(`(?is)<(?:form|script|img|iframe|link|video|audio|source)\b(?:[^>"']|"[^"]*"|'[^']*')*>`).FindAllString(body, -1) {
		form := regexp.MustCompile(`(?i)^<form\b`).MatchString(tag)
		attribute := "src"
		if form {
			attribute = "action"
		} else if regexp.MustCompile(`(?i)^<link\b`).MatchString(tag) {
			attribute = "href"
		}
		raw := skipfishAttribute(tag, attribute)
		u, err := url.Parse(raw)
		if err != nil || raw == "" {
			continue
		}
		u = base.ResolveReference(u)
		if u.Scheme != "http" {
			continue
		}
		title := "HTTP resource referenced by HTTPS page"
		if form {
			title = "Form action uses HTTP"
		}
		r.finding("low", title, base.String(), "HTML references an unencrypted "+attribute+" URL. The URL was not fetched, and browser execution or submission was not tested.")
	}
}
