// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// auditEvilginx3 checks defensive session configuration. It never runs a
// phishing proxy, collects credentials, or submits an authentication request.
func auditEvilginx3(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine {
		return nil, fmt.Errorf("Evilginx engine execution is excluded; use defensive session configuration review")
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	r := newReport("evilginx3", "Defensive session configuration review.", nil)
	r.Limited = true
	r.gap("Headers cannot establish phishing-resistant MFA. Authentication design, WebAuthn relying-party binding, session rotation, logout invalidation and role controls require explicit authenticated access and design review.")
	r.gap("One baseline GET or captured HAR responses only. No forms are submitted, credentials retained, interception, MFA bypass, crawling or exploit execution. Session cookie classification is heuristic; cookie purpose requires confirmation.")
	if len(data) == 0 {
		if !req.Authorized {
			return nil, fmt.Errorf("confirm authorization before requesting the target")
		}
		response, err := fetchAuditURL(ctx, req.Target)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		evilginxReview(r, response)
	} else {
		if req.Target != "" {
			return nil, fmt.Errorf("choose a target URL or HAR input, not both")
		}
		var capture struct {
			Log *struct {
				Entries *[]struct {
					Request struct {
						URL string `json:"url"`
					} `json:"request"`
					Response struct {
						Status  int `json:"status"`
						Headers *[]struct {
							Name  string `json:"name"`
							Value string `json:"value"`
						} `json:"headers"`
						Content struct {
							Text     string `json:"text"`
							Encoding string `json:"encoding"`
							MimeType string `json:"mimeType"`
						} `json:"content"`
					} `json:"response"`
				} `json:"entries"`
			} `json:"log"`
		}
		if json.Unmarshal(data, &capture) != nil || capture.Log == nil || capture.Log.Entries == nil || len(*capture.Log.Entries) == 0 {
			return nil, fmt.Errorf("provide a HAR log with nonempty entries")
		}
		entries := *capture.Log.Entries
		if len(entries) > maxRecords {
			return nil, fmt.Errorf("HAR exceeds the 1,000-response limit")
		}
		for _, e := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if _, err := validateAuditURL(e.Request.URL); err != nil || e.Response.Headers == nil || e.Response.Status < 100 || e.Response.Status > 599 {
				return nil, fmt.Errorf("HAR entry requires a valid HTTP URL, response status and headers")
			}
			h := http.Header{}
			for _, v := range *e.Response.Headers {
				if strings.ContainsAny(v.Name+v.Value, "\r\n\x00") {
					return nil, fmt.Errorf("invalid HAR response header")
				}
				h.Add(v.Name, v.Value)
			}
			body := []byte(e.Response.Content.Text)
			switch e.Response.Content.Encoding {
			case "":
			case "base64":
				body, err = base64.StdEncoding.DecodeString(e.Response.Content.Text)
				if err != nil {
					return nil, fmt.Errorf("invalid HAR content encoding")
				}
			default:
				return nil, fmt.Errorf("unsupported HAR content encoding")
			}
			if len(body) > auditBodyLimit {
				return nil, fmt.Errorf("HAR response body exceeds 1 MiB")
			}
			if h.Get("Content-Type") == "" {
				h.Set("Content-Type", e.Response.Content.MimeType)
			}
			evilginxReview(r, &AuditResponse{URL: e.Request.URL, Status: e.Response.Status, Header: h, Body: body})
		}
	}
	r.Summary = fmt.Sprintf("Defensive session review completed: %d configuration findings; authentication design remains unverified.", len(r.Findings))
	return r, nil
}

func evilginxReview(r *Report, response *AuditResponse) {
	u, _ := url.Parse(response.URL)
	// Retain only the origin, even if captured URLs contain account identifiers.
	target := u.Scheme + "://" + u.Host
	r.observe("response reviewed", target, fmt.Sprintf("HTTP %d; cookie names, values and body contents omitted", response.Status))
	h := response.Header
	session := false
	for _, cookie := range (&http.Response{Header: h}).Cookies() {
		if cookie.Value == "" || cookie.MaxAge < 0 || !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
			continue
		}
		name := strings.ToLower(cookie.Name)
		candidate := strings.HasPrefix(cookie.Name, "__Host-") || strings.Contains(name, "session") || name == "sid" || name == "jsessionid" || name == "phpsessid" || name == "asp.net_sessionid"
		if strings.HasPrefix(cookie.Name, "__Secure-") && !cookie.Secure {
			r.finding("low", "Cookie prefix requirements violated", target, "A cookie using the Secure prefix lacks the Secure attribute. Browsers may reject the cookie; its purpose is unverified.")
		}
		if !candidate {
			continue
		}
		session = true
		r.observe("session cookie candidate", target, "Name/prefix heuristic matched; actual authentication purpose unverified. No cookie identifiers or values retained.")
		if !cookie.Secure {
			r.finding("medium", "Session-like cookie lacks Secure", target, "A nonempty session-like cookie lacks Secure. Confirm its purpose and prevent transmission over plaintext HTTP.")
		}
		if !cookie.HttpOnly {
			r.finding("low", "Session-like cookie lacks HttpOnly", target, "A session-like cookie permits script access. Confirm whether script access is necessary; this does not establish an XSS vulnerability.")
		}
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 {
			r.finding("low", "Session-like cookie has no explicit SameSite policy", target, "Browser defaults vary by client and context. Review the intended cross-site authentication flow and explicit SameSite policy.")
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			r.finding("low", "SameSite=None cookie lacks Secure", target, "Modern browsers reject this combination; verify session creation and cross-site authentication behavior.")
		}
		if strings.HasPrefix(cookie.Name, "__Host-") && (!cookie.Secure || cookie.Path != "/" || cookie.Domain != "") || strings.HasPrefix(cookie.Name, "__Secure-") && !cookie.Secure {
			r.finding("low", "Cookie prefix requirements violated", target, "Cookie prefix requirements for Secure, Path or Domain are violated. Browsers may reject the cookie.")
		}
	}
	if session {
		if !evilginxDirective(h.Get("Cache-Control"), "no-store") {
			r.finding("low", "Session-setting response lacks no-store", target, "A response setting a session-like cookie lacks Cache-Control: no-store. Review whether personalized or authentication content is cacheable; a cookie alone does not prove sensitive body content.")
		}
		if u.Scheme != "https" {
			r.finding("medium", "Session-like cookie set over HTTP", target, "The reviewed response used plaintext HTTP. Secure cookie flags alone cannot protect a plaintext authentication exchange.")
		}
	}
	if u.Scheme == "https" {
		age, ok := evilginxHSTSAge(h.Values("Strict-Transport-Security"))
		if !ok || age <= 0 {
			r.finding("low", "HSTS is absent, invalid or disabled", target, "No effective positive HSTS max-age was observed on this HTTPS response. This check does not inspect browser preload state.")
		} else {
			r.observe("HSTS", target, fmt.Sprintf("Observed max-age=%d seconds; preload and subdomain coverage unverified", age))
		}
	}
	if strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/html") {
		if !evilginxFrameProtection(h) {
			r.finding("low", "HTML response lacks recognized framing restriction", target, "No recognized restrictive CSP frame-ancestors or X-Frame-Options policy was observed. Review framing requirements and clickjacking exposure.")
		}
		evilginxForms(r, target, u, string(response.Body))
	}
	if response.Truncated {
		r.gap("Response body was truncated at 1 MiB; later login forms may be missed.")
	}
	r.gap("Conservative static HTML form extraction does not execute scripts or implement browser HTML parsing; dynamic or malformed login forms can be missed.")
}

func evilginxDirective(value, directive string) bool {
	for _, v := range strings.Split(strings.ToLower(value), ",") {
		if strings.TrimSpace(v) == directive {
			return true
		}
	}
	return false
}

func evilginxHSTSAge(values []string) (int64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	// Browsers process the first HSTS field. Reject ambiguous duplicate max-age.
	age := int64(0)
	found := false
	for _, part := range strings.Split(values[0], ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if strings.EqualFold(kv[0], "max-age") {
			if found || len(kv) != 2 {
				return 0, false
			}
			v := strings.Trim(kv[1], "\"")
			if v == "" || strings.Trim(v, "0123456789") != "" {
				return 0, false
			}
			var err error
			age, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				return 0, false
			}
			found = true
		}
	}
	return age, found
}

func evilginxFrameProtection(h http.Header) bool {
	for _, policy := range h.Values("Content-Security-Policy") {
		for _, directive := range strings.Split(policy, ";") {
			parts := strings.Fields(strings.ToLower(directive))
			if len(parts) >= 2 && parts[0] == "frame-ancestors" {
				if len(parts) == 2 && parts[1] == "'none'" {
					return true
				}
				if len(parts) == 2 && parts[1] == "'self'" {
					return true
				}
			}
		}
	}
	value := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
	return value == "DENY" || value == "SAMEORIGIN"
}

var evilginxFormRE = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form\s*>`)
var evilginxInputRE = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
var evilginxAttributeRE = regexp.MustCompile(`(?is)([a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)

func evilginxAttribute(attributes, key string) string {
	for _, m := range evilginxAttributeRE.FindAllStringSubmatch(attributes, -1) {
		if strings.EqualFold(m[1], key) {
			return html.UnescapeString(m[2] + m[3] + m[4])
		}
	}
	return ""
}

func evilginxForms(r *Report, target string, base *url.URL, body string) {
	body = regexp.MustCompile(`(?is)<!--.*?-->|<script\b[^>]*>.*?</script\s*>`).ReplaceAllString(body, "")
	for _, form := range evilginxFormRE.FindAllStringSubmatch(body, -1) {
		password := false
		for _, input := range evilginxInputRE.FindAllStringSubmatch(form[2], -1) {
			if strings.EqualFold(evilginxAttribute(input[1], "type"), "password") {
				password = true
			}
		}
		if !password {
			continue
		}
		action, err := url.Parse(evilginxAttribute(form[1], "action"))
		if err != nil {
			r.gap("A password form action could not be parsed.")
			continue
		}
		resolved := base.ResolveReference(action)
		if base.Scheme == "http" || resolved.Scheme == "http" {
			r.finding("medium", "Password form uses insecure transport", target, "Static markup contains a password input on an HTTP page or a form action resolving to HTTP. No credentials or form actions were retained, and no form was submitted.")
		}
		if strings.EqualFold(evilginxAttribute(form[1], "method"), "get") || evilginxAttribute(form[1], "method") == "" {
			r.finding("medium", "Password form uses GET submission", target, "Static markup uses GET or the default GET method for a password form. Credentials may enter URL history and logs if the form submits normally; JavaScript behavior is unverified.")
		}
	}
}
