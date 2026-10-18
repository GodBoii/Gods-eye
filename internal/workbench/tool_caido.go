// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

type caidoCapture struct {
	Log *struct {
		Version string `json:"version"`
		Entries []struct {
			Request struct {
				Method string `json:"method"`
				URL    string `json:"url"`
			} `json:"request"`
			Response struct {
				Status  int `json:"status"`
				Content struct {
					Text     *string `json:"text"`
					Encoding string  `json:"encoding"`
					MimeType string  `json:"mimeType"`
				} `json:"content"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

type caidoEvidence struct {
	status     int
	mime, hash string
	size       int
	hasBody    bool
}

// auditCaido compares supplied captures. It makes no requests and does not infer
// identities, role permissions or authorization bypass from response similarity.
func auditCaido(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine {
		return nil, fmt.Errorf("Caido engine execution is unsupported; supply two offline HAR captures")
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if err := checkInput(data); err != nil {
		return nil, err
	}
	fields, err := caidoEnvelope(data)
	if err != nil {
		return nil, err
	}
	var baseline, candidate caidoCapture
	if json.Unmarshal(fields["baseline"], &baseline) != nil || json.Unmarshal(fields["candidate"], &candidate) != nil {
		return nil, fmt.Errorf("baseline and candidate must be HAR 1.2 objects")
	}
	var expected []string
	if raw, ok := fields["expectDenied"]; ok {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &expected) != nil {
			return nil, fmt.Errorf("expectDenied must be an array of absolute paths")
		}
	}
	if len(expected) > maxRecords {
		return nil, fmt.Errorf("expectDenied exceeds 1,000 paths")
	}
	denied := make(map[string]bool, len(expected))
	for _, p := range expected {
		u, err := url.Parse(p)
		if err != nil || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || u.Host != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(p) > 512 || u.EscapedPath() != p {
			return nil, fmt.Errorf("expectDenied requires escaped absolute paths without query or fragment")
		}
		denied[p] = true
	}
	scope := ""
	if req.Target != "" {
		origin, p, err := caidoEndpoint(req.Target)
		parsed, parseErr := url.Parse(req.Target)
		if err != nil || parseErr != nil || p != "/" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
			return nil, fmt.Errorf("target scope must be an HTTP origin without path, query or fragment")
		}
		scope = origin
	}
	r := newReport("caido", "Offline HTTP capture comparison.", data)
	r.Limited = true
	r.gap("Offline capture evidence only; no Caido proxy, interception, replay, authenticated sessions or live verification. Role 1 and role 2 are capture ordinals, not verified identities.")
	r.gap("Status, MIME and body differences do not prove authorization bypass or IDOR. Login/error pages can return 2xx. Expected-denial paths are owner assertions requiring manual verification.")
	r.gap("Queries, headers, cookies and raw bodies are omitted. Query values and request bodies do not participate in matching; repeated method/path entries are ambiguous and excluded. Encoded paths remain distinct.")
	a, err := caidoIndex(ctx, baseline, scope, r, "role 1")
	if err != nil {
		return nil, err
	}
	b, err := caidoIndex(ctx, candidate, scope, r, "role 2")
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(a))
	for key := range a {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	matched, changed := 0, 0
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		x, y := a[key], b[key]
		if len(x) != 1 || len(y) != 1 {
			continue
		}
		matched++
		parts := strings.SplitN(key, " ", 2)
		u, _ := url.Parse(parts[1])
		bodyComparison := "unavailable"
		if x[0].hasBody && y[0].hasBody {
			bodyComparison = fmt.Sprintf("equal=%t; captured bytes=%d/%d", x[0].hash == y[0].hash, x[0].size, y[0].size)
		}
		mimeComparable := x[0].mime != "" && y[0].mime != ""
		statusDiff := x[0].status != y[0].status
		bodyDiff := x[0].hasBody && y[0].hasBody && x[0].hash != y[0].hash
		mimeDiff := mimeComparable && x[0].mime != y[0].mime
		if statusDiff || bodyDiff || mimeDiff {
			changed++
		}
		r.observe("capture comparison", parts[1], fmt.Sprintf("%s; role 1/role 2 statuses=%d/%d; MIME comparable=%t, changed=%t; body %s", parts[0], x[0].status, y[0].status, mimeComparable, mimeDiff, bodyComparison))
		if denied[u.EscapedPath()] && (x[0].status == 401 || x[0].status == 403) && y[0].status >= 200 && y[0].status < 300 {
			r.finding("info", "Expected-denial contract review candidate", parts[1], fmt.Sprintf("%s changed from role 1 HTTP %d to role 2 HTTP %d on an owner-declared expected-denial path. Review the original captures and verify the role contract, protected content and login-page behavior. This is not confirmed unauthorized access.", parts[0], x[0].status, y[0].status))
		}
	}
	r.observe("comparison coverage", "", fmt.Sprintf("Matched %d unambiguous same-origin method/path pairs; %d changed; baseline unmatched/ambiguous=%d; candidate unmatched/ambiguous=%d.", matched, changed, len(a)-matched, len(b)-matched))
	r.Summary = fmt.Sprintf("Compared %d captured endpoint pairs; %d differences and %d owner-contract review candidates; authorization remains unverified.", matched, changed, len(r.Findings))
	return r, nil
}

func caidoEnvelope(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("expected baseline/candidate comparison object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid comparison JSON")
		}
		key, ok := t.(string)
		if !ok || key != "baseline" && key != "candidate" && key != "expectDenied" {
			return nil, fmt.Errorf("unknown comparison field")
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate comparison field")
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return nil, fmt.Errorf("invalid comparison field")
		}
		fields[key] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, fmt.Errorf("invalid comparison object")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing comparison data")
	}
	if fields["baseline"] == nil || fields["candidate"] == nil {
		return nil, fmt.Errorf("baseline and candidate are required")
	}
	return fields, nil
}

func caidoEndpoint(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || u == nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("invalid HTTP endpoint")
	}
	host := strings.ToLower(u.Host)
	if u.Scheme == "https" && u.Port() == "443" || u.Scheme == "http" && u.Port() == "80" {
		host = strings.TrimSuffix(host, ":"+u.Port())
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if len(p) > 512 {
		return "", "", fmt.Errorf("captured path exceeds 512 bytes")
	}
	return u.Scheme + "://" + host, p, nil
}

func caidoIndex(ctx context.Context, c caidoCapture, scope string, r *Report, role string) (map[string][]caidoEvidence, error) {
	if c.Log == nil || c.Log.Version != "1.2" || len(c.Log.Entries) == 0 || len(c.Log.Entries) > maxRecords {
		return nil, fmt.Errorf("each HAR requires version 1.2 and 1 to 1,000 entries")
	}
	index := make(map[string][]caidoEvidence)
	skipped, missing := 0, 0
	for _, entry := range c.Log.Entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		origin, p, err := caidoEndpoint(entry.Request.URL)
		method := strings.ToUpper(entry.Request.Method)
		if err != nil || method == "" || len(method) > 32 || strings.Trim(method, "ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'*+-.^_`|~0123456789") != "" || entry.Response.Status < 100 || entry.Response.Status > 599 {
			return nil, fmt.Errorf("captured entry requires a valid HTTP URL, method and status")
		}
		if scope != "" && scope != origin {
			skipped++
			continue
		}
		content := entry.Response.Content
		if content.Encoding != "" && content.Encoding != "base64" {
			return nil, fmt.Errorf("unsupported captured body encoding")
		}
		if content.Encoding != "" && content.Text == nil {
			return nil, fmt.Errorf("captured body encoding requires content text")
		}
		e := caidoEvidence{status: entry.Response.Status, mime: strings.ToLower(strings.TrimSpace(strings.SplitN(content.MimeType, ";", 2)[0])), hasBody: content.Text != nil}
		if content.Text != nil {
			body := []byte(*content.Text)
			switch content.Encoding {
			case "":
			case "base64":
				if base64.StdEncoding.DecodedLen(len(body)) > auditBodyLimit+2 {
					return nil, fmt.Errorf("captured body exceeds 1 MiB")
				}
				body, err = base64.StdEncoding.DecodeString(*content.Text)
				if err != nil {
					return nil, fmt.Errorf("invalid captured base64 body")
				}
			default:
				return nil, fmt.Errorf("unsupported captured body encoding")
			}
			if len(body) > auditBodyLimit {
				return nil, fmt.Errorf("captured body exceeds 1 MiB")
			}
			e.hash, e.size = digest(body), len(body)
		} else {
			missing++
		}
		key := method + " " + origin + p
		index[key] = append(index[key], e)
	}
	r.observe("capture coverage", "", fmt.Sprintf("%s: %d entries; %d outside scope; %d bodies unavailable; %d distinct method/path endpoints.", role, len(c.Log.Entries), skipped, missing, len(index)))
	return index, nil
}
