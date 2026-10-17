// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type sqlEvidenceEntry struct {
	Request struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"request"`
	Response struct {
		Status  int `json:"status"`
		Content struct {
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

// auditSQLMap reviews captured evidence; it does not run SQLMap or manufacture
// injection requests. A database error proves disclosure, not exploitability.
func auditSQLMap(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine {
		return nil, fmt.Errorf("SQLMap engine execution is not supported; provide a HAR capture for database error analysis")
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 && req.Target != "" {
		if !req.Authorized {
			return nil, fmt.Errorf("confirm authorization before requesting the target")
		}
		response, err := fetchAuditURL(ctx, req.Target)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("database disclosure assessment request failed; check the target and connectivity")
		}
		var entry sqlEvidenceEntry
		entry.Request.URL, entry.Request.Method = response.URL, "GET"
		entry.Response.Status = response.Status
		entry.Response.Content.Text = base64.StdEncoding.EncodeToString(response.Body)
		entry.Response.Content.Encoding = "base64"
		capture, err := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": []sqlEvidenceEntry{entry}}})
		if err != nil {
			return nil, fmt.Errorf("could not encode response evidence")
		}
		r, err := auditSQLMap(ctx, ToolRequest{Input: string(capture)})
		if err != nil {
			return nil, err
		}
		r.InputSHA256 = ""
		r.Summary = "Database error disclosure review of one authorized baseline GET; SQL injection is not confirmed."
		r.Gaps[0] = "One baseline GET only; no SQLMap engine, injection probes, exploitation, database access, schema review or permission testing was performed. Redirects are not followed."
		if response.Truncated {
			r.Limited = true
			r.gap("Response exceeded the body limit; omitted bytes were not assessed.")
		}
		return r, nil
	}
	if err := checkInput(data); err != nil {
		return nil, fmt.Errorf("provide a HAR capture with response content: %w", err)
	}
	var doc struct {
		Log *struct {
			Version string             `json:"version"`
			Entries []sqlEvidenceEntry `json:"entries"`
		} `json:"log"`
	}
	if err := decodeJSON(data, &doc); err != nil {
		return nil, err
	}
	if doc.Log == nil || doc.Log.Version == "" || len(doc.Log.Entries) == 0 {
		return nil, fmt.Errorf("expected HAR log.version and nonempty log.entries")
	}
	r := newReport("sqlmap", "Database error disclosure review of captured HTTP exchanges; SQL injection is not confirmed.", data)
	r.gap("Offline evidence only: no SQLMap engine, active injection, exploitation, database access, schema review or permission testing was performed.")
	r.gap("Signatures cover selected MySQL, PostgreSQL, SQLite, Microsoft SQL Server and Oracle errors; a clean result does not rule out injection. Captures may be stale or fabricated.")
	entries := doc.Log.Entries
	if len(entries) > maxRecords {
		entries = entries[:maxRecords]
		r.limit()
	}
	type reviewed struct {
		parsed  *url.URL
		method  string
		family  string
		status  int
		hasBody bool
	}
	reviews := make([]reviewed, 0, len(entries))
	missing := 0
	for i, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		u, err := url.Parse(entry.Request.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || entry.Request.Method == "" || entry.Response.Status < 100 || entry.Response.Status > 599 {
			return nil, fmt.Errorf("HAR entry %d has an invalid HTTP URL, method or status", i+1)
		}
		if _, err := url.ParseQuery(u.RawQuery); err != nil {
			return nil, fmt.Errorf("HAR entry %d has malformed query encoding", i+1)
		}
		body := []byte(entry.Response.Content.Text)
		switch entry.Response.Content.Encoding {
		case "":
		case "base64":
			body, err = base64.StdEncoding.DecodeString(entry.Response.Content.Text)
			if err != nil {
				return nil, fmt.Errorf("HAR entry %d has invalid base64 response content", i+1)
			}
		default:
			return nil, fmt.Errorf("HAR entry %d has unsupported response content encoding", i+1)
		}
		if len(body) == 0 {
			missing++
		}
		family := sqlErrorFamily(body)
		reviews = append(reviews, reviewed{u, entry.Request.Method, family, entry.Response.Status, len(body) > 0})
		if family != "" {
			r.finding("medium", "Database error details disclosed", entry.Request.URL, family+" error signature observed in captured response content. Confidence: medium; verify against the live application. Raw bodies and query values are omitted.")
			if sqlQueryDisclosure.Match(body) {
				r.finding("medium", "SQL statement details exposed with database error", entry.Request.URL, "A SQL statement pattern accompanies a database error signature. Confidence: medium; inspect the original capture privately and replace detailed errors with generic responses.")
			}
		}
	}
	for _, failed := range reviews {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if failed.family == "" || failed.method != "GET" {
			continue
		}
		for _, clean := range reviews {
			if !clean.hasBody || clean.family != "" || clean.status < 200 || clean.status >= 300 || clean.method != failed.method || !sameSQLEndpoint(clean.parsed, failed.parsed) {
				continue
			}
			if singleSQLQueryChange(clean.parsed.Query(), failed.parsed.Query()) {
				r.finding("medium", "Possible input-dependent database error", failed.parsed.String(), "A captured successful GET and a database-error GET to the same endpoint differ in one query parameter. Confidence: low; timestamps, sessions and server state may differ. This correlation does not confirm SQL injection; reproduce under controlled conditions.")
				break
			}
		}
	}
	if missing > 0 {
		r.Limited = true
		r.gap(fmt.Sprintf("%d captured responses have no body; database errors in those responses cannot be assessed.", missing))
	}
	r.observe("database-evidence", "", fmt.Sprintf("Reviewed %d captured HTTP exchanges; no query values, headers or response bodies retained.", len(reviews)))
	return r, nil
}

var sqlQueryDisclosure = regexp.MustCompile(`(?is)\b(?:select\s+.{1,120}?\s+from|insert\s+into|update\s+\S+\s+set|delete\s+from)\b`)

func sqlErrorFamily(body []byte) string {
	b := strings.ToLower(string(bytes.TrimSpace(body)))
	switch {
	case strings.Contains(b, "you have an error in your sql syntax") && (strings.Contains(b, "mysql") || strings.Contains(b, "mariadb")):
		return "MySQL/MariaDB"
	case strings.Contains(b, "syntax error at or near") && (strings.Contains(b, "postgresql") || strings.Contains(b, "pg_query()")):
		return "PostgreSQL"
	case (strings.Contains(b, "sqlite3.operationalerror") || strings.Contains(b, "sqliteexception")) && (strings.Contains(b, "syntax error") || strings.Contains(b, "no such column")):
		return "SQLite"
	case (strings.Contains(b, "sqlclient.sqlexception") || strings.Contains(b, "microsoft ole db provider for sql server")) && (strings.Contains(b, "incorrect syntax near") || strings.Contains(b, "unclosed quotation mark")):
		return "Microsoft SQL Server"
	case strings.Contains(b, "ora-00933") && strings.Contains(b, "sql command not properly ended"), strings.Contains(b, "ora-00936") && strings.Contains(b, "missing expression"):
		return "Oracle"
	default:
		return ""
	}
}

func sameSQLEndpoint(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && a.Host == b.Host && a.EscapedPath() == b.EscapedPath()
}

func singleSQLQueryChange(a, b url.Values) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	changes := 0
	for key, av := range a {
		bv, ok := b[key]
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				changes++
			}
		}
	}
	return changes == 1
}
