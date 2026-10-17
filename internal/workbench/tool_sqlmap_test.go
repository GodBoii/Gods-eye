// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSQLMapAuthorizedBaselineGET(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.Method != "GET" || req.URL.RawQuery != "token=privatevalue" {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL)
		}
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("sqlite3.OperationalError: syntax error")); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	request := ToolRequest{Target: server.URL + "/?token=privatevalue"}
	if _, err := auditSQLMap(context.Background(), request); err == nil {
		t.Fatal("unauthorized request accepted")
	}
	if requests != 0 {
		t.Fatal("unauthorized network request performed")
	}
	request.Authorized = true
	r, err := auditSQLMap(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || len(r.Findings) != 1 {
		t.Fatalf("expected single GET and disclosure: requests=%d report=%+v", requests, r)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "privatevalue") || strings.Contains(r.Gaps[0], "Offline") {
		t.Fatal("query secret retained or live coverage mislabeled")
	}
}

func sqlHARFixture(t *testing.T, urls, bodies []string) string {
	t.Helper()
	entries := make([]sqlEvidenceEntry, len(urls))
	for i := range urls {
		entries[i].Request.URL, entries[i].Request.Method = urls[i], "GET"
		entries[i].Response.Status = 200
		entries[i].Response.Content.Text = bodies[i]
	}
	data, err := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": entries}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSQLMapCapturedDatabaseEvidence(t *testing.T) {
	input := sqlHARFixture(t, []string{"https://example.test/items?id=1&token=secretvalue", "https://example.test/items?id=1%27&token=secretvalue"}, []string{"<h1>item</h1>", "You have an error in your SQL syntax; check the MySQL manual. SELECT private FROM customers WHERE token='secretvalue'"})
	r, err := auditSQLMap(context.Background(), ToolRequest{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("expected disclosure, query exposure and correlation: %+v", r.Findings)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secretvalue", "customers", "SELECT private", "id=", "token="} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("report leaks %q", secret)
		}
	}
	if len(r.Gaps) < 2 {
		t.Fatal("missing coverage limitations")
	}
}

func TestSQLMapErrorSignatures(t *testing.T) {
	for _, tt := range []struct{ name, body, want string }{
		{"mysql", "You have an error in your SQL syntax; MySQL", "MySQL/MariaDB"},
		{"postgres", `org.postgresql.util.PSQLException: ERROR: syntax error at or near "'"`, "PostgreSQL"},
		{"sqlite", `sqlite3.OperationalError: near "'": syntax error`, "SQLite"},
		{"mssql", "System.Data.SqlClient.SqlException: Incorrect syntax near 'x'", "Microsoft SQL Server"},
		{"oracle", "ORA-00933: SQL command not properly ended", "Oracle"},
		{"generic", "There was a SQL syntax error", ""},
		{"dbword", "We support MySQL and PostgreSQL", ""},
		{"sqlstate", "SQLSTATE[42000] access denied", ""},
		{"clean", "<p>No errors</p>", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := sqlErrorFamily([]byte(tt.body)); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSQLMapBase64AndMissingBodies(t *testing.T) {
	input := sqlHARFixture(t, []string{"https://example.test/a?id=1", "https://example.test/a?id=2"}, []string{"", "sqlite3.OperationalError: syntax error"})
	var data map[string]any
	if err := json.Unmarshal([]byte(input), &data); err != nil {
		t.Fatal(err)
	}
	entries := data["log"].(map[string]any)["entries"].([]any)
	content := entries[1].(map[string]any)["response"].(map[string]any)["content"].(map[string]any)
	content["text"] = base64.StdEncoding.EncodeToString([]byte(content["text"].(string)))
	content["encoding"] = "base64"
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	r, err := auditSQLMap(context.Background(), ToolRequest{Input: string(b)})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited || len(r.Findings) != 1 {
		t.Fatalf("missing bodies must limit assessment and cannot be clean baselines: %+v", r)
	}
}

func TestSQLMapMalformedAndEngine(t *testing.T) {
	valid := sqlHARFixture(t, []string{"https://example.test/a"}, []string{"ok"})
	for _, req := range []ToolRequest{
		{RunEngine: true, Input: valid}, {Input: "{"}, {Input: `{"log":{"version":"1.2","entries":[]}}`},
		{Input: valid + " {}"}, {Input: strings.Replace(valid, `https://example.test/a`, `file:///etc/passwd`, 1)},
		{Input: strings.Replace(valid, `https://example.test/a`, `https://example.test/a?id=%XX`, 1)},
		{Input: strings.Replace(valid, `"text":"ok","encoding":""`, `"text":"!","encoding":"base64"`, 1)},
		{Input: strings.Replace(valid, `"text":"ok","encoding":""`, `"text":"ok","encoding":"gzip"`, 1)},
	} {
		if _, err := auditSQLMap(context.Background(), req); err == nil {
			t.Fatalf("expected rejection: %+v", req)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditSQLMap(ctx, ToolRequest{Input: valid}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestSQLMapCorrelationRequiresSameEndpointAndOneQueryChange(t *testing.T) {
	for _, urls := range [][]string{
		{"https://other.test/a?id=1", "https://example.test/a?id=2"},
		{"https://example.test/b?id=1", "https://example.test/a?id=2"},
		{"https://example.test/a?id=1&x=1", "https://example.test/a?id=2&x=2"},
		{"https://example.test/a", "https://example.test/a?id=2"},
		{"https://example.test/a?id=2", "https://example.test/a?id=2"},
	} {
		r, err := auditSQLMap(context.Background(), ToolRequest{Input: sqlHARFixture(t, urls, []string{"ok", "ORA-00936: missing expression"})})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Findings) != 1 {
			t.Fatalf("unexpected correlation for %v: %+v", urls, r.Findings)
		}
	}
}
