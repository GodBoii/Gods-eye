// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSensitiveResponseRulesAndFalsePositives(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	token := "ghp_" + strings.Repeat("A", 36)
	for _, tc := range []struct {
		name, path, media, body, title string
		status                         int
	}{
		{"environment", "/.env.production", "text/plain", "APP_ENV=production\nDB_PASSWORD=fixture-password-12345", "Environment configuration with sensitive assignments exposed", 200},
		{"environment placeholder", "/.env", "text/plain", "APP_ENV=example\nDB_PASSWORD=your_password_here", "", 200},
		{"environment interpolation", "/.env", "text/plain", "APP_ENV=dev\nDB_PASSWORD=${DATABASE_PASSWORD}", "", 200},
		{"environment unrelated endpoint", "/guide.txt", "text/plain", "APP_ENV=prod\nDB_PASSWORD=fixture-password-12345", "", 200},
		{"environment HTML fallback", "/.env", "text/html", "APP_ENV=prod\nDB_PASSWORD=fixture-password-12345", "", 200},
		{"environment denied", "/.env", "text/plain", "APP_ENV=prod\nDB_PASSWORD=fixture-password-12345", "", 403},
		{"git config", "/.git/config", "text/plain", "[core]\nrepositoryformatversion = 0\nbare = false", "Git repository configuration exposed", 200},
		{"git prose", "/.git/config", "text/plain", "Here is [core] configuration", "", 200},
		{"git unrelated path", "/config", "text/plain", "[core]\nbare = false", "", 200},
		{"token", "/config.json", "application/json", `{"token":"` + token + `"}`, "GitHub credential pattern exposed in response", 200},
		{"short token", "/config.json", "application/json", `{"token":"ghp_short"}`, "", 200},
		{"token HTML guide", "/docs", "text/html", token, "", 200},
		{"private key", "/server.pem", "application/octet-stream", privateKey, "Parseable private key exposed in response", 200},
		{"key marker only", "/server.pem", "text/plain", "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests++
				if req.URL.Path != tc.path || req.Method != "GET" {
					t.Error("unexpected discovery request")
				}
				w.Header().Set("Content-Type", tc.media)
				w.WriteHeader(tc.status)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			r, err := AuditTool(context.Background(), ToolRequest{Tool: "nuclei", Target: server.URL + tc.path + "?token=QUERY_SECRET", Authorized: true})
			if err != nil {
				t.Fatal(err)
			}
			if requests != 1 {
				t.Fatal("must inspect only the requested URL")
			}
			if tc.title == "" && len(r.Findings) != 0 || tc.title != "" && (len(r.Findings) != 1 || r.Findings[0].Title != tc.title) {
				t.Fatalf("unexpected findings: %+v", r.Findings)
			}
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{token, "fixture-password-12345", "QUERY_SECRET", "BEGIN PRIVATE KEY", "DB_PASSWORD"} {
				if strings.Contains(string(data), secret) {
					t.Fatalf("report retained secret material: %s", secret)
				}
			}
		})
	}
}

func TestCORSRulesDoNotClaimWildcardCredentialTheft(t *testing.T) {
	for _, tc := range []struct{ origin, credentials, severity string }{
		{"*", "true", "low"}, {"*", "false", ""}, {"null", "true", "medium"},
		{"https://trusted.test", "true", ""}, {"https://a.test, https://b.test", "false", "low"},
		{"*", "True", ""},
	} {
		r := newReport("nuclei", "", nil)
		response := &AuditResponse{URL: "https://example.test/", Header: http.Header{}}
		response.Header.Set("Access-Control-Allow-Origin", tc.origin)
		response.Header.Set("Access-Control-Allow-Credentials", tc.credentials)
		nucleiCORSRules(r, response)
		if tc.severity == "" && len(r.Findings) != 0 || tc.severity != "" && (len(r.Findings) != 1 || r.Findings[0].Severity != tc.severity) {
			t.Fatalf("%+v: %+v", tc, r.Findings)
		}
	}
}
