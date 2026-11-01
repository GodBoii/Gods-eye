// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	environmentAssignment = regexp.MustCompile(`(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,80})\s*=\s*([^\r\n]+)`)
	gitCoreSection        = regexp.MustCompile(`(?mi)^\s*\[core\]\s*$`)
	gitRepositoryField    = regexp.MustCompile(`(?mi)^\s*(?:repositoryformatversion|bare)\s*=\s*(?:[0-9]+|true|false)\s*$`)
	githubCredential      = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`)
)

// These rules inspect only the requested response. They never guess paths,
// authenticate with discovered credentials or retain matched values.
func nucleiSensitiveRules(r *Report, response *AuditResponse) {
	if response.Status < 200 || response.Status >= 300 {
		return
	}
	u, err := url.Parse(response.URL)
	if err != nil {
		return
	}
	media := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	html := media == "text/html" || media == "application/xhtml+xml"
	name := path.Base(u.Path)
	if !html && (name == ".env" || strings.HasPrefix(name, ".env.")) {
		assignments, sensitive := 0, 0
		for _, match := range environmentAssignment.FindAllSubmatch(response.Body, -1) {
			assignments++
			key, value := string(match[1]), strings.TrimSpace(string(match[2]))
			if sensitiveEnvironmentKey(key) && !placeholderEnvironmentValue(value) {
				sensitive++
			}
		}
		if assignments >= 2 && sensitive > 0 {
			r.finding("high", "Environment configuration with sensitive assignments exposed", response.URL, "A successful non-HTML response at an explicit .env path contains multiple environment assignments, including a non-placeholder password, secret, token or database URL value. Treat values as credential candidates; restrict access and rotate verified secrets. Names and values are omitted.")
		}
	}
	if !html && strings.HasSuffix(u.Path, "/.git/config") && gitCoreSection.Match(response.Body) && gitRepositoryField.Match(response.Body) {
		r.finding("medium", "Git repository configuration exposed", response.URL, "A successful non-HTML response at an explicit .git/config path contains a core section and repository configuration fields. Restrict access to repository metadata and review deployment contents. No Git objects or other paths were requested; configuration values are omitted.")
	}
	if !html && githubCredential.Match(response.Body) {
		r.finding("high", "GitHub credential pattern exposed in response", response.URL, "A successful non-HTML response contains a supported GitHub token pattern. The value may be a fixture or revoked token; verify privately, remove unintended exposure and rotate valid credentials. The value was not tested or retained.")
	}
	if !html && containsPrivateKey(response.Body) {
		r.finding("high", "Parseable private key exposed in response", response.URL, "A successful non-HTML response contains a PEM block parseable as a PKCS#1, PKCS#8 or EC private key. Remove unintended public access, investigate usage and replace the key if it protects a real system. Public/test keys may be intentional; key bytes are omitted and were not used.")
	}
}

func sensitiveEnvironmentKey(key string) bool {
	for _, suffix := range []string{"PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY", "DATABASE_URL", "DB_URL"} {
		if key == suffix || strings.HasSuffix(key, "_"+suffix) {
			return true
		}
	}
	return false
}

func placeholderEnvironmentValue(value string) bool {
	value = strings.ToLower(strings.Trim(strings.TrimSpace(value), "\"'"))
	if len(value) < 8 || strings.HasPrefix(value, "${") || strings.HasPrefix(value, "<") {
		return true
	}
	for _, marker := range []string{"example", "placeholder", "changeme", "change_me", "your_", "your-", "redacted"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func containsPrivateKey(data []byte) bool {
	// pem.Decode searches for the next block. Bound both work and decoding to
	// the existing 1 MiB response prefix and at most 32 PEM blocks.
	for count := 0; count < 32 && len(data) > 0; count++ {
		block, rest := pem.Decode(data)
		if block == nil {
			return false
		}
		data = rest
		switch block.Type {
		case "RSA PRIVATE KEY":
			if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return true
			}
		case "EC PRIVATE KEY":
			if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return true
			}
		case "PRIVATE KEY":
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				return true
			}
		}
	}
	return false
}

func nucleiCORSRules(r *Report, response *AuditResponse) {
	origins := response.Header.Values("Access-Control-Allow-Origin")
	credentials := response.Header.Get("Access-Control-Allow-Credentials") == "true"
	if len(origins) > 1 || (len(origins) == 1 && strings.Contains(origins[0], ",")) {
		r.finding("low", "Invalid multiple CORS origins", response.URL, "The response declares multiple Access-Control-Allow-Origin values. Browsers reject this configuration; return one validated origin and Vary: Origin when selecting origins dynamically. No cross-origin access was tested.")
	}
	if len(origins) == 1 && strings.TrimSpace(origins[0]) == "*" && credentials {
		r.finding("low", "Wildcard CORS conflicts with credential allowance", response.URL, "Access-Control-Allow-Origin: * is combined with Access-Control-Allow-Credentials: true. Browsers block credentialed reads for this combination; this is a configuration conflict, not proof of credential theft. Use a validated origin allowlist when credentials are needed.")
	}
	if len(origins) == 1 && strings.TrimSpace(origins[0]) == "null" && credentials {
		r.finding("medium", "Credentialed CORS trusts the null origin", response.URL, "The response permits the serialized null origin with credentials. Sandboxed documents can have this origin. Verify cookie policy and response sensitivity in an authorized browser test; no cross-origin request, authentication or data access was attempted.")
	}
}
