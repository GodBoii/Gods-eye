// SPDX-License-Identifier: Apache-2.0
package secrets

import (
	"bytes"
	"regexp"
)

// Patterns are original project rules. Matches are candidates, not validated credentials.
type rule struct {
	id      string
	title   string
	pattern *regexp.Regexp
	markers []string
}

func rules() []rule {
	return []rule{
		{"secret.private-key", "Private key material", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`), []string{"-----BEGIN "}},
		{"secret.aws-access-key", "AWS access key identifier", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), []string{"AKIA", "ASIA"}},
		{"secret.github-token", "GitHub token candidate", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`), []string{"gh"}},
	}
}

// A required literal marker cheaply rejects ordinary text before regex evaluation.
func (r rule) find(data []byte, limit int) [][]int {
	for _, marker := range r.markers {
		if bytes.Contains(data, []byte(marker)) {
			return r.pattern.FindAllIndex(data, limit)
		}
	}
	return nil
}
