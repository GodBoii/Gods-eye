// SPDX-License-Identifier: Apache-2.0
package secrets

import (
	"strings"
	"testing"
)

func TestRuleCandidates(t *testing.T) {
	for _, test := range []struct{ name, input, want string }{
		{"private key", "-----BEGIN " + "PRIVATE KEY-----", "secret.private-key"},
		{"encrypted key", "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----", "secret.private-key"},
		{"public key", "-----BEGIN PUBLIC KEY-----", ""},
		{"access ID", "AKIA" + strings.Repeat("A", 16), "secret.aws-access-key"},
		{"short ID", "AKIA" + strings.Repeat("A", 15), ""},
		{"long ID", "AKIA" + strings.Repeat("A", 17), ""},
		{"token", "ghp_" + strings.Repeat("a", 36), "secret.github-token"},
		{"placeholder", "ghp_example", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := ""
			for _, rule := range rules() {
				if len(rule.find([]byte(test.input), 1)) > 0 {
					got = rule.id
				}
			}
			if got != test.want {
				t.Fatalf("matched %q, want %q", got, test.want)
			}
		})
	}
}
