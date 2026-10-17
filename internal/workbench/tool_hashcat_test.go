// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func hashcatRequest(t *testing.T, algorithm string, hashes, candidates []string) ToolRequest {
	t.Helper()
	data, err := json.Marshal(map[string]any{"algorithm": algorithm, "hashes": hashes, "candidates": candidates})
	if err != nil {
		t.Fatal(err)
	}
	return ToolRequest{Input: string(data)}
}

func TestAuditHashcatMatchingAndPrivacy(t *testing.T) {
	// Standard SHA-256 test vector for "abc".
	const known = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	unmatched := sha256.Sum256([]byte("unmatched-secret"))
	r, err := auditHashcat(context.Background(), hashcatRequest(t, "sha256", []string{known, strings.ToUpper(known), hex.EncodeToString(unmatched[:])}, []string{"abc", "abc", "private-nonmatch-marker"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "2 records matched") || len(r.Findings) != 3 {
		t.Fatalf("unexpected audit: %+v", r)
	}
	if len(r.Observations) != 3 || r.Observations[0].Target != "record-0001" {
		t.Fatalf("unexpected observations: %+v", r.Observations)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{known, strings.ToUpper(known), hex.EncodeToString(unmatched[:]), "abc", "private-nonmatch-marker", "unmatched-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("report exposed sensitive input %q", secret)
		}
	}
	if r.InputSHA256 != "" {
		t.Fatal("input fingerprint must not be persisted")
	}
}

func TestAuditHashcatAlgorithmsAndNoMatch(t *testing.T) {
	for _, algorithm := range []string{"sha256", "sha384", "sha512"} {
		t.Run(algorithm, func(t *testing.T) {
			var value []byte
			switch algorithm {
			case "sha256":
				sum := sha256.Sum256(nil)
				value = sum[:]
			case "sha384":
				sum := sha512.Sum384(nil)
				value = sum[:]
			case "sha512":
				sum := sha512.Sum512(nil)
				value = sum[:]
			}
			for _, candidate := range []string{"", "nonmatch"} {
				r, err := auditHashcat(context.Background(), hashcatRequest(t, algorithm, []string{hex.EncodeToString(value)}, []string{candidate}))
				if err != nil {
					t.Fatal(err)
				}
				expected := "0 records matched"
				if candidate == "" {
					expected = "1 records matched"
				}
				if !strings.Contains(r.Summary, expected) {
					t.Fatal(r.Summary)
				}
			}
		})
	}
}

func TestAuditHashcatRejectsInvalidRequests(t *testing.T) {
	sum := sha256.Sum256([]byte("credential"))
	digest := hex.EncodeToString(sum[:])
	valid := hashcatRequest(t, "sha256", []string{digest}, []string{"credential"})
	tooManyHashes := make([]string, hashcatMaxHashes+1)
	tooManyCandidates := make([]string, hashcatMaxCandidates+1)
	hashes := make([]string, hashcatMaxHashes)
	for i := range hashes {
		hashes[i] = digest
	}
	budgetCandidates := make([]string, hashcatMaxCandidates)
	cases := []ToolRequest{
		{}, {RunEngine: true}, {Target: "example.test", Input: valid.Input},
		{Input: "{"}, {Input: valid.Input + " {}"}, {Input: valid.Input + " trailing"}, {Input: "null"},
		{Input: `{"algorithm":"sha256","hashes":["x"],"candidates":["x"],"salt":"secret"}`},
		{Input: "x", Encoding: "unknown"}, {Input: "?", Encoding: "base64"},
		{Input: strings.Repeat(" ", hashcatMaxInput+1)},
		hashcatRequest(t, "md5", []string{digest}, []string{"x"}),
		hashcatRequest(t, "sha256", []string{"$salted$secret"}, []string{"x"}),
		hashcatRequest(t, "sha512", []string{digest}, []string{"x"}),
		hashcatRequest(t, "sha256", nil, []string{"x"}),
		hashcatRequest(t, "sha256", []string{digest}, nil),
		hashcatRequest(t, "sha256", tooManyHashes, []string{"x"}),
		hashcatRequest(t, "sha256", []string{digest}, tooManyCandidates),
		hashcatRequest(t, "sha256", hashes, budgetCandidates),
		hashcatRequest(t, "sha256", []string{digest}, []string{strings.Repeat("x", 1025)}),
	}
	for i, req := range cases {
		if _, err := auditHashcat(context.Background(), req); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditHashcat(ctx, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestAuditHashcatErrorPrivacy(t *testing.T) {
	for _, value := range []string{`{"algorithm":"sensitive-marker"}`, `{"sensitive-marker":true}`, `{"algorithm":"sha256","hashes":["sensitive-marker"],"candidates":["sensitive-marker"]}`} {
		_, err := auditHashcat(context.Background(), ToolRequest{Input: value})
		if err == nil || strings.Contains(err.Error(), "sensitive-marker") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
}
