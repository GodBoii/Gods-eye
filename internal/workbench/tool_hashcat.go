// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

const (
	hashcatMaxHashes         = 256
	hashcatMaxCandidates     = 4096
	hashcatMaxComparisons    = 1_000_000
	hashcatMaxInput          = 1 << 20
	hashcatMaxCandidateBytes = 1024
)

// auditHashcat checks only caller-supplied local digests and candidates. It does
// not persist input fingerprints, digest values, or candidate material.
func auditHashcat(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine {
		return nil, fmt.Errorf("Hashcat engine execution is not supported; supply bounded offline audit JSON")
	}
	if req.Target != "" {
		return nil, fmt.Errorf("password audit accepts local input only, without a target")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > hashcatMaxInput {
		return nil, fmt.Errorf("password audit requires nonempty JSON up to 1 MiB")
	}
	var input struct {
		Algorithm  string   `json:"algorithm"`
		Hashes     []string `json:"hashes"`
		Candidates []string `json:"candidates"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("invalid password audit JSON; expected algorithm, hashes and candidates only")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("password audit requires exactly one JSON object")
	}
	size := 0
	switch input.Algorithm {
	case "sha256":
		size = sha256.Size
	case "sha384":
		size = sha512.Size384
	case "sha512":
		size = sha512.Size
	default:
		return nil, fmt.Errorf("unsupported algorithm; choose explicit unsalted sha256, sha384 or sha512")
	}
	if len(input.Hashes) == 0 || len(input.Hashes) > hashcatMaxHashes || len(input.Candidates) == 0 || len(input.Candidates) > hashcatMaxCandidates {
		return nil, fmt.Errorf("password audit requires 1-256 hashes and 1-4096 candidates")
	}
	if len(input.Hashes)*len(input.Candidates) > hashcatMaxComparisons {
		return nil, fmt.Errorf("password audit exceeds 1,000,000 candidate/hash work budget")
	}
	// Canonical bytes allow upper-case hex without treating it as a new digest.
	digests := make([]string, len(input.Hashes))
	counts := make(map[string]int, len(input.Hashes))
	for i, value := range input.Hashes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != size {
			return nil, fmt.Errorf("hash record %d must be a raw unsalted digest of the selected algorithm; salted and encoded formats are unsupported", i+1)
		}
		digests[i] = string(decoded)
		counts[digests[i]]++
	}
	for _, value := range input.Candidates {
		if len(value) > hashcatMaxCandidateBytes {
			return nil, fmt.Errorf("candidate exceeds 1024-byte limit")
		}
	}
	matched := make(map[string]bool)
	short := make(map[string]bool)
	for _, candidate := range input.Candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var value []byte
		switch input.Algorithm {
		case "sha256":
			sum := sha256.Sum256([]byte(candidate))
			value = sum[:]
		case "sha384":
			sum := sha512.Sum384([]byte(candidate))
			value = sum[:]
		case "sha512":
			sum := sha512.Sum512([]byte(candidate))
			value = sum[:]
		}
		key := string(value)
		if counts[key] > 0 {
			matched[key] = true
			if len(candidate) < 12 {
				short[key] = true
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := newReport("hashcat", "Bounded offline candidate verification completed.", nil)
	r.Limited = true
	r.gap("Only explicit raw unsalted SHA-256, SHA-384 and SHA-512 digests and supplied candidates are supported. No Hashcat engine, generated guesses, salted formats or network authentication testing runs.")
	r.gap("An unmatched digest does not establish password strength. A candidate match alone does not prove a weak password. Duplicate digest records do not establish separate accounts.")
	matchedRecords, shortRecords, reusedGroups := 0, 0, 0
	for key, count := range counts {
		if matched[key] {
			matchedRecords += count
			if count > 1 {
				reusedGroups++
			}
		}
		if short[key] {
			shortRecords += count
		}
	}
	for i, key := range digests {
		if matched[key] {
			r.observe("candidate match", fmt.Sprintf("record-%04d", i+1), "Matched a supplied candidate. Sensitive input is omitted.")
		}
	}
	r.observe("audit totals", "local-audit", fmt.Sprintf("%d digest records; %d candidate entries checked; %d matched records; %d matched repeated-digest groups.", len(digests), len(input.Candidates), matchedRecords, reusedGroups))
	r.finding("medium", "Fast unsalted password digest storage", "local-audit", "The declared storage format uses a fast unsalted digest. For password storage, migrate to an adaptive salted password hashing scheme. Algorithm identity is caller-declared, not inferred from digest length.")
	if shortRecords > 0 {
		r.finding("high", "Short credentials matched supplied candidates", "local-audit", fmt.Sprintf("%d digest records matched candidates shorter than 12 UTF-8 bytes, including any empty candidate. Replace these credentials and review password policy.", shortRecords))
	}
	if reusedGroups > 0 {
		r.finding("medium", "Repeated matched credential digests", "local-audit", fmt.Sprintf("%d repeated-digest groups matched supplied candidates. This may represent password reuse or duplicate input records; verify account provenance before concluding reuse.", reusedGroups))
	}
	r.Summary = fmt.Sprintf("Offline password audit checked %d digest records against %d supplied candidate entries; %d records matched.", len(digests), len(input.Candidates), matchedRecords)
	return r, nil
}
