// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIReportsAndExitCodes(t *testing.T) {
	root := t.TempDir()
	for _, format := range []string{"json", "sarif"} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), []string{"scan", "--format", format, root}, &out, &errOut); code != 0 {
			t.Fatalf("clean code=%d: %s", code, errOut.String())
		}
		if !json.Valid(out.Bytes()) {
			t.Fatal("invalid JSON report")
		}
	}
	token := "ghp_" + strings.Repeat("Z", 36)
	if err := os.WriteFile(filepath.Join(root, "token.txt"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"scan", root}, &out, &errOut); code != 1 {
		t.Fatalf("findings code=%d", code)
	}
	if strings.Contains(out.String()+errOut.String(), token) {
		t.Fatal("leaked token")
	}
	out.Reset()
	if code := run(context.Background(), []string{"scan", "--max-file-bytes", "1", root}, &out, &errOut); code != 3 {
		t.Fatalf("partial code=%d", code)
	}
	if code := run(context.Background(), []string{"scan", "--format", "unknown", root}, &out, &errOut); code != 2 {
		t.Fatalf("invalid code=%d", code)
	}
}

func TestCLIRefusesOverwrite(t *testing.T) {
	target := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"scan", "--out", target, t.TempDir()}, &out, &errOut); code != 2 {
		t.Fatal("overwrote existing report")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "keep" {
		t.Fatal("existing output changed")
	}
}
