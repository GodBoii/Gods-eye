// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLabCLIReportsAndOverwriteProtection(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "report.json")
	output := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(input, []byte(`{"template-id":"fixture","info":{"name":"Fixture","severity":"low"},"host":"example.test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"lab", "catalog"}, {"lab", "import", "--format", "nuclei", input}, {"lab", "import", "--format", "nuclei", "--out", output, input}} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 0 {
			t.Fatal(args, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"lab", "file", "--out", output, input}, &stdout, &stderr); code != 2 {
		t.Fatal("existing output overwritten")
	}
	data, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(data), "Fixture") {
		t.Fatal("original output changed", err)
	}
	if code := run(context.Background(), []string{"lab", "tcp", "--target", "127.0.0.1", "--ports", "80"}, &stdout, &stderr); code != 2 {
		t.Fatal("network authorization omitted")
	}
}
