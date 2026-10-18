// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"godseye/internal/workbench"
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

func TestLabAssessmentCLIUsesNativeModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>Index of /fixture</title><a href="../">Parent Directory</a>`))
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	args := []string{"lab", "assess", "--tool", "nuclei", "--target", server.URL, "--authorized"}
	if code := run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	var report workbench.Report
	if json.Unmarshal(stdout.Bytes(), &report) != nil || report.Tool != "nuclei" || len(report.Findings) != 1 {
		t.Fatal("CLI did not execute native rules", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), args[:len(args)-1], &stdout, &stderr); code != 2 {
		t.Fatal("CLI assessment omitted authorization")
	}
	input := filepath.Join(t.TempDir(), "template.json")
	if err := os.WriteFile(input, []byte(`{"Resources":{"Database":{"Type":"AWS::RDS::DBInstance","Properties":{"PubliclyAccessible":true,"StorageEncrypted":false}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := run(context.Background(), []string{"lab", "assess", "--tool", "cloudfox", "--authorized", input}, &stdout, &stderr)
	if code != 0 && code != 3 {
		t.Fatal(code, stderr.String())
	}
	if json.Unmarshal(stdout.Bytes(), &report) != nil || report.Tool != "cloudfox" || len(report.Findings) < 2 {
		t.Fatal("CLI file assessment failed", stdout.String())
	}
}
