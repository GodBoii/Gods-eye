// SPDX-License-Identifier: Apache-2.0
package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"godseye/internal/secrets"
)

func TestSARIFPreservesSourceAndIncompleteStatus(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("safe\nAKIA"+strings.Repeat("A", 16)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "binary"), []byte{0, 1}, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := secrets.Scan(context.Background(), root, "test", secrets.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	data, err := SARIF(result)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Version string
		Runs    []struct {
			Results []struct {
				RuleID    string
				Locations []struct {
					PhysicalLocation struct{ Region struct{ StartLine int } }
				}
			}
			Invocations []struct {
				ExecutionSuccessful        bool
				ToolExecutionNotifications []json.RawMessage
			}
		}
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Version != "2.1.0" || len(report.Runs) != 1 || len(report.Runs[0].Results) != 1 {
		t.Fatal("wrong SARIF result counts")
	}
	run := report.Runs[0]
	if run.Results[0].RuleID != "secret.aws-access-key" || run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 2 {
		t.Fatal("source information lost")
	}
	if run.Invocations[0].ExecutionSuccessful || len(run.Invocations[0].ToolExecutionNotifications) == 0 {
		t.Fatal("incomplete scan reported success")
	}
}
