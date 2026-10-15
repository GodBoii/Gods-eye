// SPDX-License-Identifier: Apache-2.0
package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "godseye/gen/go/godseye/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func fixture(t *testing.T, root, name, content string) {
	t.Helper()
	full := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestScanRedactsAndRoundTrips(t *testing.T) {
	root := t.TempDir()
	secret := "ghp_" + strings.Repeat("a", 36)
	fixture(t, root, "app config.txt", "safe\ntoken="+secret+"\n")
	fixture(t, root, "node_modules/ignored.txt", secret)
	result, err := Scan(context.Background(), root, "test", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Excluded != 1 || result.FilesScanned != 1 {
		t.Fatalf("unexpected counts: %+v", result)
	}
	finding := result.Findings[0]
	if finding.Locations[0].GetStartLine() != 2 || finding.Locations[0].ArtifactUri != "app%20config.txt" {
		t.Fatal("wrong source location")
	}
	encoded, err := protojson.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("report exposed credential")
	}
	var decoded pb.UnifiedFinding
	if err := protojson.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(finding, &decoded) {
		t.Fatal("JSON round trip changed finding")
	}
	// Inserting a harmless line preserves the content-independent fingerprint.
	fixture(t, root, "app config.txt", "new line\nsafe\ntoken="+secret+"\n")
	again, err := Scan(context.Background(), root, "test", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if again.Findings[0].Fingerprint != finding.Fingerprint {
		t.Fatal("fingerprint depends on line number")
	}
}

func TestScanLimitsAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Limits)
		cancel bool
	}{
		{"file bytes", func(l *Limits) { l.MaxFileBytes = 2 }, false},
		{"total bytes", func(l *Limits) { l.MaxTotalBytes = 2 }, false},
		{"file count", func(l *Limits) { l.MaxFiles = 1 }, false},
		{"findings", func(l *Limits) { l.MaxFindings = 1 }, false},
		{"cancelled", func(l *Limits) {}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			fixture(t, root, "a.txt", "AKIA"+strings.Repeat("A", 16)+"\nAKIA"+strings.Repeat("B", 16))
			fixture(t, root, "b.txt", "safe")
			limits := DefaultLimits()
			test.change(&limits)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancel {
				cancel()
			}
			result, err := Scan(ctx, root, "test", limits)
			if err != nil {
				t.Fatal(err)
			}
			if result.Summary.Status == pb.RunStatus_RUN_STATUS_SUCCEEDED || len(result.Summary.CoverageGaps) == 0 {
				t.Fatal("incomplete scan reported success")
			}
			if len(result.Findings) > limits.MaxFindings {
				t.Fatal("finding budget exceeded")
			}
		})
	}
}

func TestScanRejectsInvalidInputs(t *testing.T) {
	limits := DefaultLimits()
	limits.Workers = 0
	if _, err := Scan(context.Background(), t.TempDir(), "test", limits); err == nil {
		t.Fatal("accepted zero workers")
	}
	if _, err := Scan(context.Background(), t.TempDir(), "", DefaultLimits()); err == nil {
		t.Fatal("accepted empty project")
	}
	if _, err := Scan(context.Background(), filepath.Join(t.TempDir(), "missing"), "test", DefaultLimits()); err == nil {
		t.Fatal("accepted missing root")
	}
}

func TestScanDoesNotFollowSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	fixture(t, outside, "secret.txt", "AKIA"+strings.Repeat("A", 16))
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	result, err := Scan(context.Background(), root, "test", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 || result.Excluded != 1 {
		t.Fatal("followed a symlink")
	}
}

func TestBinaryIsNotReportedClean(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "binary", "\x00binary")
	result, err := Scan(context.Background(), root, "test", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Status != pb.RunStatus_RUN_STATUS_PARTIAL {
		t.Fatal("binary omission not recorded")
	}
}
