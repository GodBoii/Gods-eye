// SPDX-License-Identifier: Apache-2.0
package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "godseye/gen/go/godseye/v1"
)

// A small warm-filesystem baseline, not a production throughput claim.
func BenchmarkScanText(b *testing.B) {
	root := b.TempDir()
	content := []byte(strings.Repeat("ordinary source content\n", 2048))
	const files = 100
	for i := 0; i < files; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("source-%03d.txt", i)), content, 0600); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(int64(len(content) * files))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := Scan(context.Background(), root, "benchmark", DefaultLimits())
		if err != nil {
			b.Fatal(err)
		}
		if result.FilesScanned != files || result.Summary.Status != pb.RunStatus_RUN_STATUS_SUCCEEDED || len(result.Findings) != 0 {
			b.Fatal("unexpected scan result")
		}
	}
}
