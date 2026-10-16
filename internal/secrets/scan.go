// SPDX-License-Identifier: Apache-2.0
package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	pb "godseye/gen/go/godseye/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Limits struct {
	Workers       int
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFindings   int
}

func DefaultLimits() Limits {
	return Limits{Workers: 2, MaxFiles: 10000, MaxFileBytes: 1 << 20, MaxTotalBytes: 64 << 20, MaxFindings: 1000}
}

type Result struct {
	RunID        string
	Findings     []*pb.UnifiedFinding
	Summary      *pb.RunSummary
	FilesScanned int
	Excluded     int
}

type fileResult struct {
	findings []*pb.UnifiedFinding
	gap      string
}

type fileJob struct {
	name  string
	bytes int64
}

// Scan never executes target code or contacts the network. os.Root confines file opens.
// Input should be an idle checkout: this initial scanner does not create a snapshot.
func Scan(ctx context.Context, directory, project string, limits Limits) (Result, error) {
	result := Result{RunID: newID(), Findings: []*pb.UnifiedFinding{}, Summary: &pb.RunSummary{Status: pb.RunStatus_RUN_STATUS_SUCCEEDED}}
	if strings.TrimSpace(project) == "" || len(project) > 128 || strings.ContainsAny(project, "\x00\r\n") || !utf8.ValidString(project) {
		return result, fmt.Errorf("project must be valid nonempty text of at most 128 bytes")
	}
	if limits.Workers < 1 || limits.Workers > 32 || limits.MaxFiles < 1 || limits.MaxFileBytes < 1 || limits.MaxFileBytes > 16<<20 || limits.MaxTotalBytes < 1 || limits.MaxFindings < 1 || limits.MaxFindings > 10000 {
		return result, fmt.Errorf("invalid scan limits")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return result, fmt.Errorf("open scan root: %w", err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan fileJob, limits.Workers)
	outputs := make(chan fileResult, limits.Workers)
	type walkResult struct {
		gaps     []string
		excluded int
		err      error
	}
	walked := make(chan walkResult, 1)
	go func() {
		state := walkResult{}
		files := 0
		var reserved int64
		state.err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				state.gaps = append(state.gaps, "A directory entry could not be read")
				return fs.SkipDir
			}
			if entry.IsDir() {
				switch entry.Name() {
				case ".git", "node_modules", "vendor", ".venv", "bin", "reports", ".godseye", "dist":
					state.excluded++
					return fs.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				state.excluded++
				return nil
			}
			files++
			if files > limits.MaxFiles {
				state.gaps = append(state.gaps, "File count limit reached")
				return fs.SkipAll
			}
			info, err := entry.Info()
			if err != nil {
				state.gaps = append(state.gaps, "A file could not be inspected")
				return nil
			}
			if info.Size() > limits.MaxFileBytes {
				state.gaps = append(state.gaps, "Files exceeded the per-file byte limit")
				return nil
			}
			// Include one byte of growth detection in every reservation.
			budget := info.Size() + 1
			if budget > limits.MaxTotalBytes-reserved {
				state.gaps = append(state.gaps, "Input reservation budget reached")
				return fs.SkipAll
			}
			reserved += budget
			select {
			case jobs <- fileJob{name, budget}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		close(jobs)
		walked <- state
	}()
	var workers sync.WaitGroup
	for i := 0; i < limits.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			patterns := rules()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				out := scanFile(root, job.name, project, result.RunID, limits, job.bytes, patterns)
				select {
				case outputs <- out:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() { workers.Wait(); close(outputs) }()
	for out := range outputs {
		if out.gap != "" {
			result.Summary.CoverageGaps = append(result.Summary.CoverageGaps, out.gap)
			continue
		}
		result.FilesScanned++
		remaining := limits.MaxFindings - len(result.Findings)
		if len(out.findings) > remaining {
			result.Findings = append(result.Findings, out.findings[:remaining]...)
			result.Summary.CoverageGaps = append(result.Summary.CoverageGaps, "Finding limit reached")
			cancel()
		} else {
			result.Findings = append(result.Findings, out.findings...)
		}
	}
	state := <-walked
	result.Excluded = state.excluded
	result.Summary.CoverageGaps = append(result.Summary.CoverageGaps, state.gaps...)
	if state.err != nil || ctx.Err() != nil {
		result.Summary.CoverageGaps = append(result.Summary.CoverageGaps, "Scan interrupted before all files were inspected")
	}
	if len(result.Summary.CoverageGaps) > 0 {
		result.Summary.Status = pb.RunStatus_RUN_STATUS_PARTIAL
	}
	sort.Strings(result.Summary.CoverageGaps)
	result.Summary.CoverageGaps = unique(result.Summary.CoverageGaps)
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Locations[0].ArtifactUri != b.Locations[0].ArtifactUri {
			return a.Locations[0].ArtifactUri < b.Locations[0].ArtifactUri
		}
		if a.Locations[0].GetStartLine() != b.Locations[0].GetStartLine() {
			return a.Locations[0].GetStartLine() < b.Locations[0].GetStartLine()
		}
		return a.RuleId < b.RuleId
	})
	result.Summary.FindingCount = uint64(len(result.Findings))
	return result, nil
}

func scanFile(root *os.Root, name, project, run string, limits Limits, readBudget int64, patterns []rule) fileResult {
	f, err := root.Open(name)
	if err != nil {
		return fileResult{gap: "A file could not be opened"}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fileResult{gap: "A file changed type during scan"}
	}
	if info.Size() > limits.MaxFileBytes {
		return fileResult{gap: "Files exceeded the per-file byte limit"}
	}
	data, err := io.ReadAll(io.LimitReader(f, readBudget))
	if err != nil {
		return fileResult{gap: "A file could not be read"}
	}
	if int64(len(data)) >= readBudget {
		return fileResult{gap: "A file grew during the scan"}
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return fileResult{gap: "Binary or non-UTF-8 files were not inspected"}
	}
	out := fileResult{}
	uri := strings.ReplaceAll((&url.URL{Path: name}).EscapedPath(), ":", "%3A")
	assetDigest := sha256.Sum256([]byte(name))
	rulesetDigest := rulesDigest(patterns)
	for _, rule := range patterns {
		matches := rule.find(data, limits.MaxFindings+1)
		previousOffset := 0
		line := uint32(1)
		for ordinal, match := range matches {
			line += uint32(bytes.Count(data[previousOffset:match[0]], []byte{'\n'}))
			previousOffset = match[0]
			findingLine := line
			// No source excerpts, matched tokens, or hashes of credentials leave the scanner.
			tuple, err := json.Marshal([]string{"v1", project, rule.id, name, fmt.Sprint(ordinal)})
			if err != nil {
				return fileResult{gap: "Fingerprint could not be encoded"}
			}
			digest := sha256.Sum256(tuple)
			out.findings = append(out.findings, &pb.UnifiedFinding{
				SchemaVersion: "1.0", FindingId: newID(), RunId: run, ProjectId: project,
				Fingerprint: "sha256:" + hex.EncodeToString(digest[:]),
				Producer:    &pb.Producer{PluginId: "builtin.secrets", PluginVersion: "0.1.0", EngineName: "godseye-secrets", EngineVersion: "0.1.0", RulesetDigest: rulesetDigest},
				Category:    pb.Category_CATEGORY_SECRET, RuleId: rule.id, Title: rule.title,
				Description: "Potential credential material detected. Verify ownership and validity; rotate exposed credentials and remove them from source history.",
				Severity:    pb.Severity_SEVERITY_HIGH, Confidence: 0.8,
				Locations:  []*pb.SourceLocation{{ArtifactUri: uri, StartLine: &findingLine}},
				Asset:      &pb.AssetRef{AssetId: "sha256:" + hex.EncodeToString(assetDigest[:]), Kind: "source"},
				Evidence:   &pb.Evidence{Summary: "Pattern matched; credential value and source excerpt withheld."},
				Risk:       &pb.RiskContext{Reachability: pb.Reachability_REACHABILITY_UNKNOWN, ReachabilityReason: "Pattern scanning does not establish runtime reachability or credential validity."},
				ObservedAt: timestamppb.New(time.Now().UTC()),
			})
			if len(out.findings) > limits.MaxFindings {
				return out
			}
		}
	}
	return out
}

func rulesDigest(patterns []rule) string {
	hash := sha256.New()
	for _, r := range patterns {
		fmt.Fprintf(hash, "%d:%s%d:%s", len(r.id), r.id, len(r.pattern.String()), r.pattern.String())
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func newID() string {
	var b [16]byte
	// crypto/rand.Read fills the buffer or terminates the process on entropy failure.
	rand.Read(b[:])
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func unique(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
