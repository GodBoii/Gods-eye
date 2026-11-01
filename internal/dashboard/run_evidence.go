// SPDX-License-Identifier: Apache-2.0
package dashboard

import (
	"fmt"
	"path/filepath"
	"time"

	"godseye/internal/workbench"
)

// runEvidence normalizes finished source/HTTPS checks into the same durable
// evidence contract as assessments. Raw source, credentials and bodies stay out.
func runEvidence(run *Run) *workbench.Report {
	recorded := run.StartedAt
	if run.FinishedAt != nil {
		recorded = *run.FinishedAt
	}
	if recorded.IsZero() {
		recorded = time.Now().UTC()
	}
	target := workbench.Target(run.Target)
	tool := "https-check"
	if run.Kind == "source" {
		tool = "source-scan"
		target = "source:" + filepath.ToSlash(run.Target)
	}
	r := &workbench.Report{
		Tool: tool, CreatedAt: recorded,
		Summary:  fmt.Sprintf("%s %s: %d credential candidates, %d response review items.", tool, run.Status, run.FindingCount, run.ReviewCount),
		Findings: []workbench.Finding{}, Observations: []workbench.Observation{},
		Nodes: []workbench.Node{}, Edges: []workbench.Edge{}, Artifacts: []workbench.Artifact{},
		Gaps: append([]string{}, run.Gaps...), Limited: run.Status != "completed",
	}
	r.Observations = append(r.Observations, workbench.Observation{Kind: "check status", Target: target, Value: run.Status})
	for _, f := range run.Findings {
		r.Findings = append(r.Findings, workbench.Finding{ID: f.ID, Title: f.Title, Severity: f.Severity,
			Target: fmt.Sprintf("%s/%s:%d", target, filepath.ToSlash(f.File), f.Line), Detail: f.Description})
	}
	for i, check := range run.Checks {
		r.Observations = append(r.Observations, workbench.Observation{Kind: check.Name, Target: target, Value: check.Status + ": " + check.Detail})
		if check.Status == "review" {
			r.Findings = append(r.Findings, workbench.Finding{ID: fmt.Sprintf("response-%d", i), Title: "Response review: " + check.Name,
				Severity: "low", Target: target, Detail: check.Detail})
		}
	}
	if run.Kind == "source" {
		r.Gaps = append(r.Gaps, "Credential pattern candidates only; values and source excerpts are omitted. No credential validation, dependency audit or code data-flow analysis. File locations retain the workspace-relative scan target.")
	} else {
		r.Gaps = append(r.Gaps, "One HTTPS response check only. Review items use low triage severity and are not confirmed vulnerabilities; inspect the recorded checks and context.")
	}
	if run.Error != "" {
		r.Gaps = append(r.Gaps, "The check encountered an error; coverage is incomplete. Review the session check for operational details.")
	}
	return r
}
