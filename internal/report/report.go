// SPDX-License-Identifier: Apache-2.0
package report

import (
	"encoding/json"
	"fmt"

	pb "godseye/gen/go/godseye/v1"
	"godseye/internal/secrets"
	"google.golang.org/protobuf/encoding/protojson"
)

// JSON preserves the canonical Protobuf JSON encoding inside a scan envelope.
func JSON(result secrets.Result) ([]byte, error) {
	findings := make([]json.RawMessage, 0, len(result.Findings))
	for _, finding := range result.Findings {
		data, err := protojson.Marshal(finding)
		if err != nil {
			return nil, fmt.Errorf("encode finding: %w", err)
		}
		findings = append(findings, data)
	}
	summary, err := protojson.Marshal(result.Summary)
	if err != nil {
		return nil, fmt.Errorf("encode summary: %w", err)
	}
	return json.MarshalIndent(struct {
		RunID        string            `json:"runId"`
		Findings     []json.RawMessage `json:"findings"`
		Summary      json.RawMessage   `json:"summary"`
		FilesScanned int               `json:"filesScanned"`
		Excluded     int               `json:"excludedEntries"`
	}{result.RunID, findings, summary, result.FilesScanned, result.Excluded}, "", "  ")
}

type object = map[string]any

// SARIF currently exports the built-in secrets engine, not arbitrary plugin output.
func SARIF(result secrets.Result) ([]byte, error) {
	rules := []object{}
	results := []object{}
	seen := map[string]bool{}
	for _, finding := range result.Findings {
		if !seen[finding.RuleId] {
			seen[finding.RuleId] = true
			rules = append(rules, object{"id": finding.RuleId, "shortDescription": object{"text": finding.Title}})
		}
		locations := []object{}
		for _, location := range finding.Locations {
			physical := object{"artifactLocation": object{"uri": location.ArtifactUri, "uriBaseId": "SRCROOT"}}
			if location.StartLine != nil {
				physical["region"] = object{"startLine": location.GetStartLine()}
			}
			locations = append(locations, object{"physicalLocation": physical})
		}
		results = append(results, object{
			"ruleId": finding.RuleId, "guid": finding.FindingId, "level": "error",
			"message": object{"text": finding.Description}, "locations": locations,
			"partialFingerprints": object{"godseye/v1": finding.Fingerprint},
			"properties":          object{"godseye.runId": finding.RunId, "godseye.severity": finding.Severity.String(), "godseye.confidence": finding.Confidence, "godseye.category": finding.Category.String(), "godseye.reachability": finding.Risk.Reachability.String()},
		})
	}
	notifications := []object{}
	for _, gap := range result.Summary.CoverageGaps {
		notifications = append(notifications, object{"level": "warning", "message": object{"text": gap}})
	}
	return json.MarshalIndent(object{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []object{{
			"tool":        object{"driver": object{"name": "godseye-secrets", "version": "0.1.0", "rules": rules}},
			"results":     results,
			"invocations": []object{{"executionSuccessful": result.Summary.Status == pb.RunStatus_RUN_STATUS_SUCCEEDED, "toolExecutionNotifications": notifications}},
			"properties":  object{"godseye.runId": result.RunID, "godseye.excludedEntries": result.Excluded},
		}},
	}, "", "  ")
}
