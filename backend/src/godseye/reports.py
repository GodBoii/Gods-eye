# SPDX-License-Identifier: Apache-2.0
"""Canonical ProtoJSON scan envelope and the existing source-only SARIF export."""

from typing import Any

from google.protobuf.json_format import MessageToDict

from godseye.scanner import Result
from godseye.v1 import plugin_pb2 as pb


def scan_json(result: Result) -> dict[str, Any]:
    return {
        "runId": result.run_id,
        "findings": [MessageToDict(item) for item in result.findings],
        "summary": MessageToDict(result.summary),
        "filesScanned": result.files_scanned,
        "excludedEntries": result.excluded,
    }


def sarif(result: Result) -> dict[str, Any]:
    rules = []
    findings = []
    seen = set()
    for finding in result.findings:
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            rules.append({"id": finding.rule_id, "shortDescription": {"text": finding.title}})
        locations = []
        for location in finding.locations:
            physical: dict[str, Any] = {
                "artifactLocation": {"uri": location.artifact_uri, "uriBaseId": "SRCROOT"}
            }
            if location.HasField("start_line"):
                physical["region"] = {"startLine": location.start_line}
            locations.append({"physicalLocation": physical})
        findings.append(
            {
                "ruleId": finding.rule_id,
                "guid": finding.finding_id,
                "level": "error",
                "message": {"text": finding.description},
                "locations": locations,
                "partialFingerprints": {"godseye/v1": finding.fingerprint},
                "properties": {
                    "godseye.runId": finding.run_id,
                    "godseye.severity": pb.Severity.Name(finding.severity),
                    "godseye.confidence": finding.confidence,
                    "godseye.category": pb.Category.Name(finding.category),
                    "godseye.reachability": pb.Reachability.Name(finding.risk.reachability),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "godseye-secrets", "version": "0.1.0", "rules": rules}},
                "results": findings,
                "invocations": [
                    {
                        "executionSuccessful": result.summary.status == pb.RUN_STATUS_SUCCEEDED,
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": gap}}
                            for gap in result.summary.coverage_gaps
                        ],
                    }
                ],
                "properties": {
                    "godseye.runId": result.run_id,
                    "godseye.excludedEntries": result.excluded,
                },
            }
        ],
    }
