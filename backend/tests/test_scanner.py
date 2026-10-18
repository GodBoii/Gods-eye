# SPDX-License-Identifier: Apache-2.0
"""Transfers secrets/rules_test.go, scan_test.go and report/report_test.go behavior."""

import json
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from google.protobuf.json_format import MessageToDict, ParseDict

from godseye.reports import sarif, scan_json
from godseye.scanner import Limits, fingerprint, scan, scan_bytes
from godseye.v1 import plugin_pb2 as pb


@pytest.mark.parametrize(
    ("source", "rule"),
    [
        ("-----BEGIN " + "PRIVATE KEY-----", "secret.private-key"),
        ("-----BEGIN ENCRYPTED " + "PRIVATE KEY-----", "secret.private-key"),
        ("-----BEGIN PUBLIC KEY-----", ""),
        ("AKIA" + "A" * 16, "secret.aws-access-key"),
        ("AKIA" + "A" * 15, ""),
        ("AKIA" + "A" * 17, ""),
        ("ghp_" + "a" * 36, "secret.github-token"),
        ("ghp_example", ""),
        ("é" + "AKIA" + "A" * 16 + "é", "secret.aws-access-key"),
        ("_" + "AKIA" + "A" * 16, ""),
    ],
)
def test_rule_candidates(source: str, rule: str) -> None:
    result = scan_bytes(source.encode(), "fixture.txt", "test", "run", 10)
    assert [item.rule_id for item in result.findings] == ([rule] if rule else [])


def test_redaction_locations_roundtrip_and_stable_identity(tmp_path: Path) -> None:
    candidate = "ghp_" + "a" * 36
    path = tmp_path / "app & config ü.txt"
    path.write_text("safe\ntoken=" + candidate + "\n", encoding="utf-8")
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "ignored.txt").write_text(candidate)
    result = scan(tmp_path, "test")
    assert result.files_scanned == 1 and result.excluded == 1 and len(result.findings) == 1
    finding = result.findings[0]
    assert finding.locations[0].start_line == 2
    assert finding.locations[0].artifact_uri == "app%20&%20config%20%C3%BC.txt"
    encoded = MessageToDict(finding)
    assert candidate not in json.dumps(encoded)
    assert ParseDict(encoded, pb.UnifiedFinding()) == finding
    path.write_text("new line\nsafe\ntoken=" + candidate, encoding="utf-8")
    assert scan(tmp_path, "test").findings[0].fingerprint == finding.fingerprint
    assert encoded["producer"]["rulesetDigest"].startswith("sha256:")
    document = sarif(result)
    assert document["version"] == "2.1.0"
    exported = document["runs"][0]
    assert exported["invocations"][0]["executionSuccessful"] is True
    assert exported["results"][0]["partialFingerprints"]["godseye/v1"] == finding.fingerprint


@pytest.mark.parametrize(
    "change",
    [
        {"max_file_bytes": 2},
        {"max_total_bytes": 2},
        {"max_files": 1},
        {"max_findings": 1},
    ],
)
def test_limits_never_claim_complete(tmp_path: Path, change: dict[str, int]) -> None:
    (tmp_path / "a.txt").write_text("AKIA" + "A" * 16 + "\nAKIA" + "B" * 16)
    (tmp_path / "b.txt").write_text("safe")
    limits = replace(Limits(), **change)
    result = scan(tmp_path, limits=limits)
    assert result.summary.status == pb.RUN_STATUS_PARTIAL
    assert result.summary.coverage_gaps
    assert len(result.findings) <= limits.max_findings
    assert sarif(result)["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_cancel_and_binary_are_partial(tmp_path: Path) -> None:
    (tmp_path / "binary").write_bytes(b"\0binary")
    result = scan(tmp_path)
    assert result.summary.status == pb.RUN_STATUS_PARTIAL and result.files_scanned == 0
    (tmp_path / "binary").write_bytes(b"\xff")
    assert scan(tmp_path).summary.status == pb.RUN_STATUS_PARTIAL
    cancel = threading.Event()
    cancel.set()
    assert scan(tmp_path, cancel=cancel).summary.status == pb.RUN_STATUS_PARTIAL
    assert scan(tmp_path, timeout=0).summary.status == pb.RUN_STATUS_PARTIAL


@pytest.mark.parametrize("project", ["", "a" * 129, "é" * 65, "line\nbreak", "\ud800"])
def test_invalid_project(tmp_path: Path, project: str) -> None:
    with pytest.raises(ValueError, match="project must"):
        scan(tmp_path, project)


@pytest.mark.parametrize(
    "limits",
    [
        Limits(workers=0),
        Limits(workers=33),
        Limits(max_files=0),
        Limits(max_file_bytes=17 << 20),
        Limits(max_total_bytes=0),
        Limits(max_findings=10_001),
    ],
)
def test_invalid_limits(tmp_path: Path, limits: Limits) -> None:
    with pytest.raises(ValueError, match="invalid scan limits"):
        scan(tmp_path, limits=limits)


def test_empty_proto_defaults_and_optional_presence(tmp_path: Path) -> None:
    document = scan_json(scan(tmp_path))
    assert document["summary"] == {"status": "RUN_STATUS_SUCCEEDED"}
    assert document["findings"] == []
    location = pb.SourceLocation(artifact_uri="source", start_line=0)
    assert MessageToDict(location) == {"artifactUri": "source", "startLine": 0}
    summary = pb.RunSummary(finding_count=2**63)
    assert MessageToDict(summary)["findingCount"] == str(2**63)
    assert fingerprint("p", "r", "x", 0) != fingerprint("p", "r", "x", 1)


def test_missing_root(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        scan(tmp_path / "missing")
