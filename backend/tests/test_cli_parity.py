# SPDX-License-Identifier: Apache-2.0
"""Compare real CLI processes. Dynamic allowances are deliberately field-specific."""

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from godseye.cli import duration

REPO = Path(__file__).resolve().parents[2]


def invoke(
    arguments: list[str], executable: list[str] | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*(executable or [sys.executable, "-m", "godseye"]), *arguments],
        capture_output=True,
        encoding="utf-8",
        timeout=20,
    )


def normalize(value: dict, format: str) -> dict:
    result = copy.deepcopy(value)
    if format == "json":
        result["runId"] = "<run>"
        for finding in result["findings"]:
            finding["findingId"] = "<finding>"
            finding["runId"] = "<run>"
            finding["observedAt"] = "<time>"
    else:
        for run in result["runs"]:
            run["properties"]["godseye.runId"] = "<run>"
            for finding in run["results"]:
                finding["guid"] = "<finding>"
                finding["properties"]["godseye.runId"] = "<run>"
    return result


@pytest.mark.parametrize(("case", "code"), [("clean", 0), ("candidate", 1), ("binary", 3)])
def test_cli_exit_and_output(tmp_path: Path, case: str, code: int) -> None:
    content = {"clean": b"safe", "candidate": b"AKIA" + b"A" * 16, "binary": b"\x00binary"}
    (tmp_path / "fixture.txt").write_bytes(content[case])
    result = invoke(["scan", str(tmp_path)])
    assert result.returncode == code, result.stderr
    document = json.loads(result.stdout)
    assert content["candidate"].decode() not in result.stdout + result.stderr
    assert document["filesScanned"] == (0 if case == "binary" else 1)


def test_cli_output_exclusive_and_flag_order(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "clean").write_text("safe")
    output = tmp_path / "report.json"
    assert invoke(["scan", "--out", str(output), str(source)]).returncode == 0
    first = output.read_bytes()
    assert invoke(["scan", "--out", str(output), str(source)]).returncode == 2
    assert output.read_bytes() == first
    assert invoke(["scan", str(source), "--workers", "1"]).returncode == 2
    assert invoke(["scan", "--workers", "0", str(source)]).returncode == 2


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1m30s", 90),
        ("1500ms", 1.5),
        (".5s", 0.5),
        ("+1s", 1),
        ("100us", 0.0001),
        ("100µs", 0.0001),
    ],
)
def test_go_duration_units(value: str, expected: float) -> None:
    assert duration(value) == expected


@pytest.mark.parity
@pytest.mark.parametrize("format", ["json", "sarif"])
@pytest.mark.parametrize("case", ["clean", "candidate", "binary", "file-limit", "byte-limit"])
def test_go_python_complete_scan_contract(tmp_path: Path, format: str, case: str) -> None:
    configured = os.environ.get("GODSEYE_GO_BASELINE")
    if not configured:
        pytest.skip("set GODSEYE_GO_BASELINE to the isolated Go baseline executable")
    baseline = Path(configured)
    assert baseline.is_file()
    (tmp_path / "safe.txt").write_text("safe")
    if case != "clean":
        # Exercise escaped hash framing, byte word boundaries and URI encoding.
        source = "éAKIA" + "A" * 16 + "é\n" + "ghp_" + "b" * 36
        (tmp_path / "a & ü.txt").write_text(source, encoding="utf-8")
    if case == "binary":
        (tmp_path / "binary").write_bytes(b"\xff\0")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "omit").write_text("AKIA" + "B" * 16)
    arguments = ["scan", "--format", format, "--project", "test<&\u2028"]
    if case == "file-limit":
        arguments += ["--max-files", "1", "--workers", "1"]
    if case == "byte-limit":
        arguments += ["--max-file-bytes", "2"]
    arguments.append(str(tmp_path))
    old = invoke(arguments, [str(baseline)])
    new = invoke(arguments)
    assert old.returncode == new.returncode, (old.stderr, new.stderr)
    assert normalize(json.loads(old.stdout), format) == normalize(json.loads(new.stdout), format)
