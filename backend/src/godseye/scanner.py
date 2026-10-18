# SPDX-License-Identifier: Apache-2.0
"""Offline byte-pattern scanner with bounded reads and canonical Protobuf findings."""

import hashlib
import json
import os
import re
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from godseye.filesystem import Directory, UnsafeEntry, open_root
from godseye.inventory import utc_now
from godseye.v1 import plugin_pb2 as pb

EXCLUDED = frozenset(
    {".git", "node_modules", "vendor", ".venv", "bin", "reports", ".godseye", "dist"}
)


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    source: bytes
    markers: tuple[bytes, ...]
    pattern: re.Pattern[bytes] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "pattern", re.compile(self.source))


RULES = (
    Rule(
        "secret.private-key",
        "Private key material",
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
        (b"-----BEGIN ",),
    ),
    Rule(
        "secret.aws-access-key",
        "AWS access key identifier",
        rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        (b"AKIA", b"ASIA"),
    ),
    Rule(
        "secret.github-token",
        "GitHub token candidate",
        rb"\bgh[pousr]_[A-Za-z0-9]{36}\b",
        (b"gh",),
    ),
)


def rules_digest() -> str:
    digest = hashlib.sha256()
    for rule in RULES:
        rule_id = rule.id.encode()
        digest.update(str(len(rule_id)).encode() + b":" + rule_id)
        digest.update(str(len(rule.source)).encode() + b":" + rule.source)
    return "sha256:" + digest.hexdigest()


RULESET_DIGEST = rules_digest()


@dataclass(frozen=True, slots=True)
class Limits:
    workers: int = 2
    max_files: int = 10_000
    max_file_bytes: int = 1 << 20
    max_total_bytes: int = 64 << 20
    max_findings: int = 1_000

    def validate(self) -> None:
        if (
            not 1 <= self.workers <= 32
            or self.max_files < 1
            or not 1 <= self.max_file_bytes <= 16 << 20
            or self.max_total_bytes < 1
            or not 1 <= self.max_findings <= 10_000
        ):
            raise ValueError("invalid scan limits")


@dataclass(slots=True)
class Result:
    run_id: str
    findings: list[pb.UnifiedFinding]
    summary: pb.RunSummary
    files_scanned: int = 0
    excluded: int = 0


DEFAULT_LIMITS = Limits()


@dataclass(slots=True)
class FileResult:
    findings: list[pb.UnifiedFinding] = field(default_factory=list)
    gap: str = ""


def fingerprint(project: str, rule: str, name: str, ordinal: int) -> str:
    framed = json.dumps(
        ["v1", project, rule, name, str(ordinal)], ensure_ascii=False, separators=(",", ":")
    )
    # encoding/json's default HTML escaping is part of the v1 hash input.
    for source, escaped in (
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("&", "\\u0026"),
        ("\u2028", "\\u2028"),
        ("\u2029", "\\u2029"),
    ):
        framed = framed.replace(source, escaped)
    return "sha256:" + hashlib.sha256(framed.encode("utf-8")).hexdigest()


def scan_bytes(
    data: bytes,
    name: str,
    project: str,
    run_id: str,
    max_findings: int,
    now: Callable[[], datetime] = utc_now,
    new_id: Callable[[], str] = lambda: str(uuid.uuid4()),
) -> FileResult:
    if b"\0" in data:
        return FileResult(gap="Binary or non-UTF-8 files were not inspected")
    try:
        data.decode("utf-8")
        uri = quote(name, safe="/$&+,;=@")
        asset_id = "sha256:" + hashlib.sha256(name.encode("utf-8")).hexdigest()
    except UnicodeError:
        return FileResult(gap="Binary or non-UTF-8 files were not inspected")
    output = FileResult()
    for rule in RULES:
        if not any(marker in data for marker in rule.markers):
            continue
        previous = 0
        line = 1
        for ordinal, match in enumerate(rule.pattern.finditer(data)):
            line += data.count(b"\n", previous, match.start())
            previous = match.start()
            finding = pb.UnifiedFinding(
                schema_version="1.0",
                finding_id=new_id(),
                run_id=run_id,
                project_id=project,
                fingerprint=fingerprint(project, rule.id, name, ordinal),
                producer=pb.Producer(
                    plugin_id="builtin.secrets",
                    plugin_version="0.1.0",
                    engine_name="godseye-secrets",
                    engine_version="0.1.0",
                    ruleset_digest=RULESET_DIGEST,
                ),
                category=pb.CATEGORY_SECRET,
                rule_id=rule.id,
                title=rule.title,
                description=(
                    "Potential credential material detected. Verify ownership and validity; "
                    "rotate exposed credentials and remove them from source history."
                ),
                severity=pb.SEVERITY_HIGH,
                confidence=0.8,
                locations=[pb.SourceLocation(artifact_uri=uri, start_line=line)],
                asset=pb.AssetRef(asset_id=asset_id, kind="source"),
                evidence=pb.Evidence(
                    summary="Pattern matched; credential value and source excerpt withheld."
                ),
                risk=pb.RiskContext(
                    reachability=pb.REACHABILITY_UNKNOWN,
                    reachability_reason="Pattern scanning does not establish runtime reachability "
                    "or credential validity.",
                ),
            )
            finding.observed_at.FromDatetime(now())
            output.findings.append(finding)
            if len(output.findings) > max_findings:
                return output
    return output


def _scan_file(
    root: Directory, name: str, budget: int, project: str, run_id: str, limits: Limits
) -> FileResult:
    try:
        with ExitStack() as stack:
            directory = root
            parts = name.split("/")
            for part in parts[:-1]:
                directory = stack.enter_context(directory.child(part))
            stream = stack.enter_context(directory.file(parts[-1]))
            if os.fstat(stream.fileno()).st_size > limits.max_file_bytes:
                return FileResult(gap="Files exceeded the per-file byte limit")
            data = stream.read(budget)
    except UnsafeEntry:
        return FileResult(gap="A file changed type during scan")
    except OSError:
        return FileResult(gap="A file could not be opened")
    if len(data) >= budget:
        return FileResult(gap="A file grew during the scan")
    return scan_bytes(data, name, project, run_id, limits.max_findings)


def scan(
    directory: Path,
    project: str = "local",
    limits: Limits = DEFAULT_LIMITS,
    *,
    cancel: threading.Event | None = None,
    timeout: float = 30,
) -> Result:
    limits.validate()
    try:
        project_size = len(project.encode("utf-8"))
    except UnicodeError as error:
        raise ValueError("project must be valid nonempty text of at most 128 bytes") from error
    if not project.strip() or project_size > 128 or any(c in project for c in "\x00\r\n"):
        raise ValueError("project must be valid nonempty text of at most 128 bytes")
    stopped = cancel if cancel is not None else threading.Event()
    deadline = time.monotonic() + timeout
    result = Result(str(uuid.uuid4()), [], pb.RunSummary(status=pb.RUN_STATUS_SUCCEEDED))
    gaps: set[str] = set()
    files = 0
    reserved = 0
    saturated = False

    def interrupted() -> bool:
        return stopped.is_set() or time.monotonic() >= deadline or saturated

    def walk(parent: Directory, prefix: str) -> Iterator[tuple[str, int]]:
        nonlocal files, reserved
        if interrupted():
            return
        try:
            entries = parent.entries()
        except OSError:
            gaps.add("A directory entry could not be read")
            return
        for entry in entries:
            if interrupted():
                return
            name = prefix + entry.name
            if entry.directory:
                if entry.name in EXCLUDED:
                    result.excluded += 1
                    continue
                try:
                    with parent.child(entry.name) as child:
                        yield from walk(child, name + "/")
                except OSError:
                    gaps.add("A directory entry could not be read")
            elif not entry.regular:
                result.excluded += 1
            else:
                files += 1
                if files > limits.max_files:
                    gaps.add("File count limit reached")
                    return
                if entry.size > limits.max_file_bytes:
                    gaps.add("Files exceeded the per-file byte limit")
                    continue
                budget = entry.size + 1
                if budget > limits.max_total_bytes - reserved:
                    gaps.add("Input reservation budget reached")
                    return
                reserved += budget
                yield name, budget
            if files > limits.max_files or "Input reservation budget reached" in gaps:
                return

    def collect(future: Future[FileResult]) -> None:
        nonlocal saturated
        output = future.result()
        if output.gap:
            gaps.add(output.gap)
            return
        result.files_scanned += 1
        remaining = limits.max_findings - len(result.findings)
        result.findings.extend(output.findings[:remaining])
        if len(output.findings) > remaining:
            gaps.add("Finding limit reached")
            saturated = True

    with open_root(directory) as root, ThreadPoolExecutor(max_workers=limits.workers) as workers:
        pending: deque[Future[FileResult]] = deque()
        for name, budget in walk(root, ""):
            pending.append(
                workers.submit(_scan_file, root, name, budget, project, result.run_id, limits)
            )
            if len(pending) >= limits.workers * 2:
                collect(pending.popleft())
        for future in pending:
            collect(future)
    if interrupted():
        gaps.add("Scan interrupted before all files were inspected")
    result.findings.sort(
        key=lambda item: (
            item.locations[0].artifact_uri,
            item.locations[0].start_line,
            item.rule_id,
        )
    )
    if gaps:
        result.summary.status = pb.RUN_STATUS_PARTIAL
    result.summary.coverage_gaps.extend(sorted(gaps))
    result.summary.finding_count = len(result.findings)
    return result
