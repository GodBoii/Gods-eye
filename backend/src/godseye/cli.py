# SPDX-License-Identifier: Apache-2.0
"""Python command entry with legacy scan flags, output protection and exit codes."""

import argparse
import json
import logging
import os
import re
import signal
import sys
import threading
from collections.abc import Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any, TextIO

from godseye import __version__
from godseye.api import create_app
from godseye.config import Settings
from godseye.reports import sarif, scan_json
from godseye.scanner import Limits, scan
from godseye.v1 import plugin_pb2 as pb


def duration(value: str) -> float:
    # Go time.ParseDuration supports compound durations and fractional units.
    value = value.removeprefix("+")
    scales = {
        "ns": 1,
        "us": 1000,
        "µs": 1000,
        "μs": 1000,
        "ms": 1_000_000,
        "s": 1_000_000_000,
        "m": 60_000_000_000,
        "h": 3_600_000_000_000,
    }
    total = 0
    position = 0
    for match in re.finditer(r"(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)", value):
        if match.start() != position:
            raise argparse.ArgumentTypeError("invalid timeout")
        total += int(Decimal(match[1]) * scales[match[2]])
        position = match.end()
    if position != len(value) or total <= 0 or total > 2**63 - 1:
        raise argparse.ArgumentTypeError("invalid timeout")
    return total / 1e9


class JsonLog(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "level": record.levelname.lower(),
                "event": record.getMessage(),
                "operationId": getattr(record, "operation_id", ""),
            }
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="godseye", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version")
    scan_parser = commands.add_parser("scan", allow_abbrev=False)
    scan_parser.add_argument("--format", "-format", choices=["json", "sarif"], default="json")
    scan_parser.add_argument("--out", "-out", default="")
    scan_parser.add_argument("--project", "-project", default="local")
    scan_parser.add_argument("--timeout", "-timeout", type=duration, default=30.0)
    scan_parser.add_argument("--workers", "-workers", type=int, default=2)
    scan_parser.add_argument("--max-files", "-max-files", type=int, default=10_000)
    scan_parser.add_argument("--max-file-bytes", "-max-file-bytes", type=int, default=1 << 20)
    scan_parser.add_argument("--max-total-bytes", "-max-total-bytes", type=int, default=64 << 20)
    scan_parser.add_argument("--max-findings", "-max-findings", type=int, default=1_000)
    scan_parser.add_argument("directory", type=Path)
    scan_parser.add_argument("trailing", nargs=argparse.REMAINDER)
    serve = commands.add_parser("serve", allow_abbrev=False)
    serve.add_argument("--root", "-root", type=Path, default=Path("."))
    serve.add_argument("--web", "-web", type=Path, default=Path("apps/web/dist"))
    serve.add_argument("--state", "-state", type=Path, default=Path(".godseye"))
    serve.add_argument("--port", "-port", type=int, default=8765)
    serve.add_argument("--bind", choices=["127.0.0.1", "0.0.0.0"], default="127.0.0.1")
    return parser


def run(args: Sequence[str], stdout: TextIO = sys.stdout, stderr: TextIO = sys.stderr) -> int:
    parser = _parser()
    try:
        options = parser.parse_args(args)
    except SystemExit as error:
        return int(error.code) if isinstance(error.code, int) else 2
    if options.command == "version":
        stdout.write(f"godseye {__version__} python\n")
        return 0
    if options.command == "serve":
        import uvicorn

        try:
            settings = Settings(
                options.root, options.state, options.web, options.port, options.bind
            ).validated()
            uvicorn.run(
                create_app(settings),
                host=settings.bind,
                port=settings.port,
                workers=1,
                access_log=False,
                server_header=False,
                timeout_graceful_shutdown=5,
                timeout_keep_alive=30,
            )
        except (OSError, ValueError):
            stderr.write("Could not start Python backend. Check paths, port and saved state.\n")
            return 2
        return 0
    # Go stops flag parsing at the first positional argument. Preserve that rule.
    if options.trailing:
        stderr.write("Flags precede the directory.\n")
        return 2
    cancelled = threading.Event()
    previous: Any = None
    if threading.current_thread() is threading.main_thread():
        previous = signal.signal(signal.SIGINT, lambda *_: cancelled.set())
    try:
        limits = Limits(
            options.workers,
            options.max_files,
            options.max_file_bytes,
            options.max_total_bytes,
            options.max_findings,
        )
        result = scan(
            options.directory, options.project, limits, cancel=cancelled, timeout=options.timeout
        )
        payload = scan_json(result) if options.format == "json" else sarif(result)
        # ASCII JSON also works when Windows redirects stdout through a legacy
        # codepage. Decoded JSON retains the original Unicode values.
        data = json.dumps(payload, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        if options.out:
            # O_EXCL is necessary; a prior exists() check races with another writer.
            descriptor = os.open(options.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        else:
            stdout.write(data)
        stderr.write(
            f"{pb.RunStatus.Name(result.summary.status)}: {result.files_scanned} files "
            f"scanned, {len(result.findings)} findings, {result.excluded} exclusions\n"
        )
        if result.summary.status != pb.RUN_STATUS_SUCCEEDED:
            return 3
        return 1 if result.findings else 0
    except (OSError, ValueError) as error:
        # Never render exception repr or parser input from an I/O boundary.
        known_errors = {
            "invalid scan limits",
            "project must be valid nonempty text of at most 128 bytes",
            "workspace must be a directory",
        }
        message = str(error) if str(error) in known_errors else "Scan or report I/O failed"
        stderr.write(message + "\n")
        return 2
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)


def main() -> int:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLog())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    return run(sys.argv[1:])
