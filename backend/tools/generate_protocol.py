# SPDX-License-Identifier: Apache-2.0
"""Reproduce or check Python bindings without Go or a runtime gRPC server."""

import argparse
import importlib.metadata
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    if importlib.metadata.version("grpcio-tools") != "1.84.0":
        parser.error("install the pinned backend development requirements first")
    backend = Path(__file__).resolve().parents[1]
    repository = backend.parent
    with tempfile.TemporaryDirectory(prefix="godseye-protocol-") as temporary:
        destination = Path(temporary) if arguments.check else backend / "src"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "grpc_tools.protoc",
                "-I",
                str(repository / "api"),
                "--python_out=" + str(destination),
                "--pyi_out=" + str(destination),
                str(repository / "api/godseye/v1/plugin.proto"),
            ],
            check=True,
        )
        if arguments.check:
            for name in ("plugin_pb2.py", "plugin_pb2.pyi"):
                relative = Path("godseye/v1") / name
                actual = (backend / "src" / relative).read_text(encoding="utf-8")
                expected = (destination / relative).read_text(encoding="utf-8")
                if actual != expected:
                    parser.error("generated Python protocol bindings are stale")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
