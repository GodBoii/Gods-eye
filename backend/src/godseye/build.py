# SPDX-License-Identifier: Apache-2.0
"""Identify the installed backend source when checking a running candidate."""

import hashlib
from pathlib import Path


def identity() -> str:
    directory = Path(__file__).parent
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*.py")):
        name = path.relative_to(directory).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(name + b"\0" + str(len(data)).encode("ascii") + b"\0" + data)
    return digest.hexdigest()[:24]
