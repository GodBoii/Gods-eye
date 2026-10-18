# SPDX-License-Identifier: Apache-2.0
"""Bounded JSON I/O, atomic replacement and a process-owned state lock."""

import json
import os
import sys
import tempfile
from pathlib import Path
from types import TracebackType
from typing import BinaryIO


class StorageError(ValueError):
    """A saved document is invalid or exceeds the contract's bounds."""


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise StorageError("saved document exceeds storage limit")
    return data


def json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
        "utf-8"
    )


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix="godseye-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if sys.platform != "win32":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class InstanceLock:
    """Hold an OS lock until close/crash. Never unlink the lock's inode while owned.

    This coordinates Python instances. Legacy Go does not participate, so migration
    launches must still use a separate state copy.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._stream: BinaryIO | None = None

    def __enter__(self) -> "InstanceLock":
        if self._stream is not None:
            raise RuntimeError("state lock is already held by this object")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        stream = (self.directory / ".python-writer.lock").open("a+b")
        try:
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            stream.close()
            raise StorageError("another Python process owns this state directory") from error
        self._stream = stream
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None
