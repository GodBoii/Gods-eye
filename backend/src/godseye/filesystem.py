# SPDX-License-Identifier: Apache-2.0
"""Descriptor/handle-owned traversal for an idle source checkout.

POSIX opens each child relative to its pinned parent with O_NOFOLLOW. Windows
pins every ancestor against rename/delete, opens the final component as a reparse
point and rejects reparse attributes before enumeration/read. Hard links remain
regular files, as in Go. Neither implementation snapshots concurrent file writes.
"""

import os
import stat
import sys
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


class UnsafeEntry(OSError):
    """A link, reparse point or nonregular entry cannot be traversed."""


@dataclass(frozen=True, slots=True)
class Entry:
    name: str
    directory: bool
    regular: bool
    size: int


class Directory:
    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self.descriptor = descriptor

    def entries(self) -> list[Entry]:
        source: int | Path = self.path if sys.platform == "win32" else self.descriptor
        with os.scandir(source) as entries:
            result = []
            for item in entries:
                info = item.stat(follow_symlinks=False)
                reparse = bool(getattr(info, "st_file_attributes", 0) & 0x400)
                result.append(
                    Entry(
                        item.name,
                        stat.S_ISDIR(info.st_mode) and not reparse,
                        stat.S_ISREG(info.st_mode) and not reparse,
                        info.st_size,
                    )
                )
        return sorted(result, key=lambda entry: entry.name)

    @contextmanager
    def child(self, name: str) -> Iterator["Directory"]:
        _validate_name(name)
        if sys.platform == "win32":
            from godseye.filesystem_windows import pinned_directory

            with pinned_directory(self.path / name) as directory:
                yield directory
        else:
            descriptor = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.descriptor
            )
            try:
                yield Directory(self.path / name, descriptor)
            finally:
                os.close(descriptor)

    @contextmanager
    def file(self, name: str) -> Iterator[BinaryIO]:
        _validate_name(name)
        if sys.platform == "win32":
            from godseye.filesystem_windows import regular_file

            with regular_file(self.path / name) as stream:
                yield stream
        else:
            # NONBLOCK prevents a file swapped to a FIFO from blocking open().
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.descriptor
            )
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise UnsafeEntry("A file changed type during scan")
                stream = os.fdopen(descriptor, "rb")
            except BaseException:
                os.close(descriptor)
                raise
            with stream:
                yield stream


def _validate_name(name: str) -> None:
    if not name or name in {".", ".."} or any(c in name for c in "/\\\x00"):
        raise UnsafeEntry("invalid child name")
    if sys.platform == "win32" and (":" in name or name.endswith((" ", "."))):
        raise UnsafeEntry("ambiguous Windows child name")


@contextmanager
def open_root(path: Path) -> Iterator[Directory]:
    absolute = path.resolve(strict=True)
    if not absolute.is_dir():
        raise ValueError("workspace must be a directory")
    if sys.platform == "win32":
        from godseye.filesystem_windows import pinned_directory

        # Pin the complete resolved path. Closing parents before descendants would
        # let a later CreateFileW path lookup traverse a replacement ancestor.
        with ExitStack() as stack:
            current = Path(absolute.anchor)
            directory = stack.enter_context(pinned_directory(current))
            for component in absolute.parts[1:]:
                current = current / component
                directory = stack.enter_context(pinned_directory(current))
            yield directory
    else:
        descriptor = os.open(absolute, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield Directory(absolute, descriptor)
        finally:
            os.close(descriptor)
