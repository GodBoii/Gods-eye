# SPDX-License-Identifier: Apache-2.0
"""Windows handles reject reparse points and keep the opened path from moving."""

import ctypes
import os
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import BinaryIO

from godseye.filesystem import Directory, UnsafeEntry


class FileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("creation", wintypes.FILETIME),
        ("access", wintypes.FILETIME),
        ("write", wintypes.FILETIME),
        ("volume", wintypes.DWORD),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD),
        ("index_high", wintypes.DWORD),
        ("index_low", wintypes.DWORD),
    ]


@contextmanager
def _handle(path: Path, *, directory: bool) -> Iterator[int]:
    # Load APIs on use, never when importing the cross-platform scanner.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    info_call = kernel.GetFileInformationByHandle
    info_call.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInformation)]
    info_call.restype = wintypes.BOOL
    disk_call = kernel.GetFileType
    disk_call.argtypes = [wintypes.HANDLE]
    disk_call.restype = wintypes.DWORD
    final_path_call = kernel.GetFinalPathNameByHandleW
    final_path_call.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    final_path_call.restype = wintypes.DWORD

    # READ|WRITE sharing allows ordinary edits. Omitting DELETE sharing prevents
    # rename/unlink and rejects handles already opened with delete access.
    # Request actual read access for directories too. Metadata-only access does
    # not participate in Windows sharing checks and cannot pin against rename.
    handle = create(str(path), 0x80000000, 3, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = FileInformation()
        if not info_call(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if (
            info.attributes & 0x400
            or bool(info.attributes & 0x10) != directory
            or disk_call(handle) != 1
        ):
            raise UnsafeEntry("A file changed type during scan")
        actual = ctypes.create_unicode_buffer(32768)
        length = final_path_call(handle, actual, len(actual), 0)
        if not length or length >= len(actual):
            raise UnsafeEntry("Could not validate the opened file path")
        opened = actual.value
        if opened.startswith("\\\\?\\UNC\\"):
            opened = "\\\\" + opened[8:]
        elif opened.startswith("\\\\?\\"):
            opened = opened[4:]
        expected = str(path)
        if expected.startswith("\\\\?\\UNC\\"):
            expected = "\\\\" + expected[8:]
        elif expected.startswith("\\\\?\\"):
            expected = expected[4:]
        # Validate the opened handle before any content read. This also rejects
        # an ancestor reparse point changed in place after its original check.
        if os.path.normcase(os.path.normpath(opened)) != os.path.normcase(
            os.path.normpath(expected)
        ):
            raise UnsafeEntry("The opened file escaped the pinned path")
        yield handle
    finally:
        close(handle)


@contextmanager
def pinned_directory(path: Path) -> Iterator[Directory]:
    with _handle(path, directory=True):
        yield Directory(path, -1)


@contextmanager
def regular_file(path: Path) -> Iterator[BinaryIO]:
    import msvcrt

    # Duplicate the handle so fdopen owns only the duplicate, not _handle's handle.
    with _handle(path, directory=False) as handle:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        duplicate = kernel.DuplicateHandle
        duplicate.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        duplicate.restype = wintypes.BOOL
        current = kernel.GetCurrentProcess()
        copied = wintypes.HANDLE()
        if not duplicate(current, handle, current, ctypes.byref(copied), 0, False, 2):
            raise ctypes.WinError(ctypes.get_last_error())
        assert copied.value is not None
        try:
            descriptor = msvcrt.open_osfhandle(copied.value, os.O_RDONLY | os.O_BINARY)
        except OSError:
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle(copied)
            raise
        with os.fdopen(descriptor, "rb") as stream:
            yield stream
