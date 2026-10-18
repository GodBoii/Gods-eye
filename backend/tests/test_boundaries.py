# SPDX-License-Identifier: Apache-2.0
import os
import subprocess
import sys
from pathlib import Path

import pytest

from godseye.contracts import AssetRequest, InvalidRequest, RunRequest, decode_request
from godseye.filesystem import UnsafeEntry, open_root
from godseye.inventory import Inventory, load_assets
from godseye.scanner import Limits, _scan_file, scan
from godseye.storage import InstanceLock, StorageError


@pytest.mark.parametrize("data", [b"{}", b"null", b'{"target":null}', b'{"TARGET":"."}'])
def test_request_missing_null_and_case(data: bytes) -> None:
    result = decode_request(data, RunRequest)
    assert result.authorized is False
    assert result.target in {"", "."}


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b'{"unknown":1}',
        b'{"authorized":1}',
        b'{"target":123}',
        b'{"target":"\xff"}',
        b"NaN",
        b"{" + b" " * (16 << 10),
    ],
)
def test_request_types_bytes_and_unknowns(data: bytes) -> None:
    with pytest.raises(InvalidRequest, match="Invalid JSON request"):
        decode_request(data, RunRequest)


def test_trailing_json_and_no_input_echo() -> None:
    with pytest.raises(InvalidRequest, match="Expected one JSON object"):
        decode_request(b'{} {"secret":"candidate"}', RunRequest)
    with pytest.raises(InvalidRequest) as error:
        decode_request(b'{"authorized":"candidate"}', RunRequest)
    assert "candidate" not in str(error.value)


def test_inventory_reopen_and_atomic_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "assets.json"
    inventory = Inventory(path, lambda: "A" * 26)
    value = inventory.add(AssetRequest(name=" Project ", kind="source", target=" . ", owner=" Me "))
    assert value["name"] == "Project" and value["owner"] == "Me"
    assert load_assets(path)[0].model_dump() == value
    original = path.read_bytes()

    def fail_replace(*_: object) -> None:
        raise PermissionError("synthetic failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(PermissionError):
        inventory.remove(value["id"])
    assert inventory.list() == [value] and path.read_bytes() == original
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize(
    "content",
    [b"{", b"[] []", b" " * ((1 << 20) + 1), b"[{}]"],
    ids=["malformed", "trailing", "oversized", "invalid-asset"],
)
def test_invalid_inventory_does_not_start_empty(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "assets.json"
    path.write_bytes(content)
    with pytest.raises(StorageError):
        load_assets(path)


def test_inventory_limits_use_utf8_bytes(tmp_path: Path) -> None:
    inventory = Inventory(tmp_path / "assets.json", lambda: "A" * 26)
    with pytest.raises(ValueError, match="field limits"):
        inventory.add(AssetRequest(name="é" * 51, kind="source", target="."))
    with pytest.raises(ValueError, match="single-line"):
        inventory.add(AssetRequest(name="abc\nxyz", kind="source", target="."))
    with pytest.raises(ValueError, match="category"):
        inventory.add(AssetRequest(name="name", kind="unknown", target="."))
    for _ in range(200):
        inventory.add(AssetRequest(name="name", kind="source", target="."))
    with pytest.raises(OverflowError):
        inventory.add(AssetRequest(name="over", kind="source", target="."))


def test_state_lock_is_process_owned_and_releases_after_exit(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "-c",
        "from pathlib import Path; "
        "from godseye.storage import InstanceLock; "
        "import sys; "
        "lock = InstanceLock(Path(sys.argv[1])); lock.__enter__()",
        str(tmp_path),
    ]
    with InstanceLock(tmp_path):
        result = subprocess.run(command, capture_output=True, timeout=10)
        assert result.returncode != 0
        assert b"another Python process owns" in result.stderr
    assert subprocess.run(command, capture_output=True, timeout=10).returncode == 0
    with InstanceLock(tmp_path):
        pass


def test_growing_file_is_omitted(tmp_path: Path) -> None:
    (tmp_path / "source").write_text("longer than reserved")
    with open_root(tmp_path) as root:
        result = _scan_file(root, "source", 2, "test", "run", Limits())
    assert result.gap == "A file grew during the scan" and not result.findings


def test_links_and_directory_replacement(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "candidate").write_text("AKIA" + "A" * 16)
    link = root / "link"
    if sys.platform == "win32":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, timeout=10
        )
        assert result.returncode == 0, result.stderr
    else:
        link.symlink_to(outside, target_is_directory=True)
    result_scan = scan(root)
    assert result_scan.excluded == 1 and not result_scan.findings
    with open_root(root) as directory, pytest.raises(OSError), directory.child("link"):
        pass
    (root / "child").mkdir()
    with open_root(root) as directory, directory.child("child") as child:
        if sys.platform == "win32":
            with pytest.raises(PermissionError):
                (root / "child").rename(root / "moved")
        else:
            (root / "child").rename(root / "moved")
            (root / "child").symlink_to(outside, target_is_directory=True)
            assert child.entries() == []
            with pytest.raises(OSError), directory.child("child"):
                pass


@pytest.mark.parametrize("name", ["../outside", "..", "a/b", "a\\b", "\0"])
def test_invalid_child_names(tmp_path: Path, name: str) -> None:
    with open_root(tmp_path) as root, pytest.raises(UnsafeEntry), root.file(name):
        pass


def test_generated_schema_comes_from_unchanged_source() -> None:
    from google.protobuf import descriptor_pb2

    from godseye.v1 import plugin_pb2 as pb

    descriptor = descriptor_pb2.FileDescriptorProto.FromString(pb.DESCRIPTOR.serialized_pb)
    assert descriptor.package == "godseye.v1"
    assert descriptor.options.go_package == "godseye/gen/go/godseye/v1;godseyev1"
    event = pb.DebugTelemetryEvent(monotonic_offset_ns=2**63)
    event.metric.name = "fixture"
    event.metric.value = 1
    assert event.WhichOneof("payload") == "metric"
    assert pb.DebugTelemetryEvent.FromString(event.SerializeToString()) == event
