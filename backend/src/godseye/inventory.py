# SPDX-License-Identifier: Apache-2.0
"""Legacy assets.json format and write-before-publish inventory ownership."""

import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ConfigDict

from godseye.contracts import AssetRequest, InvalidRequest, parse_json, timestamp
from godseye.storage import StorageError, atomic_write, json_bytes, read_bounded

KINDS = frozenset(
    {
        "source",
        "website",
        "api",
        "backend",
        "application",
        "database",
        "cloud",
        "container",
        "network",
    }
)


class Asset(AssetRequest):
    # json.Unmarshal historically ignores unknown saved inventory fields.
    model_config = ConfigDict(strict=True, extra="ignore")
    id: str = ""
    createdAt: str = "0001-01-01T00:00:00Z"


def validate_asset(asset: AssetRequest) -> None:
    values = (asset.name, asset.kind, asset.target, asset.owner)
    try:
        sizes = [len(value.encode("utf-8")) for value in values]
    except UnicodeError as error:
        raise ValueError("fields must be single-line text") from error
    if any(any(c in value for c in "\x00\r\n") for value in values):
        raise ValueError("fields must be single-line text")
    if (
        not asset.name.strip()
        or sizes[0] > 100
        or not asset.target.strip()
        or sizes[2] > 1024
        or sizes[3] > 100
    ):
        raise ValueError("provide a name and target within the field limits")
    if asset.kind not in KINDS:
        raise ValueError("unsupported asset category")


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def load_assets(path: Path) -> list[Asset]:
    try:
        data = read_bounded(path, 1 << 20)
    except FileNotFoundError:
        return []
    try:
        raw = parse_json(data)
        if raw is None:
            return []
        if not isinstance(raw, list) or len(raw) > 200:
            raise ValueError("inventory must contain at most 200 assets")
        assets = [Asset.model_validate(value) for value in raw]
        for asset in assets:
            validate_asset(asset)
            if asset.createdAt != "0001-01-01T00:00:00Z":
                timestamp(asset.createdAt)
        return assets
    except (ValueError, InvalidRequest) as error:
        raise StorageError("invalid saved inventory") from error


class Inventory:
    def __init__(
        self, path: Path, new_id: Callable[[], str], now: Callable[[], datetime] = utc_now
    ) -> None:
        self._path = path
        self._new_id = new_id
        self._now = now
        self._lock = threading.Lock()
        self._assets = load_assets(path)

    def list(self) -> list[dict[str, Any]]:
        # Writers replace the whole list after persistence and never mutate assets.
        snapshot = self._assets
        return [asset.model_dump() for asset in snapshot]

    def add(self, request: AssetRequest) -> dict[str, Any]:
        asset = Asset(
            id=self._new_id(),
            name=request.name.strip(),
            kind=request.kind,
            target=request.target.strip(),
            owner=request.owner.strip(),
            createdAt=iso_time(self._now()),
        )
        validate_asset(asset)
        with self._lock:
            if len(self._assets) >= 200:
                raise OverflowError("Inventory limit of 200 assets reached")
            proposed = [*self._assets, asset]
            atomic_write(self._path, json_bytes([value.model_dump() for value in proposed]))
            self._assets = proposed
        return asset.model_dump()

    def remove(self, asset_id: str) -> None:
        with self._lock:
            proposed = [asset for asset in self._assets if asset.id != asset_id]
            if len(proposed) == len(self._assets):
                raise KeyError("Asset not found")
            atomic_write(self._path, json_bytes([value.model_dump() for value in proposed]))
            self._assets = proposed
