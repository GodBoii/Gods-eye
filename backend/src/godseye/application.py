# SPDX-License-Identifier: Apache-2.0
"""Application-owned inventory and source scan state, independent of HTTP handlers."""

import asyncio
import copy
import logging
import secrets
from pathlib import Path
from typing import Any

from godseye.config import Settings
from godseye.contracts import RunRequest
from godseye.inventory import Inventory, iso_time, utc_now
from godseye.jobs import WorkerError, run_scan
from godseye.webcheck import Check, inspect

logger = logging.getLogger(__name__)


def new_id() -> str:
    # Go crypto/rand.Text emits 26 RFC 4648 base32 characters for 128 random bits.
    import base64

    return base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


class RunConflict(ValueError):
    pass


class Application:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.inventory = Inventory(settings.state / "assets.json", new_id)
        self.runs: list[dict[str, Any]] = []
        self._reports: dict[str, dict[str, Any]] = {}
        self._active: tuple[str, asyncio.Event, asyncio.Task[None]] | None = None
        self._closing = False

    def state(self) -> dict[str, Any]:
        summaries = [{**run, "findings": [], "checks": []} for run in self.runs]
        return {
            "workspace": str(self.settings.root),
            "assets": self.inventory.list(),
            "runs": summaries,
        }

    def run(self, run_id: str) -> dict[str, Any]:
        for run in self.runs:
            if run["id"] == run_id:
                return copy.deepcopy(run)
        raise KeyError("Check not found")

    def start(self, request: RunRequest) -> str:
        if not request.authorized:
            raise ValueError("Confirm that you own or are authorized to check the target")
        if not request.target or len(request.target.encode("utf-8")) > 1024:
            raise ValueError("A target is required")
        resolved = self.settings.root
        if request.kind == "source":
            path = Path(request.target)
            if path.is_absolute() or path.drive:
                raise ValueError("use a workspace-relative directory")
            try:
                resolved = (self.settings.root / path).resolve(strict=True)
            except OSError as error:
                raise ValueError("directory does not exist") from error
            if not resolved.is_relative_to(self.settings.root):
                raise ValueError("directory must stay inside the configured workspace")
            if not resolved.is_dir():
                raise ValueError("target must be a directory")
        elif request.kind not in {"website", "api", "backend", "application"}:
            raise ValueError("This asset category supports inventory only")
        # All transitions occur synchronously on the one application event loop.
        if self._active is not None or self._closing:
            raise RunConflict("A check is already running; wait or cancel it first")
        run_id = new_id()
        self.runs.insert(
            0,
            {
                "id": run_id,
                "target": request.target,
                "kind": request.kind,
                "status": "running",
                "startedAt": iso_time(utc_now()),
                "finishedAt": None,
                "files": 0,
                "findingCount": 0,
                "reviewCount": 0,
                "findings": [],
                "checks": [],
                "gaps": [],
                "error": "",
            },
        )
        removed = self.runs[20:]
        del self.runs[20:]
        for run in removed:
            self._reports.pop(run["id"], None)
        cancelled = asyncio.Event()
        task = asyncio.create_task(self._execute(run_id, resolved, cancelled))
        self._active = (run_id, cancelled, task)
        return run_id

    async def _execute(self, run_id: str, path: Path, cancelled: asyncio.Event) -> None:
        run = next(run for run in self.runs if run["id"] == run_id)
        try:
            if run["kind"] != "source":
                run["checks"] = await self._inspect(run["target"], run["kind"], cancelled)
                run["reviewCount"] = sum(check["status"] == "review" for check in run["checks"])
                run["status"] = "completed"
                return
            output = await run_scan(path, cancelled)
            if output:
                report = output["json"]
                run["files"] = report["filesScanned"]
                run["gaps"] = report["summary"].get("coverageGaps", [])
                run["findings"] = [
                    {
                        "id": item["findingId"],
                        "title": item["title"],
                        "rule": item["ruleId"],
                        "severity": item["severity"].removeprefix("SEVERITY_").lower(),
                        "file": item["locations"][0]["artifactUri"],
                        "line": item["locations"][0].get("startLine", 0),
                        "description": item["description"],
                    }
                    for item in report["findings"]
                ]
                run["findingCount"] = len(run["findings"])
                self._reports[run_id] = output
                run["status"] = "partial" if run["gaps"] else "completed"
            else:
                run["status"] = "cancelled"
        except WorkerError:
            run["status"] = "failed"
            run["error"] = "Source scan worker failed"
            logger.error("source_scan_failed", extra={"operation_id": run_id})
        except ValueError as error:
            run["status"] = "failed"
            run["error"] = str(error)
        except Exception:
            # Last application boundary: log a category, never exception input.
            run["status"] = "failed"
            run["error"] = "Check failed"
            logger.error("check_failed", extra={"operation_id": run_id})
        finally:
            if cancelled.is_set():
                run["status"] = "cancelled"
            run["finishedAt"] = iso_time(utc_now())
            if self._active is not None and self._active[0] == run_id:
                self._active = None

    @staticmethod
    async def _inspect(target: str, kind: str, cancelled: asyncio.Event) -> list[Check]:
        request = asyncio.create_task(inspect(target, kind))
        cancellation = asyncio.create_task(cancelled.wait())
        try:
            done, _ = await asyncio.wait(
                {request, cancellation}, timeout=30, return_when=asyncio.FIRST_COMPLETED
            )
            if request in done and not cancelled.is_set():
                return request.result()
            cancelled.set()
            return []
        finally:
            request.cancel()
            cancellation.cancel()
            await asyncio.gather(request, cancellation, return_exceptions=True)

    def cancel(self, run_id: str) -> str:
        run = next((run for run in self.runs if run["id"] == run_id), None)
        if run is None:
            raise KeyError("Check not found")
        if self._active is not None and self._active[0] == run_id and run["status"] == "running":
            run["status"] = "cancelling"
            self._active[1].set()
        return str(run["status"])

    def report(self, run_id: str, format: str) -> dict[str, Any]:
        run = self.run(run_id)
        if run["status"] in {"running", "cancelling"}:
            raise RunConflict("Check has not finished")
        if format not in {"json", "sarif"}:
            raise ValueError("Unsupported report format")
        output = self._reports.get(run_id)
        if output:
            return dict(output[format])
        if format == "json":
            return run
        raise ValueError("SARIF is available for source scans only")

    async def close(self) -> None:
        self._closing = True
        if self._active is not None:
            _, event, task = self._active
            event.set()
            await task
