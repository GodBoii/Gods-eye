# SPDX-License-Identifier: Apache-2.0
"""Own a spawned scanner until its result or cancellation cleanup is complete."""

import asyncio
import logging
import multiprocessing
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

from godseye.contracts import parse_json
from godseye.reports import sarif, scan_json
from godseye.scanner import DEFAULT_LIMITS, Limits, scan
from godseye.storage import json_bytes

logger = logging.getLogger(__name__)
MAX_RESULT_BYTES = 64 << 20


class WorkerError(RuntimeError):
    pass


def _scan_worker(connection: Connection, root: str, limits: Limits, cancel: Any) -> None:
    try:
        result = scan(Path(root), "dashboard", limits, cancel=cancel)
        data = json_bytes({"json": scan_json(result), "sarif": sarif(result)})
        if len(data) > MAX_RESULT_BYTES:
            raise WorkerError("Report exceeds worker output limit")
        connection.send_bytes(data)
    except Exception:
        # This is a process boundary. Never send exceptions that may contain paths,
        # candidate bytes or parser input. The parent records the failed job ID.
        connection.send_bytes(b'{"error":"Source scan worker failed"}')
    finally:
        connection.close()


async def run_scan(
    root: Path, cancel: asyncio.Event, limits: Limits = DEFAULT_LIMITS
) -> dict[str, Any]:
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    stopped = context.Event()
    process = context.Process(
        target=_scan_worker, args=(send, str(root), limits, stopped), daemon=True
    )
    try:
        process.start()
    except BaseException:
        receive.close()
        send.close()
        process.close()
        raise
    send.close()
    reader = asyncio.create_task(asyncio.to_thread(receive.recv_bytes, MAX_RESULT_BYTES))
    cancelled = asyncio.create_task(cancel.wait())
    try:
        done, _ = await asyncio.wait(
            {reader, cancelled}, timeout=30, return_when=asyncio.FIRST_COMPLETED
        )
        if reader not in done:
            stopped.set()
            try:
                await asyncio.wait_for(asyncio.shield(reader), 1)
            except TimeoutError:
                process.terminate()
        if reader.done() and not reader.cancelled():
            data = reader.result()
            result = parse_json(data)
            if not isinstance(result, dict) or "error" in result:
                raise WorkerError("Source scan worker failed")
            return result
        return {}
    except (EOFError, OSError, ValueError) as error:
        raise WorkerError("Source scan worker failed") from error
    finally:
        stopped.set()
        cancelled.cancel()
        await asyncio.gather(cancelled, return_exceptions=True)
        await asyncio.to_thread(process.join, 1)
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, 1)
        if process.is_alive():
            process.kill()
            await asyncio.to_thread(process.join, 1)
        # EOF follows child exit. Drain the owned reader before closing its pipe.
        await asyncio.gather(reader, return_exceptions=True)
        receive.close()
        if process.is_alive():
            logger.error("worker_cleanup_failed", extra={"operation": "source-scan"})
            raise WorkerError("Source scan worker could not be stopped")
        process.close()
