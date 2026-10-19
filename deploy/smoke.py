# SPDX-License-Identifier: Apache-2.0
"""Exercise real Compose services using local synthetic inputs only.

Run from the repository root with Python 3.13. The saved IDs file goes under
ignored local state. Exercise creates clearly labelled fixture evidence; verify
checks that the same records survive container recreation.
"""

import argparse
import base64
import json
import struct
import tempfile
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
HEADERS = {"X-GodsEye-Request": "1", "Content-Type": "application/json"}


def request(
    port: int,
    path: str,
    *,
    method: str = "GET",
    value: Any = None,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    if value is not None:
        data = json.dumps(value).encode("utf-8")
    outgoing = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        method=method,
        headers={**HEADERS, **(headers or {})},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(outgoing, timeout=50)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        payload = (
            json.loads(body) if response.headers.get_content_type() == "application/json" else body
        )
        return response.status, payload


def png() -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">II5B", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\x01\x02\x03"))
        + chunk(b"IEND", b"")
    )


def scan_fixture(port: int, target: str, candidate: str) -> None:
    status, started = request(
        port,
        "/api/runs",
        method="POST",
        value={
            "kind": "source",
            "target": target,
            "authorized": True,
        },
    )
    assert status == 202, (port, status, started)
    run_id = started["id"]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        status, run = request(port, "/api/runs/" + run_id)
        assert status == 200
        if run["status"] not in {"running", "cancelling"}:
            break
        time.sleep(0.05)
    assert run["status"] == "completed" and run["findingCount"] == 1, run
    for format in ("json", "sarif"):
        status, report = request(port, f"/api/runs/{run_id}/report?format={format}")
        assert status == 200 and candidate not in json.dumps(report)


def check_boundaries(port: int) -> None:
    assert request(port, "/")[0] == 200
    assert request(port, "/api/health")[0] == 200
    assert request(port, "/api/health", headers={"Host": "evil.example"})[0] == 403
    assert request(port, "/api/health", headers={"Origin": "https://evil.example"})[0] == 403


def exercise() -> dict[str, Any]:
    result: dict[str, Any] = {"assets": {}, "reports": []}
    for port in (8765, 8875):
        check_boundaries(port)
        status, asset = request(
            port,
            "/api/assets",
            method="POST",
            value={
                "name": "Compose smoke fixture",
                "kind": "source",
                "target": ".",
                "owner": "self-test",
            },
        )
        assert status == 201, (port, asset)
        result["assets"][str(port)] = asset["id"]
    assert request(8765, "/api/health")[1]["capabilities"] == [
        "workbench-v1",
        "tool-assessments-v1",
    ]
    assert request(8875, "/api/health")[1]["runtime"] == "python"
    assert len(request(8765, "/api/lab/capabilities")[1]) == 26
    assert len(request(8765, "/api/lab/catalog")[1]["formats"]) == 14
    assert request(4173, "/")[0] == 200
    assert request(4173, "/api/flights?lat=999&lon=0")[0] == 400
    assert request(4173, "/api/flights/track")[1] == {"path": []}
    assert request(4173, "/api/unknown-compose-probe")[0] == 404
    assert request(4173, "/api/openai/realtime")[0] == 410

    local = REPOSITORY / ".godseye"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="compose-smoke-", dir=local) as temporary:
        directory = Path(temporary)
        candidate = "AKIA" + "A" * 16
        (directory / "fixture.txt").write_text(candidate, encoding="utf-8")
        target = directory.relative_to(REPOSITORY).as_posix()
        for port in (8765, 8875):
            scan_fixture(port, target, candidate)

    status, imported = request(
        8765,
        "/api/lab/import?format=nuclei",
        method="POST",
        value={
            "template-id": "compose-smoke",
            "host": "https://fixture.invalid/",
            "info": {"name": "Compose integration fixture", "severity": "info"},
        },
    )
    assert status == 201, imported
    result["reports"].append(imported["id"])
    payload = png()
    status, recovered = request(
        8765,
        "/api/lab/assess",
        method="POST",
        value={
            "tool": "foremost",
            "target": "",
            "input": base64.b64encode(payload).decode("ascii"),
            "encoding": "base64",
            "ports": [],
            "authorized": True,
            "runEngine": False,
        },
    )
    assert status == 201, recovered
    assert recovered["artifacts"][0]["offset"] == 0
    assert recovered["artifacts"][0]["length"] == len(payload)
    result["reports"].append(recovered["id"])
    return result


def verify(saved: dict[str, Any]) -> None:
    for port, asset_id in saved["assets"].items():
        status, state = request(int(port), "/api/state")
        assert status == 200 and any(asset["id"] == asset_id for asset in state["assets"])
    for report_id in saved["reports"]:
        status, report = request(8765, "/api/lab/reports/" + report_id)
        assert status == 200 and report["id"] == report_id
        assert request(8765, "/api/lab/reports/" + report_id + "?download=1")[1] == report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["exercise", "verify"])
    parser.add_argument("--results", type=Path, default=REPOSITORY / ".godseye/compose-smoke.json")
    options = parser.parse_args()
    if options.mode == "exercise":
        saved = exercise()
        verify(saved)
        options.results.parent.mkdir(parents=True, exist_ok=True)
        options.results.write_text(json.dumps(saved, indent=2), encoding="utf-8")
    else:
        verify(json.loads(options.results.read_text(encoding="utf-8")))
    print(f"Compose {options.mode} passed")


if __name__ == "__main__":
    main()
