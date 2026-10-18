# SPDX-License-Identifier: Apache-2.0
"""Real listeners, copied stores and public HTTP contracts, with no production state."""

import copy
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

HEADERS = {"X-GodsEye-Request": "1"}


@contextmanager
def server(command: list[str], root: Path, state: Path, web: Path) -> Iterator[httpx.Client]:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    state.parent.mkdir(parents=True, exist_ok=True)
    with (state.parent / f"{state.name}-server.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                *command,
                "serve",
                "--root",
                str(root),
                "--state",
                str(state),
                "--web",
                str(web),
                "--port",
                str(port),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False) as client:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    assert process.poll() is None, "local server exited during startup"
                    try:
                        if client.get("/api/health", timeout=0.5).status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    time.sleep(0.02)
                else:
                    pytest.fail("local server did not become ready")
                yield client
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def contract(client: httpx.Client) -> dict:
    results = {}
    cases = [
        ("GET", "/api/state", b"", {}),
        ("GET", "/api/state/", b"", {}),
        ("GET", "/api/health", b"", {"Host": "evil.example"}),
        ("GET", "/api/health", b"", {"Origin": "https://evil.example"}),
        ("GET", "/api/health", b"", {"Sec-Fetch-Site": "cross-site"}),
        ("POST", "/api/assets", b"{}", {}),
        ("POST", "/api/assets", b"[]", HEADERS),
        ("POST", "/api/assets", b"null", HEADERS),
        ("POST", "/api/assets", b'{"name":1}', HEADERS),
        ("POST", "/api/assets", b'{"unknown":1}', HEADERS),
        ("POST", "/api/assets", b"{} {}", HEADERS),
        ("POST", "/api/assets", b"{} trailing", HEADERS),
        ("POST", "/api/assets", b" " * 16385, HEADERS),
        ("DELETE", "/api/assets/missing", b"", HEADERS),
        ("GET", "/api/runs/missing", b"", {}),
        ("GET", "/api/runs/missing/report?format=json", b"", {}),
        ("POST", "/api/runs/missing/cancel", b"", HEADERS),
        ("POST", "/api/runs", b'{"target":"..","kind":"source","authorized":true}', HEADERS),
        ("POST", "/api/runs", b'{"target":".","kind":"source","authorized":false}', HEADERS),
    ]
    for index, (method, url, body, headers) in enumerate(cases):
        response = client.request(method, url, content=body, headers=headers)
        payload = (
            response.json()
            if response.headers.get("content-type", "").startswith("application/json")
            else response.text
        )
        if index == 0:
            payload["workspace"] = "<workspace>"
        results[str(index)] = {"status": response.status_code, "payload": payload}
        if index == 0:
            results["security"] = {
                name: response.headers[name]
                for name in (
                    "content-security-policy",
                    "x-content-type-options",
                    "referrer-policy",
                    "cache-control",
                )
            }
    return results


@pytest.mark.parity
def test_real_http_and_both_direction_inventory(tmp_path: Path) -> None:
    configured = os.environ.get("GODSEYE_GO_BASELINE")
    if not configured:
        pytest.skip("set GODSEYE_GO_BASELINE to run HTTP parity")
    root = tmp_path / "workspace"
    web = tmp_path / "web"
    root.mkdir()
    web.mkdir()
    (web / "index.html").write_text("<!doctype html><title>fixture</title>")
    original = tmp_path / "go-state"
    python_state = tmp_path / "python-state"
    rollback = tmp_path / "rollback-state"
    with server([configured], root, original, web) as old:
        expected = contract(old)
        value = old.post(
            "/api/assets",
            headers=HEADERS,
            json={
                "name": "Synthetic ü project",
                "kind": "source",
                "target": ".",
                "owner": "fixture",
            },
        )
        assert value.status_code == 201
        asset = value.json()
    shutil.copytree(original, python_state)
    with server([sys.executable, "-m", "godseye"], root, python_state, web) as new:
        assert new.get("/api/state").json()["assets"] == [asset]
        new.delete("/api/assets/" + asset["id"], headers=HEADERS).raise_for_status()
        assert contract(new) == expected
        created = new.post(
            "/api/assets",
            headers=HEADERS,
            json={"NAME": "Python saved", "kind": "source", "target": ".", "owner": None},
        )
        assert created.status_code == 201
        saved = created.json()
    shutil.copytree(python_state, rollback)
    with server([configured], root, rollback, web) as restored:
        assert restored.get("/api/state").json()["assets"] == [saved]


@pytest.mark.parity
def test_real_source_job_exports_match_go(tmp_path: Path) -> None:
    configured = os.environ.get("GODSEYE_GO_BASELINE")
    if not configured:
        pytest.skip("set GODSEYE_GO_BASELINE to run HTTP parity")
    root, web = tmp_path / "workspace", tmp_path / "web"
    root.mkdir()
    web.mkdir()
    (web / "index.html").write_text("fixture")
    (root / "candidate.txt").write_text("AKIA" + "A" * 16)
    outputs = []
    for name, command in (("go", [configured]), ("python", [sys.executable, "-m", "godseye"])):
        with server(command, root, tmp_path / name, web) as client:
            run_id = client.post(
                "/api/runs",
                headers=HEADERS,
                json={"target": ".", "kind": "source", "authorized": True},
            ).json()["id"]
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                run = client.get("/api/runs/" + run_id).json()
                if run["status"] not in {"running", "cancelling"}:
                    break
                time.sleep(0.02)
            assert run["status"] == "completed", run
            for key in ("id", "startedAt", "finishedAt"):
                run[key] = "<dynamic>"
            for finding in run["findings"]:
                finding["id"] = "<finding>"
            output = copy.deepcopy(run)
            assert client.get(f"/api/runs/{run_id}/report?format=sarif").status_code == 200
            assert "AKIA" + "A" * 16 not in json.dumps(output)
            outputs.append(output)
    assert outputs[0] == outputs[1]
