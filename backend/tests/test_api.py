# SPDX-License-Identifier: Apache-2.0
"""HTTP boundaries, source job lifetime and compatible inventory persistence."""

import multiprocessing
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from godseye.api import create_app
from godseye.config import Settings

BASE = "http://127.0.0.1:8766"
MUTATION = {"X-GodsEye-Request": "1"}


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    root = tmp_path / "workspace"
    web = tmp_path / "web"
    root.mkdir()
    web.mkdir()
    (web / "index.html").write_text("<!doctype html><title>Fixture</title>")
    return Settings(root, tmp_path / "state", web, 8766)


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), base_url=BASE) as value:
        yield value


def test_health_truthful_caps_static_and_headers(client: TestClient) -> None:
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["runtime"] == "python"
    assert health.json()["capabilities"] == ["inventory-v1", "source-scans-v1"]
    assert client.head("/api/health").content == b""
    assert client.get("/").status_code == 200
    assert client.get("/api/state/").status_code == 404
    for path in ("/docs", "/openapi.json", "/api/lab/catalog", "/api/unknown"):
        result = client.get(path)
        assert result.status_code == 404 and "location" not in result.headers
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["cache-control"] == "no-store"
    assert health.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ({"Host": "evil.example"}, "Host not allowed\n"),
        ({"Origin": "https://evil.example"}, "Origin not allowed\n"),
        ({"Sec-Fetch-Site": "cross-site"}, "Cross-site request denied\n"),
        ({}, "Missing request header\n"),
    ],
)
def test_boundary_rejections(client: TestClient, headers: dict[str, str], reason: str) -> None:
    result = client.post("/api/runs", json={}, headers=headers)
    assert result.status_code == 403 and result.text == reason
    assert result.headers["content-type"].startswith("text/plain")


def test_mutation_errors_and_inventory_reopen(client: TestClient, settings: Settings) -> None:
    for content in ('{"name":1}', '{"unknown":1}', "[]", '{"name":"secret"} {}'):
        result = client.post("/api/assets", content=content, headers=MUTATION)
        assert result.status_code == 400
        assert "secret" not in result.text
    result = client.post(
        "/api/assets",
        headers=MUTATION,
        json={"name": "Project", "kind": "source", "target": ".", "owner": "Me"},
    )
    assert result.status_code == 201
    asset_id = result.json()["id"]
    assert len(asset_id) == 26
    # A second application may use the saved store only after the first closes.
    assert client.get("/api/state").json()["assets"][0]["id"] == asset_id
    assert (settings.state / "assets.json").is_file()
    assert client.delete("/api/assets/missing", headers=MUTATION).status_code == 404
    assert client.delete("/api/assets/" + asset_id, headers=MUTATION).json() == {"removed": True}
    assert client.get("/api/state").json()["assets"] == []
    assert client.post("/api/assets", content=b" " * 16385, headers=MUTATION).status_code == 400


def wait_terminal(client: TestClient, run_id: str) -> dict:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = client.get("/api/runs/" + run_id)
        assert result.status_code == 200
        run = result.json()
        if run["status"] not in {"running", "cancelling"}:
            return run
        time.sleep(0.01)
    pytest.fail("source job did not terminate")


def test_scan_job_reports_admission_and_privacy(client: TestClient, settings: Settings) -> None:
    candidate = "AKIA" + "A" * 16
    (settings.root / "candidate.txt").write_text(candidate)
    request = {"kind": "source", "target": ".", "authorized": True}
    result = client.post("/api/runs", json=request, headers=MUTATION)
    assert result.status_code == 202
    run_id = result.json()["id"]
    assert client.post("/api/runs", json=request, headers=MUTATION).status_code == 409
    assert client.get(f"/api/runs/{run_id}/report?format=json").status_code == 409
    run = wait_terminal(client, run_id)
    assert run["status"] == "completed", run
    assert run["files"] == 1 and run["findingCount"] == 1
    assert run["reviewCount"] == 0 and run["finishedAt"]
    assert client.get("/api/state").json()["runs"][0]["findings"] == []
    for format in ("json", "sarif"):
        download = client.get(f"/api/runs/{run_id}/report?format={format}")
        assert download.status_code == 200
        assert candidate not in download.text
        assert "attachment" in download.headers["content-disposition"]
    assert client.get(f"/api/runs/{run_id}/report?format=xml").status_code == 400
    assert client.get("/api/runs/missing").status_code == 404
    assert client.post(f"/api/runs/{run_id}/cancel", headers=MUTATION).json() == {
        "status": "completed"
    }


def test_cancel_keeps_ownership_until_child_stops(client: TestClient, settings: Settings) -> None:
    before = {child.pid for child in multiprocessing.active_children()}
    (settings.root / "large.txt").write_text("ordinary text\n" * 50000)
    request = {"kind": "source", "target": ".", "authorized": True}
    result = client.post("/api/runs", json=request, headers=MUTATION)
    run_id = result.json()["id"]
    start = time.monotonic()
    assert (
        client.post(f"/api/runs/{run_id}/cancel", headers=MUTATION).json()["status"] == "cancelling"
    )
    run = wait_terminal(client, run_id)
    assert run["status"] == "cancelled"
    assert time.monotonic() - start < 5
    assert {child.pid for child in multiprocessing.active_children()} <= before
    assert client.post("/api/runs", json=request, headers=MUTATION).status_code == 202


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "source", "target": "..", "authorized": True},
        {"kind": "source", "target": ".", "authorized": False},
        {"kind": "source", "target": ".", "authorized": True, "unknown": 1},
        {"kind": "database", "target": "db", "authorized": True},
    ],
)
def test_invalid_runs(client: TestClient, payload: dict) -> None:
    assert client.post("/api/runs", json=payload, headers=MUTATION).status_code == 400


def test_state_lock_prevents_second_application(settings: Settings) -> None:
    with (
        TestClient(create_app(settings), base_url=BASE),
        pytest.raises(ValueError, match="owns"),
        TestClient(create_app(settings), base_url=BASE),
    ):
        pass
    with TestClient(create_app(settings), base_url=BASE) as reopened:
        assert reopened.get("/api/state").status_code == 200
