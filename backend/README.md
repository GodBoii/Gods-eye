# Python migration candidate

The root `docker compose up --build` now starts this candidate on port 8875, the complete existing dashboard/backend on 8765, and Earth on 4173. Frontend assets build in Docker. See [the Compose guide](../documentation/10-docker-compose.md). This packages the current migration state; it does not mark unported features complete.

The current implementation runs inventory, source scans and single-response HTTPS checks, with JSON/SARIF exports, request guards, persistent inventory, one active check, cancellation and a spawned scan worker. It does not call Go. Python 3.13 is required. The exact tested patch is 3.13.3 on Windows. The preview launcher requires PowerShell 7.4 or newer.

This is an intermediate implementation. World feeds, evidence stores, imports, diagnostics and the 26 assessments still run in the existing Go release. They are not advertised by the Python candidate. Do not use the candidate as the default backend until the remaining acceptance gates pass. See [the implementation ledger](../documentation/08-implementation-ledger.md).

From the repository root on Windows:

```powershell
./scripts/start-python.ps1 -Build -Port 8876
```

The script uses a separate port and `.godseye/python-preview` state. It refuses the default Go port/state and verifies the running backend's source build identity before reusing it. It builds only the existing dashboard. Earth's Node service remains separate. The current dashboard can exercise Overview, Assets and source/HTTPS Checks; Workbench and World need their Python implementations before cutover. The existing UI initially opens Workbench, which currently shows an expected missing-route error on this candidate. Use Overview, Assets or Checks for the migrated workflows. This is a cutover blocker, not a completed dashboard migration.

For a development installation:

```powershell
python -m venv backend/.venv
./backend/.venv/Scripts/python.exe -m pip install --require-hashes -r backend/requirements-dev.lock
./backend/.venv/Scripts/python.exe -m pip install --no-deps -e backend
./backend/.venv/Scripts/python.exe -m godseye scan --project local C:/path/to/source
./backend/.venv/Scripts/python.exe -m godseye serve --port 8876 --state .godseye/python-preview --root .
```

`scan` exits 0 for complete/no candidates, 1 for complete/candidates, 2 for invalid setup/output, and 3 for incomplete coverage. Flags precede the directory. `--out` creates a new file exclusively. The rules match credential candidates; reports omit values and excerpts.

Run verification from the repository root:

```powershell
$env:GODSEYE_GO_BASELINE = (Resolve-Path bin/godseye-go-baseline.exe).Path
./backend/.venv/Scripts/python.exe -m pytest backend/tests -q
./backend/.venv/Scripts/python.exe -m ruff check backend
./backend/.venv/Scripts/python.exe -m ruff format --check backend
./backend/.venv/Scripts/python.exe -m mypy --config-file backend/pyproject.toml backend/src/godseye
./backend/.venv/Scripts/python.exe backend/tools/generate_protocol.py --check
```

Go is needed only to rebuild the comparison release and run tests marked `parity`. Without `GODSEYE_GO_BASELINE`, those tests report skips. The Python runtime does not require Go, Node, protoc or grpcio-tools. Serving the UI requires a previously built `apps/web/dist`.

The generated bindings come from the unchanged `api/godseye/v1/plugin.proto`. Regenerate them with `backend/tools/generate_protocol.py`, using the locked development environment. No gRPC server has been added.

The universal runtime and development locks include package hashes. To deliberately refresh them with the pinned uv development tool:

```powershell
./backend/.venv/Scripts/python.exe -m uv pip compile backend/pyproject.toml --python-version 3.13 --universal --generate-hashes -o backend/requirements.lock
./backend/.venv/Scripts/python.exe -m uv pip compile backend/pyproject.toml --extra dev --python-version 3.13 --universal --generate-hashes -o backend/requirements-dev.lock
```

Runtime license texts are in `licenses/python-libraries.txt`; regenerate them with `backend/tools/runtime_notices.py`. Windows and Linux dependency resolution is not proof of Linux execution. Linux confinement, Docker, full subprocess-tree cleanup for future installed engines, load benchmarks and final browser parity remain release gates.

The OS lock coordinates Python writers only. The Go release does not take that lock. Never run both against the same writable state, even if Python can reopen a copied Go inventory.
