# SPDX-License-Identifier: Apache-2.0
"""Python candidate HTTP application. Only completed features are advertised."""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.staticfiles import StaticFiles

from godseye import __version__
from godseye.application import Application, RunConflict
from godseye.build import identity
from godseye.config import Settings
from godseye.contracts import AssetRequest, InvalidRequest, RunRequest, decode_request
from godseye.middleware import LocalBoundary
from godseye.storage import InstanceLock

logger = logging.getLogger(__name__)


async def request_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 16 << 10:
            raise InvalidRequest("Invalid JSON request")
        body.extend(chunk)
    return bytes(body)


def create_app(settings: Settings) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configuration = settings.validated()
        with InstanceLock(configuration.state):
            application = Application(configuration)
            app.state.application = application
            app.state.build_id = identity()
            try:
                yield
            finally:
                await application.close()

    app = FastAPI(
        lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False
    )
    app.add_middleware(LocalBoundary, host=settings.host)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException) -> Response:
        if error.status_code == 405:
            return PlainTextResponse("Method Not Allowed\n", 405, headers=error.headers)
        return PlainTextResponse("404 page not found\n", 404)

    @app.exception_handler(InvalidRequest)
    async def invalid_request(request: Request, error: InvalidRequest) -> Response:
        return JSONResponse({"error": str(error)}, 400)

    @app.api_route("/api/health", methods=["GET", "HEAD"])
    async def health(request: Request) -> dict[str, Any]:
        return {
            "service": "godseye",
            "version": __version__,
            "runtime": "python",
            "build": request.app.state.build_id,
            "migrationStage": "source-https-and-inventory",
            "capabilities": ["inventory-v1", "source-scans-v1", "https-checks-v1"],
        }

    @app.api_route("/api/state", methods=["GET", "HEAD"])
    async def state(request: Request) -> dict[str, Any]:
        application: Application = request.app.state.application
        return application.state()

    @app.post("/api/assets")
    async def add_asset(request: Request) -> Response:
        value = decode_request(await request_body(request), AssetRequest)
        application: Application = request.app.state.application
        try:
            asset = await asyncio.to_thread(application.inventory.add, value)
        except OverflowError as error:
            return JSONResponse({"error": str(error)}, 409)
        except ValueError as error:
            return JSONResponse({"error": str(error)}, 400)
        except OSError:
            logger.error("inventory_write_failed")
            return JSONResponse({"error": "Could not save inventory"}, 500)
        return JSONResponse(asset, 201)

    @app.delete("/api/assets/{asset_id}")
    async def remove_asset(request: Request, asset_id: str) -> Response:
        application: Application = request.app.state.application
        try:
            await asyncio.to_thread(application.inventory.remove, asset_id)
        except KeyError:
            return JSONResponse({"error": "Asset not found"}, 404)
        except OSError:
            logger.error("inventory_write_failed")
            return JSONResponse({"error": "Could not save inventory"}, 500)
        return JSONResponse({"removed": True})

    @app.post("/api/runs")
    async def start_run(request: Request) -> Response:
        value = decode_request(await request_body(request), RunRequest)
        application: Application = request.app.state.application
        try:
            run_id = application.start(value)
        except RunConflict as error:
            return JSONResponse({"error": str(error)}, 409)
        except ValueError as error:
            return JSONResponse({"error": str(error)}, 400)
        return JSONResponse({"id": run_id}, 202)

    @app.api_route("/api/runs/{run_id}", methods=["GET", "HEAD"])
    async def run_detail(request: Request, run_id: str) -> Response:
        application: Application = request.app.state.application
        try:
            return JSONResponse(application.run(run_id))
        except KeyError:
            return JSONResponse({"error": "Check not found"}, 404)

    @app.post("/api/runs/{run_id}/cancel")
    async def cancel_run(request: Request, run_id: str) -> Response:
        application: Application = request.app.state.application
        try:
            return JSONResponse({"status": application.cancel(run_id)})
        except KeyError:
            return JSONResponse({"error": "Check not found"}, 404)

    @app.api_route("/api/runs/{run_id}/report", methods=["GET", "HEAD"])
    async def download(request: Request, run_id: str) -> Response:
        application: Application = request.app.state.application
        format = request.query_params.get("format", "")
        try:
            report = application.report(run_id, format)
        except KeyError:
            return JSONResponse({"error": "Check not found"}, 404)
        except RunConflict as error:
            return JSONResponse({"error": str(error)}, 409)
        except ValueError as error:
            return JSONResponse({"error": str(error)}, 400)
        return JSONResponse(
            report,
            headers={"Content-Disposition": f"attachment; filename=godseye-{run_id}.{format}"},
        )

    app.mount("/", StaticFiles(directory=settings.web, html=True, check_dir=False))
    return app
