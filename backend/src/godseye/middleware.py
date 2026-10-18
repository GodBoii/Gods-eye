# SPDX-License-Identifier: Apache-2.0
"""Legacy loopback request guards and response headers as pure ASGI middleware."""

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'none'",
}


class LocalBoundary:
    def __init__(self, app: ASGIApp, host: str) -> None:
        self.app = app
        self.host = host

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        reason = ""
        if headers.get("host") != self.host:
            reason = "Host not allowed"
        elif headers.get("origin", "") not in {"", "http://" + self.host}:
            reason = "Origin not allowed"
        elif headers.get("sec-fetch-site") == "cross-site":
            reason = "Cross-site request denied"
        elif scope["method"] not in {"GET", "HEAD"} and headers.get("x-godseye-request") != "1":
            reason = "Missing request header"
        if reason:
            await PlainTextResponse(
                reason + "\n", status_code=403, headers={"X-Content-Type-Options": "nosniff"}
            )(scope, receive, send)
            return

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).update(SECURITY_HEADERS)
            # Go's GET registrations also accept HEAD; body bytes are suppressed.
            if message["type"] == "http.response.body" and scope["method"] == "HEAD":
                message = {**message, "body": b""}
            await send(message)

        await self.app(scope, receive, secure_send)
