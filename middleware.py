"""ASGI middleware.

Framework-agnostic by construction: it only touches the ASGI spec's
`scope` / `receive` / `send` primitives, never a FastAPI or Starlette
type, so it works unmodified with FastAPI, Starlette, or any other
ASGI app. Running it for real requires an ASGI server (uvicorn,
hypercorn, ...) — this class itself has no such dependency.

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limiter=RateLimiter(config))
    # or, without FastAPI's helper:
    asgi_app = RateLimitMiddleware(app, limiter=RateLimiter(config))
"""
from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, List, Tuple

from .limiter import RateLimiter
from .types import RateLimitResult

Scope = Dict[str, Any]
Receive = Callable[[], Awaitable[Dict[str, Any]]]
Send = Callable[[Dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter: RateLimiter) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        client = scope.get("client")
        direct_ip = client[0] if client else "0.0.0.0"
        endpoint = scope.get("path", "/")

        result = await self.limiter.check(headers=headers, direct_ip=direct_ip, endpoint=endpoint)

        if not result.allowed:
            await self._send_420(send, result)
            return

        extra_headers: List[Tuple[bytes, bytes]] = [
            (k.encode("latin-1"), v.encode("latin-1")) for k, v in result.headers().items()
        ]

        async def send_with_headers(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + extra_headers
            await send(message)

        await self.app(scope, receive, send_with_headers)

    @staticmethod
    async def _send_420(send: Send, result: RateLimitResult) -> None:
        body = json.dumps(
            {
                "error": "rate_limited",
                "message": "Enhance Your Calm",
                "layer": result.layer.value if result.layer else None,
                "retry_after": result.retry_after,
            }
        ).encode()
        headers = [(b"content-type", b"application/json")]
        headers += [(k.encode("latin-1"), v.encode("latin-1")) for k, v in result.headers().items()]
        await send({"type": "http.response.start", "status": 420, "headers": headers})
        await send({"type": "http.response.body", "body": body})
