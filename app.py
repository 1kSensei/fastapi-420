#!/usr/bin/env python3
"""fastapi_420 demo app -- a real HTTP server, stdlib only.

The project spec (see README / wiki) wires this middleware into
FastAPI via `RateLimitMiddleware`, run under uvicorn. Neither is
installed in this environment, so this file demonstrates the exact
same `RateLimiter.check()` call -- the actual rate-limiting logic --
against Python's built-in `http.server` instead. Swap in FastAPI +
`app.add_middleware(RateLimitMiddleware, limiter=...)` and nothing
about the limiter itself changes; see middleware.py.

Two routes, two different limiter configs, exactly like a real app
would have a stricter login limit than its general API:

  POST /auth/login   -- 3 requests / 30s per client (brute-force guard)
  GET  /api/data      -- 20 req/s burst up to 30, token bucket

Run with:  uv run python examples/app.py
       or: python3 examples/app.py   (from the project root)

Then, in another terminal:

  curl -i http://127.0.0.1:8000/auth/login -X POST -d "username=test&password=test"
  # repeat 4x -- the 4th response is HTTP/1.1 420 Enhance Your Calm

  curl -i http://127.0.0.1:8000/api/data
"""
from __future__ import annotations

import asyncio
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fastapi_420 import Algorithm, LimitRule, RateLimiter, RateLimiterConfig

HOST, PORT = "127.0.0.1", 8000

# A tight, isolated limiter for the sensitive endpoint -- three failed
# logins and you wait. No endpoint/global layer: this instance exists
# only to guard this one route, so those layers would be redundant.
login_limiter = RateLimiter(
    RateLimiterConfig(
        algorithm=Algorithm.SLIDING_WINDOW,
        user_limit=LimitRule(limit=3, window_seconds=30),
        endpoint_limit=None,
        global_limit=None,
    )
)

# A more generous, burst-tolerant limiter for everything else.
default_limiter = RateLimiter(
    RateLimiterConfig(
        algorithm=Algorithm.TOKEN_BUCKET,
        user_limit=LimitRule(limit=20, window_seconds=1, burst=30),
        endpoint_limit=None,
        global_limit=LimitRule(limit=500, window_seconds=10),
    )
)

ROUTES = {("POST", "/auth/login"): login_limiter}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fastapi_420-demo/1.0"

    def _dispatch(self, method: str) -> None:
        limiter = ROUTES.get((method, self.path), default_limiter)
        headers = {k.lower(): v for k, v in self.headers.items()}
        direct_ip = self.client_address[0]

        length = int(self.headers.get("Content-Length", 0) or 0)
        _body = self.rfile.read(length) if length else b""  # drained, not otherwise used

        result = asyncio.run(
            limiter.check(headers=headers, direct_ip=direct_ip, endpoint=self.path)
        )

        if not result.allowed:
            self._respond(
                420,
                "Enhance Your Calm",
                result.headers(),
                {
                    "error": "rate_limited",
                    "message": "Enhance Your Calm",
                    "layer": result.layer.value if result.layer else None,
                    "retry_after": result.retry_after,
                },
            )
            return

        self._respond(
            200,
            "OK",
            result.headers(),
            {"ok": True, "path": self.path, "method": method},
        )

    def _respond(self, status: int, reason: str, extra_headers: dict, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status, reason)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"fastapi_420 demo app listening on http://{HOST}:{PORT}")
    print()
    print("Try:")
    print(f'  curl -i http://{HOST}:{PORT}/auth/login -X POST -d "username=test&password=test"')
    print("  (repeat 4x -- the 4th response is HTTP/1.1 420 Enhance Your Calm)")
    print()
    print(f"  curl -i http://{HOST}:{PORT}/api/data")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
