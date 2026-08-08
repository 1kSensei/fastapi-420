"""FastAPI dependency-injection style helper (optional extra).

For apps that want a stricter, route-specific limit (e.g. 3/min on
`/auth/login`) layered on top of — or instead of — the global
middleware. Requires FastAPI to be installed; the import is deferred
into the returned dependency function so importing this module never
requires FastAPI itself.

    from fastapi import FastAPI, Depends
    from fastapi_420 import RateLimiter, RateLimiterConfig, LimitRule

    app = FastAPI()
    login_limiter = RateLimiter(RateLimiterConfig(
        user_limit=LimitRule(limit=3, window_seconds=60),
        endpoint_limit=None, global_limit=None,
    ))
    login_limit = rate_limit_dependency(login_limiter, "auth_login")

    @app.post("/auth/login", dependencies=[Depends(login_limit)])
    async def login(...): ...
"""
from __future__ import annotations

from typing import Any, Callable

from .limiter import RateLimiter
from .types import RateLimitResult


def rate_limit_dependency(limiter: RateLimiter, endpoint_name: str) -> Callable[..., Any]:
    async def dependency(request: Any) -> RateLimitResult:
        try:
            from fastapi import HTTPException
        except ImportError as exc:
            raise ImportError("rate_limit_dependency requires FastAPI: pip install fastapi") from exc

        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in request.scope.get("headers", [])}
        client = request.client
        direct_ip = client.host if client else "0.0.0.0"
        result = await limiter.check(headers=headers, direct_ip=direct_ip, endpoint=endpoint_name)
        if not result.allowed:
            raise HTTPException(status_code=420, detail="Enhance Your Calm", headers=result.headers())
        return result

    return dependency
