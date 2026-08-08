"""fastapi_420 — production-style rate limiting library.

Three algorithms (sliding window, token bucket, fixed window), a
three-layer defense system (per-user, per-endpoint, global + circuit
breaker), and composite client fingerprinting (IP incl. IPv6 /64
normalization, headers, JWT/API-key/session identity).

The core package (this import) has zero third-party dependencies.
Redis-backed storage and the FastAPI dependency helper are optional
extras that import their requirement lazily, only when you actually
construct them — see storage.redis_backend and dependencies.
"""
from .config import RateLimiterConfig
from .limiter import RateLimiter
from .middleware import RateLimitMiddleware
from .types import Algorithm, Fingerprint, Layer, LimitRule, RateLimitResult

__all__ = [
    "RateLimiter",
    "RateLimiterConfig",
    "RateLimitMiddleware",
    "Algorithm",
    "Layer",
    "LimitRule",
    "RateLimitResult",
    "Fingerprint",
]

__version__ = "1.0.0"
