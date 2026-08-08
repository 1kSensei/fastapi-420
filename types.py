"""Shared types and enums for fastapi_420.

This module has zero dependencies outside the standard library, on
purpose: it's imported by every other module in the package, and the
package as a whole is designed to work with nothing installed beyond
Python itself (Redis and FastAPI integrations are optional extras,
imported lazily where they're actually used).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple


class Algorithm(str, Enum):
    """Supported rate limiting algorithms."""

    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    FIXED_WINDOW = "fixed_window"


class Layer(str, Enum):
    """Defense layers, checked in this order (most specific first)."""

    USER = "user"
    ENDPOINT = "endpoint"
    GLOBAL = "global"


@dataclass(frozen=True)
class LimitRule:
    """A single rate limit: `limit` requests per `window_seconds`.

    For TOKEN_BUCKET, `limit`/`window_seconds` sets the steady-state
    refill rate and `burst` (default: `limit`) sets bucket capacity —
    i.e. how far a client can burst above the steady-state rate.
    """

    limit: int
    window_seconds: float
    algorithm: Algorithm = Algorithm.SLIDING_WINDOW
    burst: Optional[int] = None

    def __post_init__(self) -> None:
        if self.limit <= 0:
            raise ValueError("limit must be positive")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.burst is not None and self.burst <= 0:
            raise ValueError("burst must be positive")


@dataclass
class RateLimitResult:
    """Outcome of a single rate limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset_at: float  # unix timestamp
    retry_after: Optional[float] = None
    layer: Optional[Layer] = None
    algorithm: Optional[Algorithm] = None

    def headers(self) -> Dict[str, str]:
        h = {
            "RateLimit-Limit": str(self.limit),
            "RateLimit-Remaining": str(max(0, self.remaining)),
            "RateLimit-Reset": str(int(self.reset_at)),
        }
        if not self.allowed and self.retry_after is not None:
            h["Retry-After"] = str(max(1, int(self.retry_after) + 1))
        return h


@dataclass
class Fingerprint:
    """A composite client identity used as the rate-limit key.

    `source` records *why* this fingerprint was built the way it was,
    which is useful in logs/metrics when tuning limits: "identity"
    means an authenticated user got their own bucket; "ip" means we
    fell back to network-level identification for an anonymous client.
    """

    ip: str
    identity: Optional[str] = None
    user_agent_hash: Optional[str] = None
    source: str = "ip"  # "identity" | "ip"

    def key(self) -> str:
        if self.identity:
            return f"{self.source}:{self.identity}"
        return f"ip:{self.ip}"
