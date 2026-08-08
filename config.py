"""Settings for fastapi_420.

A plain dataclass instead of pydantic-settings, so the core library
stays dependency-free — `from_env()` gives the same 12-factor-app
ergonomics (read config from environment variables) without requiring
pydantic to be installed. If you have pydantic-settings in your app
already, wrapping this in a BaseSettings subclass is a few lines; it's
not required.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .types import Algorithm, LimitRule


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class RateLimiterConfig:
    # Storage
    redis_url: Optional[str] = None
    fallback_to_memory: bool = True

    # Fingerprinting
    trust_x_forwarded_for: bool = False
    trusted_proxies: Tuple[str, ...] = ()
    api_key_header: str = "x-api-key"

    # Algorithm
    algorithm: Algorithm = Algorithm.SLIDING_WINDOW

    # Three-layer defense — any of these may be None to disable that layer
    user_limit: Optional[LimitRule] = field(
        default_factory=lambda: LimitRule(limit=100, window_seconds=60)
    )
    endpoint_limit: Optional[LimitRule] = None
    global_limit: Optional[LimitRule] = field(
        default_factory=lambda: LimitRule(limit=10_000, window_seconds=10)
    )

    # Circuit breaker
    circuit_threshold: int = 1000
    circuit_window_seconds: float = 10.0
    circuit_cooldown_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> "RateLimiterConfig":
        return cls(
            redis_url=os.environ.get("REDIS_URL"),
            fallback_to_memory=_bool_env("FALLBACK_TO_MEMORY", True),
            trust_x_forwarded_for=_bool_env("TRUST_X_FORWARDED_FOR", False),
            circuit_threshold=int(os.environ.get("CIRCUIT_THRESHOLD", "1000")),
        )
