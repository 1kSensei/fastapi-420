"""Three-layer defense: per-user, then per-endpoint, then global.

Checked in that order — most specific first — for two reasons: it's
the cheapest useful check to run first (a single abusive client should
never need a global-scope check to catch), and it produces the most
actionable response. Telling one client "you're over your limit" is
far more useful than telling everyone "the whole API is under load"
when the real cause is one misbehaving script.

Any layer configured as `None` is skipped entirely — e.g. an app with
no per-endpoint tiers just sets `endpoint=None` and only pays for the
user + global checks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..algorithms.base import RateLimitAlgorithm
from ..types import Layer, LimitRule, RateLimitResult
from .circuit_breaker import CircuitBreaker


@dataclass
class LayerConfig:
    user: Optional[LimitRule] = None
    endpoint: Optional[LimitRule] = None
    global_: Optional[LimitRule] = None


class ThreeLayerDefense:
    def __init__(
        self,
        algorithm: RateLimitAlgorithm,
        config: LayerConfig,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ) -> None:
        self.algorithm = algorithm
        self.config = config
        self.breaker = circuit_breaker or CircuitBreaker()

    async def check(self, client_key: str, endpoint_key: str) -> RateLimitResult:
        if self.breaker.should_short_circuit():
            return RateLimitResult(
                allowed=False,
                limit=0,
                remaining=0,
                reset_at=0.0,
                retry_after=self.breaker.cooldown_seconds,
                layer=Layer.GLOBAL,
            )

        checks: List[Tuple[Layer, str, LimitRule]] = []
        if self.config.user:
            checks.append((Layer.USER, f"user:{client_key}", self.config.user))
        if self.config.endpoint:
            checks.append((Layer.ENDPOINT, f"endpoint:{endpoint_key}:{client_key}", self.config.endpoint))
        if self.config.global_:
            checks.append((Layer.GLOBAL, "global", self.config.global_))

        tightest: Optional[RateLimitResult] = None
        for layer, key, rule in checks:
            result = await self.algorithm.check(key, rule)
            result.layer = layer
            if not result.allowed:
                self.breaker.record_rejection()
                return result
            if tightest is None or result.remaining < tightest.remaining:
                tightest = result

        self.breaker.record_success()
        return tightest or RateLimitResult(allowed=True, limit=0, remaining=0, reset_at=0.0)
