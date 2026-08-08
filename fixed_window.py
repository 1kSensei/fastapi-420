"""Fixed window counter.

Simplest algorithm: divide time into fixed-size buckets aligned to
epoch (`window_id = floor(now / window_seconds)`) and count requests
per bucket. O(1) memory and time per key.

Boundary exploit: a client can send `limit` requests in the last
instant of one window and `limit` more in the first instant of the
next, getting up to 2x the limit through in a moment straddling the
boundary. Fine for coarse, cheap protection (e.g. a generous global
ceiling); use SlidingWindowAlgorithm wherever that burst matters.
"""
from __future__ import annotations

import time

from ..types import Algorithm, LimitRule, RateLimitResult
from .base import RateLimitAlgorithm


class FixedWindowAlgorithm(RateLimitAlgorithm):
    name = Algorithm.FIXED_WINDOW

    async def check(self, key: str, rule: LimitRule) -> RateLimitResult:
        now = time.time()
        window_id = int(now // rule.window_seconds)
        storage_key = f"fw:{key}:{window_id}"
        window_reset = (window_id + 1) * rule.window_seconds

        def updater(current):
            count = (current or 0) + 1
            return count, count

        count = await self.storage.atomic_update(storage_key, updater, ttl=rule.window_seconds)
        allowed = count <= rule.limit

        return RateLimitResult(
            allowed=allowed,
            limit=rule.limit,
            remaining=max(0, rule.limit - count),
            reset_at=window_reset,
            retry_after=None if allowed else window_reset - now,
            algorithm=self.name,
        )
