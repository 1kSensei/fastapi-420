"""Sliding window counter (weighted average of two fixed windows).

Approximates a true sliding-window log using O(1) memory per key
instead of O(limit) — this is the algorithm behind Cloudflare's public
rate-limiting writeups, with a quoted worst-case error around 0.003%
against a true log-based sliding window (hence "99.997% accuracy").

    estimate = current_count + previous_count * overlap
    overlap  = (window_seconds - elapsed_in_current_window) / window_seconds

Intuition: `overlap` is the fraction of the *previous* window that
still falls inside a `window_seconds`-wide sliding view ending right
now. Early in the current window, overlap is close to 1 (most of a
true sliding window is still "borrowed" from the previous bucket);
late in the current window, overlap approaches 0 (the previous bucket
has almost entirely aged out). This closes the fixed-window boundary
exploit: a burst straddling the boundary shows up as a high count in
*both* buckets, and the weighted estimate catches it even though
neither bucket alone exceeds the limit.
"""
from __future__ import annotations

import time

from ..types import Algorithm, LimitRule, RateLimitResult
from .base import RateLimitAlgorithm


class SlidingWindowAlgorithm(RateLimitAlgorithm):
    name = Algorithm.SLIDING_WINDOW

    async def check(self, key: str, rule: LimitRule) -> RateLimitResult:
        now = time.time()
        window_id = int(now // rule.window_seconds)
        elapsed = now - window_id * rule.window_seconds
        overlap = max(0.0, (rule.window_seconds - elapsed) / rule.window_seconds)

        curr_key = f"sw:{key}:{window_id}"
        prev_key = f"sw:{key}:{window_id - 1}"

        previous = await self.storage.get(prev_key) or 0

        def updater(current):
            count = (current or 0) + 1
            return count, count

        # ttl = 2 windows: a bucket must survive long enough to still
        # be readable as "previous" for the entirety of the next window.
        current = await self.storage.atomic_update(curr_key, updater, ttl=rule.window_seconds * 2)

        estimate = current + previous * overlap
        allowed = estimate <= rule.limit
        reset_at = (window_id + 1) * rule.window_seconds

        return RateLimitResult(
            allowed=allowed,
            limit=rule.limit,
            remaining=max(0, int(rule.limit - estimate)),
            reset_at=reset_at,
            retry_after=None if allowed else reset_at - now,
            algorithm=self.name,
        )
