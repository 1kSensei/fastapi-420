"""Token bucket.

A bucket holds up to `capacity` tokens and refills continuously at
`refill_rate` tokens/second (computed as `rule.limit / rule.window_seconds`).
Each request costs one token; refill and consumption happen in the
same atomic update, so the bucket's state (tokens, last_refill_time)
is always read, advanced to "now", and re-checked as one step —
there's no separate background refill process to fall out of sync.

Unlike the window algorithms, this naturally tolerates short bursts up
to `capacity` while still enforcing a strict long-run average rate,
which suits clients that legitimately batch work (e.g. a mobile app
syncing everything on reconnect) better than a hard per-window cutoff.

`rule.burst` (default: `rule.limit`) sets bucket capacity independent
of the refill rate — e.g. `LimitRule(limit=10, window_seconds=1, burst=50)`
allows bursts of 50 while averaging out to 10 req/s over time.
"""
from __future__ import annotations

import time

from ..types import Algorithm, LimitRule, RateLimitResult
from .base import RateLimitAlgorithm


class TokenBucketAlgorithm(RateLimitAlgorithm):
    name = Algorithm.TOKEN_BUCKET

    async def check(self, key: str, rule: LimitRule) -> RateLimitResult:
        now = time.time()
        capacity = float(rule.burst or rule.limit)
        refill_rate = rule.limit / rule.window_seconds  # tokens per second
        storage_key = f"tb:{key}"

        def updater(current):
            if current is None:
                tokens, last_refill = capacity, now
            else:
                tokens, last_refill = current

            elapsed = max(0.0, now - last_refill)
            tokens = min(capacity, tokens + elapsed * refill_rate)

            if tokens >= 1.0:
                tokens -= 1.0
                allowed = True
            else:
                allowed = False

            return (tokens, now), (allowed, tokens)

        # ttl generous enough that an idle bucket doesn't vanish (and
        # thus "refill to full") faster than it would drain naturally.
        ttl = max(rule.window_seconds * 4, capacity / max(refill_rate, 1e-9))
        allowed, tokens_remaining = await self.storage.atomic_update(storage_key, updater, ttl=ttl)

        if allowed:
            retry_after = None
        else:
            retry_after = max(0.0, (1.0 - tokens_remaining) / refill_rate)

        return RateLimitResult(
            allowed=allowed,
            limit=int(capacity),
            remaining=int(tokens_remaining),
            reset_at=now + (capacity - tokens_remaining) / refill_rate,
            retry_after=retry_after,
            algorithm=self.name,
        )
