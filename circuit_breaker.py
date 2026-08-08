"""Circuit breaker for global DDoS protection.

Independent of any single client's limit: this watches the *aggregate*
rejection rate across every client. A spike in individual users
hitting their own limits is normal background noise; a spike that
crosses `threshold` rejections within `window_seconds` is a much
stronger signal of a coordinated flood, and is treated differently —
the breaker OPENs and the global layer short-circuits to "deny
everything" for `cooldown_seconds`. That trades a worse experience for
everyone during the outage for shedding load fast: during an actual
volumetric attack, running the full fingerprint + per-client algorithm
pipeline on every single request is itself a resource drain worth
skipping.

After `cooldown_seconds`, the breaker goes HALF_OPEN and lets a small
probe fraction of traffic through for real; if that traffic looks
healthy (`record_success`), it closes again — otherwise it stays
tripped and keeps shedding load.
"""
from __future__ import annotations

import time
from enum import Enum
from typing import List


class BreakerState(str, Enum):
    CLOSED = "closed"  # normal operation
    OPEN = "open"  # tripped, shedding load
    HALF_OPEN = "half_open"  # cooldown elapsed, testing recovery


class CircuitBreaker:
    def __init__(
        self,
        threshold: int = 1000,
        window_seconds: float = 10.0,
        cooldown_seconds: float = 30.0,
        half_open_probe_rate: float = 0.05,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.half_open_probe_rate = half_open_probe_rate

        self._state = BreakerState.CLOSED
        self._rejections: List[float] = []
        self._opened_at = 0.0
        self._probe_counter = 0

    @property
    def state(self) -> BreakerState:
        if self._state == BreakerState.OPEN and time.time() - self._opened_at >= self.cooldown_seconds:
            self._state = BreakerState.HALF_OPEN
        return self._state

    def record_rejection(self) -> None:
        now = time.time()
        self._rejections.append(now)
        cutoff = now - self.window_seconds
        self._rejections = [t for t in self._rejections if t >= cutoff]
        if self._state == BreakerState.CLOSED and len(self._rejections) >= self.threshold:
            self._trip()

    def record_success(self) -> None:
        if self._state == BreakerState.HALF_OPEN:
            self._state = BreakerState.CLOSED
            self._rejections.clear()

    def _trip(self) -> None:
        self._state = BreakerState.OPEN
        self._opened_at = time.time()

    def allow_probe(self) -> bool:
        """HALF_OPEN only: let roughly `half_open_probe_rate` of traffic through."""
        self._probe_counter += 1
        interval = max(1, round(1 / self.half_open_probe_rate))
        return self._probe_counter % interval == 0

    def should_short_circuit(self) -> bool:
        current = self.state
        if current == BreakerState.CLOSED:
            return False
        if current == BreakerState.OPEN:
            return True
        return not self.allow_probe()  # HALF_OPEN: deny unless this is a probe
