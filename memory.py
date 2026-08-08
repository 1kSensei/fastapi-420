"""In-memory storage backend.

Correct within a single process (one asyncio event loop). The lock
exists because Python's `await` can suspend a coroutine mid-update —
without it, two concurrent requests for the same key could both read
the same starting value before either writes back, silently letting
more requests through than the limit allows. CPython's GIL prevents
*byte-code level* races but does nothing about races across `await`
points, which is exactly where the interesting concurrency lives here.

Single process only: if you run multiple worker processes (gunicorn
-w 4, multiple pods, ...) each gets its own independent counters and
the *effective* limit becomes `configured_limit * process_count`. Use
RedisStorage when that matters.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, Optional, Tuple

from .base import StorageBackend, Updater


class MemoryStorage(StorageBackend):
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[Any, Optional[float]]] = {}
        self._lock = asyncio.Lock()
        self._last_sweep = time.monotonic()
        self._sweep_interval = 5.0

    def _read_unlocked(self, key: str) -> Optional[Any]:
        entry = self._data.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at is not None and expires_at <= time.time():
            del self._data[key]
            return None
        return value

    async def atomic_update(
        self, key: str, updater: Updater, ttl: Optional[float] = None
    ) -> Any:
        async with self._lock:
            current = self._read_unlocked(key)
            new_value, result = updater(current)
            expires_at = time.time() + ttl if ttl else None
            self._data[key] = (new_value, expires_at)
            self._maybe_sweep()
            return result

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            return self._read_unlocked(key)

    def _maybe_sweep(self) -> None:
        # Evict expired keys periodically rather than on every write —
        # keeps the common-case write O(1) instead of O(n) per call.
        now_mono = time.monotonic()
        if now_mono - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now_mono
        now = time.time()
        expired = [k for k, (_, exp) in self._data.items() if exp is not None and exp <= now]
        for k in expired:
            del self._data[k]

    async def close(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)
