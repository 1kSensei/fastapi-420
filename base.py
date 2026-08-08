"""Abstract storage backend interface.

Every algorithm talks to storage through a single primitive,
`atomic_update`: read the current value of `key` (or None if it's
missing/expired), pass it to `updater`, and durably store whatever
`updater` returns as the new value — all as one indivisible operation.

That's the whole correctness contract. `MemoryStorage` satisfies it
with an `asyncio.Lock`; `RedisStorage` satisfies it with WATCH/MULTI
(generic path) or a purpose-built Lua script (fast path, used by the
algorithms that ship one) so two processes racing to update the same
counter can never both read-then-write past a limit.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional, Tuple

# updater(old_value_or_None) -> (new_value_to_store, value_to_return)
Updater = Callable[[Optional[Any]], Tuple[Any, Any]]


class StorageBackend(ABC):
    @abstractmethod
    async def atomic_update(
        self, key: str, updater: Updater, ttl: Optional[float] = None
    ) -> Any:
        """Atomically read-modify-write `key`. See module docstring."""

    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Read `key` without modifying it. Returns None if absent/expired."""

    @abstractmethod
    async def close(self) -> None:
        """Release any underlying connections/resources."""
