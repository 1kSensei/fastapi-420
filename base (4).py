"""Common interface every rate limiting algorithm implements."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..storage.base import StorageBackend
from ..types import Algorithm, LimitRule, RateLimitResult


class RateLimitAlgorithm(ABC):
    name: Algorithm

    def __init__(self, storage: StorageBackend) -> None:
        self.storage = storage

    @abstractmethod
    async def check(self, key: str, rule: LimitRule) -> RateLimitResult:
        """Consume one unit of `key`'s quota under `rule` and report the outcome.

        Implementations must treat this as "attempt to consume" — even
        a rejected request is recorded, so a client hammering a
        blocked endpoint doesn't get a free retry-without-cost loop.
        """
