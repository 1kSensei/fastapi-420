"""RateLimiter — the public entry point wiring everything together.

    limiter = RateLimiter(RateLimiterConfig(
        algorithm=Algorithm.SLIDING_WINDOW,
        user_limit=LimitRule(limit=100, window_seconds=60),
    ))
    result = await limiter.check(headers=request_headers, direct_ip=peer_ip, endpoint="/api/data")
    if not result.allowed:
        ...  # 420, with result.headers() attached
"""
from __future__ import annotations

import logging
from typing import Dict, Mapping, Optional, Type

from .algorithms.base import RateLimitAlgorithm
from .algorithms.fixed_window import FixedWindowAlgorithm
from .algorithms.sliding_window import SlidingWindowAlgorithm
from .algorithms.token_bucket import TokenBucketAlgorithm
from .config import RateLimiterConfig
from .defense.circuit_breaker import CircuitBreaker
from .defense.layers import LayerConfig, ThreeLayerDefense
from .fingerprinting.composite import build_fingerprint
from .storage.base import StorageBackend
from .storage.memory import MemoryStorage
from .types import Algorithm, RateLimitResult

logger = logging.getLogger("fastapi_420")

_ALGORITHMS: Dict[Algorithm, Type[RateLimitAlgorithm]] = {
    Algorithm.FIXED_WINDOW: FixedWindowAlgorithm,
    Algorithm.SLIDING_WINDOW: SlidingWindowAlgorithm,
    Algorithm.TOKEN_BUCKET: TokenBucketAlgorithm,
}


class RateLimiter:
    def __init__(
        self,
        config: Optional[RateLimiterConfig] = None,
        storage: Optional[StorageBackend] = None,
    ) -> None:
        self.config = config or RateLimiterConfig()
        self.storage = storage or self._build_storage()
        algo_cls = _ALGORITHMS[self.config.algorithm]
        self.algorithm: RateLimitAlgorithm = algo_cls(self.storage)
        self.defense = ThreeLayerDefense(
            algorithm=self.algorithm,
            config=LayerConfig(
                user=self.config.user_limit,
                endpoint=self.config.endpoint_limit,
                global_=self.config.global_limit,
            ),
            circuit_breaker=CircuitBreaker(
                threshold=self.config.circuit_threshold,
                window_seconds=self.config.circuit_window_seconds,
                cooldown_seconds=self.config.circuit_cooldown_seconds,
            ),
        )

    def _build_storage(self) -> StorageBackend:
        if self.config.redis_url:
            try:
                from .storage.redis_backend import RedisStorage

                return RedisStorage(self.config.redis_url)
            except ImportError:
                if not self.config.fallback_to_memory:
                    raise
                logger.warning(
                    "REDIS_URL is set but the 'redis' package isn't installed; falling back "
                    "to in-memory storage (FALLBACK_TO_MEMORY=True). Limits will NOT be shared "
                    "across processes until 'redis' is installed."
                )
        return MemoryStorage()

    async def check(self, headers: Mapping[str, str], direct_ip: str, endpoint: str) -> RateLimitResult:
        fp = build_fingerprint(
            headers=headers,
            direct_ip=direct_ip,
            trust_x_forwarded_for=self.config.trust_x_forwarded_for,
            trusted_proxies=self.config.trusted_proxies,
            api_key_header=self.config.api_key_header,
        )
        return await self.defense.check(client_key=fp.key(), endpoint_key=endpoint)

    async def close(self) -> None:
        await self.storage.close()
