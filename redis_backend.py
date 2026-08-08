"""Redis storage backend — distributed, atomic via Lua scripts.

Requires the `redis` package (`pip install "redis>=4.2"` for the
built-in asyncio client). The import is deferred into `__init__` so
importing `fastapi_420` — or even constructing `MemoryStorage` — never
requires Redis to be installed. `RateLimiter._build_storage()` catches
the resulting ImportError and falls back to MemoryStorage when
`FALLBACK_TO_MEMORY=True` (the default).

Two code paths:

  * `run_script` — for algorithms that ship a purpose-built Lua script
    (see storage/lua/*.lua), giving true single-round-trip atomicity.
  * `atomic_update` — a generic WATCH/MULTI/EXEC fallback, satisfying
    the same StorageBackend contract for anything that *doesn't* have
    a bespoke script. Slower (optimistic-locking retry loop) but
    correct, and keeps RedisStorage a drop-in replacement for
    MemoryStorage without every algorithm needing Redis-specific code.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import StorageBackend, Updater

_LUA_DIR = Path(__file__).parent / "lua"


class RedisStorage(StorageBackend):
    def __init__(self, url: str = "redis://localhost:6379") -> None:
        try:
            import redis.asyncio as redis  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "RedisStorage requires the 'redis' package: pip install \"redis>=4.2\""
            ) from exc
        self._redis_module = redis
        self._client = redis.from_url(url, decode_responses=True)
        self._scripts: Dict[str, Any] = {}

    async def run_script(self, name: str, keys: List[str], args: List[Any]) -> Any:
        """Run (and cache) a named Lua script from storage/lua/<name>.lua."""
        script = self._scripts.get(name)
        if script is None:
            source = (_LUA_DIR / f"{name}.lua").read_text()
            script = self._client.register_script(source)
            self._scripts[name] = script
        return await script(keys=keys, args=args)

    async def atomic_update(
        self, key: str, updater: Updater, ttl: Optional[float] = None
    ) -> Any:
        async with self._client.pipeline(transaction=True) as pipe:
            while True:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    current = json.loads(raw) if raw else None
                    new_value, result = updater(current)
                    pipe.multi()
                    pipe.set(key, json.dumps(new_value), ex=int(ttl) if ttl else None)
                    await pipe.execute()
                    return result
                except self._redis_module.WatchError:
                    continue  # another process won the race; retry with fresh data

    async def get(self, key: str) -> Optional[Any]:
        raw = await self._client.get(key)
        return json.loads(raw) if raw else None

    async def close(self) -> None:
        await self._client.aclose()
