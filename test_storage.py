import asyncio
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fastapi_420.storage.memory import MemoryStorage


class MemoryStorageTests(unittest.IsolatedAsyncioTestCase):
    async def test_get_missing_key_returns_none(self):
        store = MemoryStorage()
        self.assertIsNone(await store.get("nope"))

    async def test_atomic_update_roundtrip(self):
        store = MemoryStorage()

        def incr(current):
            new = (current or 0) + 1
            return new, new

        r1 = await store.atomic_update("k", incr)
        r2 = await store.atomic_update("k", incr)
        self.assertEqual((r1, r2), (1, 2))
        self.assertEqual(await store.get("k"), 2)

    async def test_ttl_expiry(self):
        store = MemoryStorage()
        await store.atomic_update("k", lambda c: (1, 1), ttl=0.05)
        self.assertEqual(await store.get("k"), 1)
        await asyncio.sleep(0.08)
        self.assertIsNone(await store.get("k"))

    async def test_concurrent_updates_are_serialized(self):
        # 100 coroutines incrementing the same counter concurrently must
        # produce exactly 100 -- if the lock were missing, interleaved
        # read-modify-write cycles would lose updates.
        store = MemoryStorage()

        def incr(current):
            new = (current or 0) + 1
            return new, new

        async def bump():
            await store.atomic_update("shared", incr)

        await asyncio.gather(*(bump() for _ in range(100)))
        self.assertEqual(await store.get("shared"), 100)

    async def test_sweep_evicts_expired_keys(self):
        store = MemoryStorage()
        store._sweep_interval = 0.0  # force sweep to run on next write
        await store.atomic_update("a", lambda c: (1, 1), ttl=0.01)
        await asyncio.sleep(0.02)
        await store.atomic_update("b", lambda c: (1, 1))  # triggers sweep
        self.assertNotIn("a", store._data)


if __name__ == "__main__":
    unittest.main()
