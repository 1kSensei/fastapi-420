import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fastapi_420.algorithms.fixed_window import FixedWindowAlgorithm
from fastapi_420.algorithms.sliding_window import SlidingWindowAlgorithm
from fastapi_420.algorithms.token_bucket import TokenBucketAlgorithm
from fastapi_420.storage.memory import MemoryStorage
from fastapi_420.types import LimitRule


class FixedWindowTests(unittest.IsolatedAsyncioTestCase):
    async def test_allows_up_to_limit_then_blocks(self):
        algo = FixedWindowAlgorithm(MemoryStorage())
        rule = LimitRule(limit=3, window_seconds=60)
        results = [await algo.check("client-a", rule) for _ in range(5)]
        self.assertEqual([r.allowed for r in results], [True, True, True, False, False])
        self.assertEqual(results[-1].remaining, 0)
        self.assertIsNotNone(results[-1].retry_after)

    async def test_separate_keys_are_independent(self):
        algo = FixedWindowAlgorithm(MemoryStorage())
        rule = LimitRule(limit=1, window_seconds=60)
        a = await algo.check("client-a", rule)
        b = await algo.check("client-b", rule)
        self.assertTrue(a.allowed)
        self.assertTrue(b.allowed)

    async def test_boundary_exploit_is_reproducible(self):
        # Demonstrates the documented weakness: two requests placed on
        # either side of a window boundary can both succeed even
        # though they land within a fraction of a second of each other.
        algo = FixedWindowAlgorithm(MemoryStorage())
        rule = LimitRule(limit=1, window_seconds=0.2)
        first = await algo.check("client-a", rule)
        self.assertTrue(first.allowed)
        await asyncio.sleep(0.21)  # cross into the next window
        second = await algo.check("client-a", rule)
        self.assertTrue(second.allowed)  # 2 requests allowed within ~0.21s under a limit of 1/0.2s


class SlidingWindowTests(unittest.IsolatedAsyncioTestCase):
    async def test_allows_up_to_limit_then_blocks(self):
        algo = SlidingWindowAlgorithm(MemoryStorage())
        rule = LimitRule(limit=3, window_seconds=60)
        results = [await algo.check("client-a", rule) for _ in range(5)]
        self.assertEqual([r.allowed for r in results], [True, True, True, False, False])

    async def test_smooths_the_fixed_window_boundary_exploit(self):
        # Same shape as the fixed-window boundary test, but the weighted
        # estimate should catch the burst instead of letting it through.
        algo = SlidingWindowAlgorithm(MemoryStorage())
        rule = LimitRule(limit=1, window_seconds=0.3)
        first = await algo.check("client-a", rule)
        self.assertTrue(first.allowed)
        await asyncio.sleep(0.31)  # just past the boundary; overlap should still be high
        second = await algo.check("client-a", rule)
        self.assertFalse(second.allowed)


class TokenBucketTests(unittest.IsolatedAsyncioTestCase):
    async def test_allows_burst_up_to_capacity(self):
        algo = TokenBucketAlgorithm(MemoryStorage())
        rule = LimitRule(limit=10, window_seconds=10, burst=5)  # capacity=5
        results = [await algo.check("client-a", rule) for _ in range(6)]
        self.assertEqual([r.allowed for r in results], [True, True, True, True, True, False])

    async def test_refills_over_time(self):
        algo = TokenBucketAlgorithm(MemoryStorage())
        # capacity 1, refills at 1/0.1s = 10 tokens/sec
        rule = LimitRule(limit=1, window_seconds=0.1, burst=1)
        first = await algo.check("client-a", rule)
        self.assertTrue(first.allowed)
        second = await algo.check("client-a", rule)
        self.assertFalse(second.allowed)
        await asyncio.sleep(0.15)
        third = await algo.check("client-a", rule)
        self.assertTrue(third.allowed)


if __name__ == "__main__":
    unittest.main()
