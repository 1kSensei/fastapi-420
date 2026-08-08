import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fastapi_420.algorithms.sliding_window import SlidingWindowAlgorithm
from fastapi_420.defense.circuit_breaker import BreakerState, CircuitBreaker
from fastapi_420.defense.layers import LayerConfig, ThreeLayerDefense
from fastapi_420.storage.memory import MemoryStorage
from fastapi_420.types import Layer, LimitRule


class CircuitBreakerTests(unittest.TestCase):
    def test_starts_closed(self):
        cb = CircuitBreaker(threshold=5)
        self.assertEqual(cb.state, BreakerState.CLOSED)
        self.assertFalse(cb.should_short_circuit())

    def test_trips_after_threshold_rejections(self):
        cb = CircuitBreaker(threshold=5, window_seconds=60)
        for _ in range(5):
            cb.record_rejection()
        self.assertEqual(cb.state, BreakerState.OPEN)
        self.assertTrue(cb.should_short_circuit())

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker(threshold=5, window_seconds=60)
        for _ in range(4):
            cb.record_rejection()
        self.assertEqual(cb.state, BreakerState.CLOSED)

    def test_half_open_transition_after_cooldown(self):
        cb = CircuitBreaker(threshold=1, window_seconds=60, cooldown_seconds=0.05)
        cb.record_rejection()
        self.assertEqual(cb.state, BreakerState.OPEN)
        import time

        time.sleep(0.06)
        self.assertEqual(cb.state, BreakerState.HALF_OPEN)

    def test_half_open_closes_on_success(self):
        cb = CircuitBreaker(threshold=1, window_seconds=60, cooldown_seconds=0.01)
        cb.record_rejection()
        import time

        time.sleep(0.02)
        _ = cb.state  # trigger OPEN -> HALF_OPEN transition
        cb.record_success()
        self.assertEqual(cb.state, BreakerState.CLOSED)


class ThreeLayerDefenseTests(unittest.IsolatedAsyncioTestCase):
    async def test_user_layer_blocks_before_global(self):
        algo = SlidingWindowAlgorithm(MemoryStorage())
        config = LayerConfig(
            user=LimitRule(limit=1, window_seconds=60),
            endpoint=None,
            global_=LimitRule(limit=1000, window_seconds=60),
        )
        defense = ThreeLayerDefense(algo, config)

        first = await defense.check("client-a", "/api")
        second = await defense.check("client-a", "/api")

        self.assertTrue(first.allowed)
        self.assertFalse(second.allowed)
        self.assertEqual(second.layer, Layer.USER)

    async def test_different_users_do_not_interfere(self):
        algo = SlidingWindowAlgorithm(MemoryStorage())
        config = LayerConfig(user=LimitRule(limit=1, window_seconds=60))
        defense = ThreeLayerDefense(algo, config)

        a = await defense.check("client-a", "/api")
        b = await defense.check("client-b", "/api")
        self.assertTrue(a.allowed)
        self.assertTrue(b.allowed)

    async def test_endpoint_layer_isolates_per_route(self):
        algo = SlidingWindowAlgorithm(MemoryStorage())
        config = LayerConfig(
            user=None,
            endpoint=LimitRule(limit=1, window_seconds=60),
            global_=None,
        )
        defense = ThreeLayerDefense(algo, config)

        login1 = await defense.check("client-a", "/auth/login")
        login2 = await defense.check("client-a", "/auth/login")
        data1 = await defense.check("client-a", "/api/data")

        self.assertTrue(login1.allowed)
        self.assertFalse(login2.allowed)
        self.assertTrue(data1.allowed)  # different endpoint, own bucket

    async def test_breaker_trips_and_short_circuits_globally(self):
        algo = SlidingWindowAlgorithm(MemoryStorage())
        config = LayerConfig(user=LimitRule(limit=1, window_seconds=60))
        breaker = CircuitBreaker(threshold=3, window_seconds=60, cooldown_seconds=60)
        defense = ThreeLayerDefense(algo, config, circuit_breaker=breaker)

        # Exhaust 3 different users' single-request quotas to accumulate rejections.
        for client in ["c1", "c1", "c2", "c2", "c3", "c3"]:
            await defense.check(client, "/api")

        self.assertEqual(breaker.state, BreakerState.OPEN)

        # Now even a brand-new, never-before-seen client is short-circuited.
        result = await defense.check("brand-new-client", "/api")
        self.assertFalse(result.allowed)
        self.assertEqual(result.layer, Layer.GLOBAL)


if __name__ == "__main__":
    unittest.main()
