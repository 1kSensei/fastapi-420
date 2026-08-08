#!/usr/bin/env python3
"""fastapi_420 demo — no server, no network, no dependencies.

Walks through the pieces of the library end to end:

  1. Algorithms: the fixed-window boundary exploit, and how sliding
     window / token bucket each handle the same traffic pattern.
  2. Three-layer defense: per-user isolation, per-endpoint isolation.
  3. Circuit breaker: what happens under a simulated flood, and how
     the breaker recovers afterwards.
  4. Fingerprinting: IPv6 /64 collapsing, X-Forwarded-For spoofing
     resistance, and JWT-based identity extraction.

Run with:  uv run python examples/demo.py
       or: python3 examples/demo.py   (from the project root)
"""
from __future__ import annotations

import asyncio
import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fastapi_420 import Algorithm, LimitRule, RateLimiterConfig
from fastapi_420.algorithms.fixed_window import FixedWindowAlgorithm
from fastapi_420.algorithms.sliding_window import SlidingWindowAlgorithm
from fastapi_420.algorithms.token_bucket import TokenBucketAlgorithm
from fastapi_420.defense.circuit_breaker import CircuitBreaker
from fastapi_420.defense.layers import LayerConfig, ThreeLayerDefense
from fastapi_420.fingerprinting.auth import extract_identity
from fastapi_420.fingerprinting.ip import extract_client_ip, fingerprint_key
from fastapi_420.storage.memory import MemoryStorage


def header(title: str) -> None:
    print(f"\n{'=' * 70}\n {title}\n{'=' * 70}")


def row(*cols, widths=(24, 10, 12, 24)) -> None:
    print("".join(str(c).ljust(w) for c, w in zip(cols, widths)))


async def demo_fixed_window_boundary_exploit() -> None:
    header("1a. Fixed window: the boundary exploit")
    print("Limit: 2 requests / 0.3s window. Sending 2 requests, waiting just past\n"
          "the window boundary, then sending 2 more -- 4 requests in ~0.3s total.")
    algo = FixedWindowAlgorithm(MemoryStorage())
    rule = LimitRule(limit=2, window_seconds=0.3)
    row("request", "elapsed", "allowed", "remaining")
    start = time.monotonic()
    for i in range(2):
        r = await algo.check("attacker", rule)
        row(f"#{i + 1}", f"{time.monotonic() - start:.3f}s", r.allowed, r.remaining)
    await asyncio.sleep(0.31)
    for i in range(2, 4):
        r = await algo.check("attacker", rule)
        row(f"#{i + 1}", f"{time.monotonic() - start:.3f}s", r.allowed, r.remaining)
    print("-> All 4 allowed: 2x the configured limit slipped through around the boundary.")


async def demo_sliding_window_fixes_it() -> None:
    header("1b. Sliding window: same traffic, boundary exploit closed")
    algo = SlidingWindowAlgorithm(MemoryStorage())
    rule = LimitRule(limit=2, window_seconds=0.3)
    row("request", "elapsed", "allowed", "remaining")
    start = time.monotonic()
    for i in range(2):
        r = await algo.check("attacker", rule)
        row(f"#{i + 1}", f"{time.monotonic() - start:.3f}s", r.allowed, r.remaining)
    await asyncio.sleep(0.31)
    for i in range(2, 4):
        r = await algo.check("attacker", rule)
        row(f"#{i + 1}", f"{time.monotonic() - start:.3f}s", r.allowed, r.remaining)
    print("-> The weighted estimate still 'sees' the previous window's burst and blocks it.")


async def demo_token_bucket_burst() -> None:
    header("1c. Token bucket: legitimate bursts are fine, sustained abuse isn't")
    algo = TokenBucketAlgorithm(MemoryStorage())
    rule = LimitRule(limit=5, window_seconds=1, burst=5)  # 5 req/s steady, burst of 5
    row("request", "allowed", "tokens left", "")
    for i in range(7):
        r = await algo.check("mobile-app-sync", rule)
        row(f"#{i + 1}", r.allowed, r.remaining, "")
    print("-> First 5 (the full bucket) succeed instantly; #6-7 are throttled until refill.")


async def demo_three_layer_defense() -> None:
    header("2. Three-layer defense: per-user and per-endpoint isolation")
    storage = MemoryStorage()
    algo = SlidingWindowAlgorithm(storage)
    config = LayerConfig(
        user=LimitRule(limit=2, window_seconds=5),
        endpoint=LimitRule(limit=3, window_seconds=5),
        global_=LimitRule(limit=100, window_seconds=5),
    )
    defense = ThreeLayerDefense(algo, config)

    print("client 'alice' hits /api/data 3 times (user limit is 2):")
    for i in range(3):
        r = await defense.check("alice", "/api/data")
        row(f"  request #{i + 1}", "", r.allowed, f"blocked by: {r.layer.value if not r.allowed else '-'}")

    print("\nclient 'bob' hits /api/data right after -- unaffected by alice's limit:")
    r = await defense.check("bob", "/api/data")
    row("  request #1", "", r.allowed, "")


async def demo_circuit_breaker() -> None:
    header("3. Circuit breaker: simulated flood across many fake clients")
    storage = MemoryStorage()
    algo = SlidingWindowAlgorithm(storage)
    config = LayerConfig(user=LimitRule(limit=1, window_seconds=60))
    breaker = CircuitBreaker(threshold=20, window_seconds=5, cooldown_seconds=0.5)
    defense = ThreeLayerDefense(algo, config, circuit_breaker=breaker)

    print(f"Breaker trips at {breaker.threshold} rejections / {breaker.window_seconds}s.")
    print("Simulating 30 distinct 'attacker' IPs, each sending 2 requests (2nd is always over-limit)...")

    tripped_at = None
    for i in range(30):
        client = f"attacker-{i}"
        await defense.check(client, "/login")  # consumes their 1 allowed request
        result = await defense.check(client, "/login")  # this one is rejected
        if not result.allowed and result.layer.value == "global" and tripped_at is None:
            tripped_at = i + 1

    print(f"Breaker state after flood: {breaker.state.value}")
    if tripped_at:
        print(f"-> Started short-circuiting globally around attacker #{tripped_at}.")

    print("\nA brand-new, never-before-seen client tries right now:")
    victim = await defense.check("innocent-bystander", "/login")
    row("  innocent-bystander", "", victim.allowed, f"layer: {victim.layer.value}")
    print("-> Denied too: this is the breaker's tradeoff -- shed ALL load during a")
    print("   suspected flood, at the cost of also blocking legitimate traffic briefly.")

    print(f"\nWaiting {breaker.cooldown_seconds}s for the cooldown to elapse...")
    await asyncio.sleep(breaker.cooldown_seconds + 0.05)
    print(f"Breaker state now: {breaker.state.value} (probing recovery)")


def demo_fingerprinting() -> None:
    header("4. Fingerprinting")

    print("IPv6 /64 collapsing (a client can rotate the last 64 bits for free):")
    a = fingerprint_key("2001:db8:1234:5678:aaaa:bbbb:cccc:1111")
    b = fingerprint_key("2001:db8:1234:5678:ffff:0001:0002:0003")
    print(f"  address 1 -> {a}")
    print(f"  address 2 -> {b}")
    print(f"  same /64 bucket: {a == b}")

    print("\nX-Forwarded-For spoofing resistance (untrusted by default):")
    spoofed_ip = extract_client_ip(
        headers={"x-forwarded-for": "1.2.3.4"},
        direct_ip="9.9.9.9",
        trust_x_forwarded_for=False,
    )
    print(f"  client claims X-Forwarded-For: 1.2.3.4, real socket peer: 9.9.9.9")
    print(f"  extracted IP (trust_x_forwarded_for=False): {spoofed_ip}  <- header ignored")

    print("\nJWT-based identity extraction (signature NOT verified -- see fingerprinting/auth.py):")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "user-8821"}).encode()).rstrip(b"=").decode()
    fake_jwt = f"eyJhbGciOiJub25lIn0.{payload}.fakesignature"
    identity = extract_identity({"authorization": f"Bearer {fake_jwt}"})
    print(f"  Authorization: Bearer <jwt with sub=user-8821>")
    print(f"  extracted rate-limit identity: {identity}")


async def main() -> None:
    print("fastapi_420 -- rate limiting library demo (pure stdlib, no server required)")
    await demo_fixed_window_boundary_exploit()
    await demo_sliding_window_fixes_it()
    await demo_token_bucket_burst()
    await demo_three_layer_defense()
    await demo_circuit_breaker()
    demo_fingerprinting()
    print("\nDone. See examples/app.py for a real HTTP server wired up the same way,")
    print("or README.md for the full architecture writeup.")


if __name__ == "__main__":
    asyncio.run(main())
