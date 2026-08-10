# fastapi_420 — Advanced API Rate Limiter

Sorry about no folders on the repo, i did not know how to use github at the time. Just follow the architecture section to properly build the file tree manually. Again Sorry.

A production-style rate limiting library: three algorithms, a
three-layer defense system (per-user → per-endpoint → global +
circuit breaker), and composite client fingerprinting that resists
the common IP-spoofing and IPv6-rotation bypasses.

Built from the **Advanced** tier of
[CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects)
(`PROJECTS/advanced/api-rate-limiter`, project id `fastapi-420`).

> **A note on this build.** The original project spec targets FastAPI +
> Redis + Pydantic, run via `uv`. This environment has no package-registry
> access, so the core library here is implemented with **zero third-party
> dependencies** — every algorithm, storage backend (in-memory), defense
> layer, and fingerprinting rule is pure standard library. Redis support
> and the FastAPI dependency-injection helper are still implemented in
> full (see `storage/redis_backend.py`, `dependencies.py`) but import
> their requirement lazily, so they activate automatically if you `pip
> install redis` / `pip install fastapi` later — nothing to change in
> the code. `examples/app.py` demonstrates the exact same rate-limiting
> logic over a real HTTP server using `http.server` instead of uvicorn.

## Why this one

Of the three complete Advanced projects in the repo (API Rate Limiter,
Bug Bounty Platform, Encrypted P2P Chat), this is the one whose full
scope — algorithms, storage, defense, middleware — is a self-contained
backend library rather than a multi-service app needing Docker, a
frontend, and package installs to run. That made it possible to build
*and verify* the entire thing, end to end, in this sandbox.

## Architecture

```
src/fastapi_420/
├── types.py              Algorithm/Layer enums, LimitRule, RateLimitResult, Fingerprint
├── config.py              RateLimiterConfig (dataclass; .from_env() for 12-factor config)
├── limiter.py              RateLimiter — the public facade wiring everything together
├── middleware.py           RateLimitMiddleware — framework-agnostic ASGI middleware
├── dependencies.py         FastAPI Depends()-style per-route limiting (optional extra)
├── algorithms/
│   ├── fixed_window.py      O(1) counter; has the classic boundary-burst exploit
│   ├── sliding_window.py    Weighted current+previous window; ~99.997% accurate, O(1)
│   └── token_bucket.py      Refill-and-consume; tolerates bursts up to `burst` capacity
├── storage/
│   ├── memory.py             asyncio.Lock-guarded dict; correct within one process
│   ├── redis_backend.py      WATCH/MULTI + Lua-script paths; correct across processes
│   └── lua/*.lua              Atomic single-round-trip scripts for the Redis path
├── fingerprinting/
│   ├── ip.py                  XFF spoofing resistance, IPv6 /64 collapsing
│   ├── headers.py             UA/Accept-* entropy for shared-IP disambiguation
│   ├── auth.py                 JWT subject / API key / session extraction (unverified — see below)
│   └── composite.py            Combines the above into one Fingerprint, identity > IP
└── defense/
    ├── circuit_breaker.py       CLOSED → OPEN → HALF_OPEN, trips on aggregate rejection rate
    └── layers.py                  ThreeLayerDefense: user → endpoint → global, most-restrictive wins
```

## The three algorithms, and why there are three

**Fixed window** is the cheapest: one counter per `(client, window_id)`.
Its weakness is real — a client can send `limit` requests in the last
instant of one window and `limit` more in the first instant of the
next, getting ~2x the limit through in a moment. `examples/demo.py`
reproduces this live.

**Sliding window** fixes it with a weighted estimate of the current and
previous fixed window:

```
estimate = current_count + previous_count * overlap
overlap  = (window_seconds - elapsed_in_current_window) / window_seconds
```

Still O(1) per key (no per-request log to store or prune), and closes
the boundary exploit because a burst straddling the boundary shows up
elevated in *both* buckets. This is the library's default algorithm.

**Token bucket** is the odd one out — it's not about a *window* at all.
A bucket holds `capacity` tokens and refills continuously at
`limit / window_seconds` tokens/sec; each request costs one token.
This is the right choice when bursty-but-bounded traffic is legitimate
(a mobile app syncing everything after reconnecting), since it
enforces a strict long-run average while still absorbing bursts up to
capacity.

## Three-layer defense

Checked most-specific-first: **user → endpoint → global**, and any
layer can be disabled (`None`) if you don't need it. A per-user block
is more actionable than a global "the API is under load" message, so
it's checked (and returned) first. A **circuit breaker** sits in front
of all three: if aggregate rejections across *all* clients cross a
threshold within a window — the signature of a coordinated flood,
not one noisy client — it trips OPEN and short-circuits every request
for a cooldown period, then HALF_OPENs to probe recovery. This trades
briefly blocking legitimate traffic for shedding load fast during an
actual attack, instead of running the full fingerprint+algorithm
pipeline per request while under fire.

## Fingerprinting

Client identity is resolved in priority order: **authenticated
identity > IP**. For anonymous traffic, the client IP is normalized —
IPv6 addresses collapse to their `/64` network, since ISPs commonly
hand a single customer a full `/64` (or more) and many OSes rotate the
host portion on their own (RFC 4941 privacy extensions); limiting the
full 128-bit address is trivially bypassed by that rotation alone.
`X-Forwarded-For` is **ignored by default** — it's attacker-controlled
input — and only trusted when `trust_x_forwarded_for=True` with an
explicit `trusted_proxies` allowlist, in which case the chain is
walked from the right past every trusted hop.

For authenticated clients, a Bearer JWT's payload is *decoded but not
signature-verified* to read `sub`/`user_id`. This is intentional and
worth calling out: rate limiting by claimed identity is a usability
optimization (give a logged-in user their own bucket instead of
sharing their IP's), not a trust boundary. An attacker who forges a
JWT to steal a rate-limit bucket has gained nothing but a shared quota
with whichever `sub` they picked — actual authentication is the
application's job, enforced elsewhere.

## Running it

No installation needed for the core library or tests:

```bash
# 34 unit tests, pure stdlib
PYTHONPATH=src python3 -m unittest discover -s tests -v

# CLI walkthrough: boundary exploit, sliding window fix, token bucket
# bursts, layer isolation, circuit breaker trip/recovery, fingerprinting
python3 examples/demo.py

# Real HTTP server (stdlib http.server) with the exact curl example
# from the project spec
python3 examples/app.py
# in another terminal:
curl -i http://127.0.0.1:8000/auth/login -X POST -d "username=test&password=test"
# repeat 4x — the 4th response is HTTP/1.1 420 Enhance Your Calm
curl -i http://127.0.0.1:8000/api/data
```

With `fastapi` and `redis` installed, the same `RateLimiter` drops
into a real ASGI app:

```python
from fastapi import FastAPI
from fastapi_420 import RateLimiter, RateLimiterConfig, RateLimitMiddleware, LimitRule

app = FastAPI()
limiter = RateLimiter(RateLimiterConfig(
    redis_url="redis://localhost:6379",   # falls back to memory if `redis` isn't installed
    user_limit=LimitRule(limit=100, window_seconds=60),
))
app.add_middleware(RateLimitMiddleware, limiter=limiter)
```

## What's simplified from the original spec

- **No Pydantic** — `RateLimiterConfig` is a plain `@dataclass` with a
  `from_env()` classmethod instead of `pydantic-settings`.
- **No uvicorn** — `examples/app.py` uses `http.server` to prove the
  exact same `RateLimiter.check()` call works over real HTTP; the ASGI
  `RateLimitMiddleware` is still fully implemented in `middleware.py`
  for use with a real ASGI server.
- **Redis is optional and untested here** — `storage/redis_backend.py`
  and the Lua scripts in `storage/lua/` are complete, but there's no
  Redis server in this sandbox to run them against. `MemoryStorage` is
  what every test and demo above actually exercises.
