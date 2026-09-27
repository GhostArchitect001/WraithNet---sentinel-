"""
Standalone test for the rate limiter (core/rate_limiter.py). Run with:
    python3 tests/test_rate_limiter_standalone.py

Covers the InMemoryRateLimiter directly (always runs), and the
RedisRateLimiter + build_rate_limiter fallback behavior (runs against
a real Redis if one is reachable at localhost:6379; otherwise those
scenarios are skipped with a note rather than failed, since CI/dev
boxes won't always have Redis running).
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time

from core.rate_limiter import (
    InMemoryRateLimiter,
    RateLimitExceeded,
    build_rate_limiter,
)

try:
    import redis as redis_pkg
except ImportError:
    redis_pkg = None


def _redis_available() -> bool:
    if redis_pkg is None:
        return False
    try:
        client = redis_pkg.Redis.from_url(
            "redis://localhost:6379/0", socket_connect_timeout=0.2, socket_timeout=0.2
        )
        return client.ping()
    except Exception:
        return False


def run():
    failures = 0

    print("=== Scenario 1: InMemoryRateLimiter allows requests under the limit ===")
    limiter = InMemoryRateLimiter(window_seconds=60, max_requests=5)
    try:
        for _ in range(5):
            limiter.check("tenant-alpha")
        print("  OK: 5 requests under a limit of 5 all allowed")
    except RateLimitExceeded:
        print("  FAIL: request under the limit was rejected")
        failures += 1

    print("\n=== Scenario 2: InMemoryRateLimiter blocks the request that exceeds the limit ===")
    try:
        limiter.check("tenant-alpha")
        print("  FAIL: 6th request should have raised RateLimitExceeded")
        failures += 1
    except RateLimitExceeded:
        print("  OK: 6th request correctly rejected")

    print("\n=== Scenario 3: different tenants have independent limits ===")
    limiter2 = InMemoryRateLimiter(window_seconds=60, max_requests=2)
    try:
        limiter2.check("tenant-a")
        limiter2.check("tenant-a")
        limiter2.check("tenant-b")  # different tenant, should not be affected by tenant-a's usage
        print("  OK: tenant-b unaffected by tenant-a's usage")
    except RateLimitExceeded:
        print("  FAIL: tenant-b should not have been rate limited by tenant-a's requests")
        failures += 1

    print("\n=== Scenario 4: sliding window expires old entries ===")
    limiter3 = InMemoryRateLimiter(window_seconds=1, max_requests=1)
    try:
        limiter3.check("tenant-window")
        try:
            limiter3.check("tenant-window")
            print("  FAIL: second immediate request should have been rejected")
            failures += 1
        except RateLimitExceeded:
            pass
        time.sleep(1.1)
        limiter3.check("tenant-window")
        print("  OK: request allowed again after window elapsed")
    except RateLimitExceeded:
        print("  FAIL: request after window elapsed should have been allowed")
        failures += 1

    print("\n=== Scenario 5: reset() clears a tenant's window ===")
    limiter4 = InMemoryRateLimiter(window_seconds=60, max_requests=1)
    limiter4.check("tenant-reset")
    limiter4.reset("tenant-reset")
    try:
        limiter4.check("tenant-reset")
        print("  OK: request allowed again after reset()")
    except RateLimitExceeded:
        print("  FAIL: reset() should have cleared the tenant's window")
        failures += 1

    print("\n=== Scenario 6: build_rate_limiter falls back gracefully with no redis_url ===")
    fallback_limiter = build_rate_limiter(redis_url=None, window_seconds=60, max_requests=5)
    if not isinstance(fallback_limiter, InMemoryRateLimiter):
        print(f"  FAIL: expected InMemoryRateLimiter, got {type(fallback_limiter)}")
        failures += 1
    else:
        print("  OK: no redis_url falls back to InMemoryRateLimiter")

    print("\n=== Scenario 7: build_rate_limiter falls back when Redis is unreachable ===")
    unreachable_limiter = build_rate_limiter(
        redis_url="redis://localhost:1/0",  # invalid port, should fail to connect
        window_seconds=60,
        max_requests=5,
    )
    if not isinstance(unreachable_limiter, InMemoryRateLimiter):
        print(f"  FAIL: expected fallback to InMemoryRateLimiter, got {type(unreachable_limiter)}")
        failures += 1
    else:
        print("  OK: unreachable Redis falls back to InMemoryRateLimiter instead of crashing")

    if _redis_available():
        print("\n=== Scenario 8 (Redis live): RedisRateLimiter enforces the same limit ===")
        redis_limiter = build_rate_limiter(
            redis_url="redis://localhost:6379/0", window_seconds=60, max_requests=3
        )
        redis_limiter.reset("tenant-redis-test")
        try:
            for _ in range(3):
                redis_limiter.check("tenant-redis-test")
            try:
                redis_limiter.check("tenant-redis-test")
                print("  FAIL: 4th request should have exceeded limit of 3")
                failures += 1
            except RateLimitExceeded:
                print("  OK: RedisRateLimiter enforces limit same as in-memory version")
        finally:
            redis_limiter.reset("tenant-redis-test")

        print("\n=== Scenario 9 (Redis live): counters survive a fresh limiter instance ===")
        redis_limiter_a = build_rate_limiter(
            redis_url="redis://localhost:6379/0", window_seconds=60, max_requests=2
        )
        redis_limiter_a.reset("tenant-persist-test")
        redis_limiter_a.check("tenant-persist-test")
        redis_limiter_a.check("tenant-persist-test")
        # Simulate a restart: brand new limiter object, same Redis backend
        redis_limiter_b = build_rate_limiter(
            redis_url="redis://localhost:6379/0", window_seconds=60, max_requests=2
        )
        try:
            redis_limiter_b.check("tenant-persist-test")
            print("  FAIL: new limiter instance should see the count from before 'restart'")
            failures += 1
        except RateLimitExceeded:
            print("  OK: rate limit state persisted across a new limiter instance (simulated restart)")
        finally:
            redis_limiter_b.reset("tenant-persist-test")
    else:
        print(
            "\n=== Scenarios 8-9 skipped: no Redis reachable at localhost:6379 ===\n"
            "  (This is expected in most dev/CI environments. Run a local Redis,\n"
            "   e.g. `docker run -p 6379:6379 redis`, to exercise the Redis-backed\n"
            "   scenarios.)"
        )

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)
