"""
Redis-backed sliding-window rate limiter for Ghost Sentinel.
==============================================================

Replaces the in-process dict/deque limiter that used to live in
api/main.py. Same job - cap requests per tenant per rolling window -
but backed by Redis so it works correctly across multiple API
processes/servers and survives process restarts (the counters live
in Redis, not in this process's memory).

Algorithm: sliding-window log via a Redis sorted set (ZSET) per
tenant. Each request adds an entry scored by its timestamp; entries
older than the window are trimmed on every call; the count of
remaining entries is compared against the limit. This is the same
sliding-window-log approach the old in-process deque implemented,
just backed by a store that's shared and durable.

    ZREMRANGEBYSCORE tenant:<id>  0  (now - window)   # drop stale entries
    ZCARD tenant:<id>                                 # count what's left
    ZADD tenant:<id> now now                          # record this request
    EXPIRE tenant:<id> window                          # let Redis reap it

The four ops run inside a MULTI/EXEC pipeline so concurrent requests
from the same tenant, across any number of processes, don't race.

Fail-open policy: if Redis is unreachable, requests are allowed
through rather than blocked, and a warning is logged. An outage in
the rate limiter's own dependency should not become an outage of the
whole API. If you'd rather fail closed (reject requests when Redis
is down) for a stricter deployment, flip FAIL_OPEN_ON_REDIS_ERROR
below.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger("ghost_sentinel.rate_limiter")

try:
    import redis
except ImportError:  # pragma: no cover - exercised only in envs without redis installed
    redis = None

FAIL_OPEN_ON_REDIS_ERROR = True


class RateLimitExceeded(Exception):
    """Raised when a tenant has exceeded their allotted requests for the window."""

    def __init__(self, tenant_id: str, limit: int, window_seconds: int):
        self.tenant_id = tenant_id
        self.limit = limit
        self.window_seconds = window_seconds
        super().__init__(
            f"Rate limit exceeded for tenant '{tenant_id}': "
            f"{limit} requests per {window_seconds}s"
        )


class RedisRateLimiter:
    """
    Sliding-window rate limiter backed by Redis.

    Same shape as the old check_rate_limit(tenant_id) function it
    replaces: construct once at startup, call .check(tenant_id) per
    request, catch RateLimitExceeded to return a 429.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        window_seconds: int = 60,
        max_requests: int = 120,
        key_prefix: str = "ghost_sentinel:ratelimit:",
        socket_timeout: float = 0.2,
    ):
        if redis is None:
            raise RuntimeError(
                "The 'redis' package is not installed. Add 'redis' to "
                "requirements.txt and pip install it, or use "
                "InMemoryRateLimiter for local/dev use."
            )
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.key_prefix = key_prefix
        self._client = redis.Redis.from_url(
            redis_url,
            socket_timeout=socket_timeout,
            socket_connect_timeout=socket_timeout,
            decode_responses=True,
        )

    def _key(self, tenant_id: str) -> str:
        return f"{self.key_prefix}{tenant_id}"

    def check(self, tenant_id: str) -> None:
        """
        Record this request and raise RateLimitExceeded if the tenant
        is over their limit for the current window. Returns None
        (allowed) otherwise.
        """
        now = time.time()
        window_start = now - self.window_seconds
        key = self._key(tenant_id)

        try:
            pipe = self._client.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zcard(key)
            pipe.zadd(key, {f"{now:.6f}-{id(pipe)}": now})
            pipe.expire(key, self.window_seconds)
            _removed, count_before_this_request, _added, _expired = pipe.execute()
        except Exception as exc:  # redis.exceptions.RedisError and friends
            logger.warning(
                "Rate limiter Redis call failed for tenant '%s': %s. "
                "Failing %s.",
                tenant_id,
                exc,
                "open (request allowed)" if FAIL_OPEN_ON_REDIS_ERROR else "closed (request blocked)",
            )
            if FAIL_OPEN_ON_REDIS_ERROR:
                return
            raise

        if count_before_this_request >= self.max_requests:
            raise RateLimitExceeded(tenant_id, self.max_requests, self.window_seconds)

    def reset(self, tenant_id: str) -> None:
        """Clear a tenant's window. Mainly useful for tests."""
        self._client.delete(self._key(tenant_id))


class InMemoryRateLimiter:
    """
    Drop-in fallback with the exact same .check(tenant_id) interface
    as RedisRateLimiter, backed by an in-process dict/deque.

    Intended for local development or single-process deployments
    where standing up Redis isn't worth it yet. This is functionally
    the same limiter that used to live directly in api/main.py - it's
    kept here, behind the same interface as the Redis version, so
    swapping between them is a one-line change and neither one is a
    special case in the API layer.
    """

    def __init__(self, window_seconds: int = 60, max_requests: int = 120):
        from collections import defaultdict, deque

        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self._log: dict[str, "deque[float]"] = defaultdict(deque)

    def check(self, tenant_id: str) -> None:
        now = time.monotonic()
        log = self._log[tenant_id]
        while log and now - log[0] > self.window_seconds:
            log.popleft()
        if len(log) >= self.max_requests:
            raise RateLimitExceeded(tenant_id, self.max_requests, self.window_seconds)
        log.append(now)

    def reset(self, tenant_id: str) -> None:
        self._log.pop(tenant_id, None)


def build_rate_limiter(
    redis_url: Optional[str] = None,
    window_seconds: int = 60,
    max_requests: int = 120,
):
    """
    Factory used by api/main.py. Returns a RedisRateLimiter if a
    redis_url is given and the redis package is installed; otherwise
    falls back to InMemoryRateLimiter with a warning, so the service
    still starts (e.g. in local dev without Redis running) instead of
    crashing on import.
    """
    if redis_url:
        if redis is None:
            logger.warning(
                "GHOST_SENTINEL_REDIS_URL is set but the 'redis' package "
                "isn't installed. Falling back to InMemoryRateLimiter. "
                "Run: pip install redis"
            )
            return InMemoryRateLimiter(window_seconds, max_requests)
        try:
            limiter = RedisRateLimiter(
                redis_url=redis_url,
                window_seconds=window_seconds,
                max_requests=max_requests,
            )
            limiter._client.ping()
            logger.info("Rate limiter connected to Redis at %s", redis_url)
            return limiter
        except Exception as exc:
            logger.warning(
                "Could not connect to Redis at %s (%s). Falling back to "
                "InMemoryRateLimiter for this process.",
                redis_url,
                exc,
            )
            return InMemoryRateLimiter(window_seconds, max_requests)

    logger.info(
        "No GHOST_SENTINEL_REDIS_URL configured; using InMemoryRateLimiter. "
        "Fine for a single process/dev, but won't hold state across "
        "multiple server instances - set GHOST_SENTINEL_REDIS_URL for "
        "production."
    )
    return InMemoryRateLimiter(window_seconds, max_requests)
