"""Small in-memory caches and quota counters.

The free server sleeps and restarts, so these are best-effort. Investigation
results are also cached in Postgres (see services/store.py) to survive
restarts. Caching protects the free API quotas from repeated checks of the
same viral scam message.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from cachetools import TTLCache

_tool_cache: TTLCache = TTLCache(maxsize=4000, ttl=6 * 3600)


def cache_set(namespace: str, key: str, value: Any, ttl: float | None = None) -> None:
    # TTLCache has one global TTL; store an explicit expiry for shorter ones.
    expires = time.time() + ttl if ttl else None
    _tool_cache[(namespace, key)] = (expires, value)


def cache_lookup(namespace: str, key: str) -> Any | None:
    item = _tool_cache.get((namespace, key))
    if item is None:
        return None
    expires, value = item
    if expires is not None and time.time() > expires:
        _tool_cache.pop((namespace, key), None)
        return None
    return value


def clear_all() -> None:
    _tool_cache.clear()


class Quota:
    """Sliding-window counters: N calls per minute and per day."""

    def __init__(self, per_minute: int | None, per_day: int | None) -> None:
        self.per_minute = per_minute
        self.per_day = per_day
        self.minute: deque[float] = deque()
        self.day: deque[float] = deque()

    def _trim(self, now: float) -> None:
        while self.minute and now - self.minute[0] > 60:
            self.minute.popleft()
        while self.day and now - self.day[0] > 86400:
            self.day.popleft()

    def try_acquire(self) -> bool:
        now = time.time()
        self._trim(now)
        if self.per_minute is not None and len(self.minute) >= self.per_minute:
            return False
        if self.per_day is not None and len(self.day) >= self.per_day:
            return False
        self.minute.append(now)
        self.day.append(now)
        return True

    def remaining_today(self) -> int | None:
        self._trim(time.time())
        return None if self.per_day is None else self.per_day - len(self.day)
