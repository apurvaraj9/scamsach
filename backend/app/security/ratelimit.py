"""In-memory sliding-window rate limiting.

Layers of protection for the free quotas:
1. per anonymous visitor (IP): a few checks per hour
2. per logged-in user: a daily allowance
3. a global hourly ceiling, so even someone rotating IPs cannot drain the
   free LLM / threat-intel quotas
4. per-provider budgets inside the LLM and VirusTotal clients

The server has one process on the free tier, so memory is enough; a
multi-instance deployment would move this to Redis/Postgres.
"""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque

from starlette.requests import Request


class SlidingWindow:
    def __init__(self) -> None:
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        """Record a hit if allowed. Returns (allowed, retry_after_seconds)."""
        now = time.time()
        q = self.hits[key]
        while q and now - q[0] > window_seconds:
            q.popleft()
        if len(q) >= limit:
            return False, int(window_seconds - (now - q[0])) + 1
        q.append(now)
        if len(self.hits) > 20000:  # keep memory bounded
            self.hits = defaultdict(deque, {k: v for k, v in self.hits.items() if v})
        return True, 0

    def reset(self) -> None:
        self.hits.clear()


limiter = SlidingWindow()


def client_ip(request: Request) -> str:
    """Best-effort real client IP behind the hosting proxy.

    Cloudflare-fronted hosts set CF-Connecting-IP (clients cannot override it
    through the proxy). Otherwise we take the right-most X-Forwarded-For
    entry, which is the one our own platform proxy appended. Spoofing this
    only shifts which bucket is used; the global ceiling still applies."""
    for header in ("cf-connecting-ip", "true-client-ip"):
        value = request.headers.get(header, "").strip()
        if _valid_ip(value):
            return value
    xff = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    for candidate in reversed(xff):
        if _valid_ip(candidate):
            return candidate
    return request.client.host if request.client else "unknown"


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
