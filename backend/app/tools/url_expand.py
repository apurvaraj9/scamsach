"""Safely find out where a shortened link (bit.ly, tinyurl...) leads.

Safety rules (this is the part to explain in the demo):
1. We only ever send a request to a *known public shortener*. The final
   destination - the possible scam site - is never contacted. Many scam links
   carry a unique tracking ID; visiting them would tell the scammer that this
   victim engaged.
2. Each hop is checked against SSRF: only http/https, only ports 80/443, and
   the shortener's IP must be a public internet address (no localhost,
   private network or cloud-metadata addresses).
3. We send HEAD (or GET without reading the body), never render anything,
   and stop after 5 hops or 5 seconds per hop.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from .domains import is_shortener

MAX_HOPS = 5
USER_AGENT = "ScamSachLinkChecker/1.0 (+safety research; does not follow to destination)"


class UnsafeTarget(Exception):
    pass


@dataclass
class ExpandResult:
    start: str
    chain: list[str] = field(default_factory=list)
    final_url: str | None = None
    note: str = ""


async def _assert_public(host: str, port: int) -> None:
    if port not in (80, 443):
        raise UnsafeTarget(f"port {port} not allowed")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTarget(f"cannot resolve {host}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise UnsafeTarget(f"{host} resolves to a non-public address")


async def expand_shortlink(url: str, client: httpx.AsyncClient | None = None) -> ExpandResult:
    result = ExpandResult(start=url, chain=[url])
    own_client = client is None
    client = client or httpx.AsyncClient(follow_redirects=False, timeout=5.0, headers={"User-Agent": USER_AGENT})
    current = url
    try:
        for _ in range(MAX_HOPS):
            parts = urlsplit(current)
            host = (parts.hostname or "").lower()
            if parts.scheme not in ("http", "https"):
                result.note = "Stopped: link uses an unusual scheme."
                return result
            if not is_shortener(host):
                # We have reached a non-shortener: record it, do not visit it.
                result.final_url = current
                return result
            port = parts.port or (443 if parts.scheme == "https" else 80)
            await _assert_public(host, port)
            resp = await client.head(current)
            if resp.status_code in (400, 403, 405, 501):
                async with client.stream("GET", current) as streamed:  # body is never read
                    resp = streamed
            location = resp.headers.get("location")
            if not (300 <= resp.status_code < 400 and location):
                result.note = f"Shortener answered {resp.status_code} without a redirect (link may be disabled)."
                return result
            current = urljoin(current, location)
            result.chain.append(current)
        result.note = "Too many redirects - a common trick to hide the destination."
        return result
    finally:
        if own_client:
            await client.aclose()
