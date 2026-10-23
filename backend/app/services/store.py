"""Supabase (Postgres) access through its REST API (PostgREST) with httpx.

- Only the backend talks to the database, using the *secret* key, which never
  leaves the server. Row Level Security is still enabled on every table as a
  second line of defence (see supabase/schema.sql).
- We store the *masked* message and the report only; the raw message you
  pasted is never written anywhere.
- Every method is a safe no-op when Supabase is not configured, so the app
  runs locally with zero accounts.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..config import get_settings

log = logging.getLogger("scamsach.store")
TIMEOUT = httpx.Timeout(8.0, connect=4.0)
CACHE_HOURS = 24


def message_fingerprint(message: str) -> str:
    """Keyed hash of the normalised message, used as the cache key. Keyed
    (HMAC) so nobody can confirm a guessed message from the hash."""
    norm = re.sub(r"\s+", " ", message.strip().lower())
    return hmac.new(get_settings().cache_secret.encode(), norm.encode(), hashlib.sha256).hexdigest()


def _headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    key = get_settings().supabase_secret_key
    h = {"apikey": key, "Content-Type": "application/json"}
    if key.startswith("eyJ"):  # legacy service_role JWT also goes in Authorization
        h["Authorization"] = f"Bearer {key}"
    if extra:
        h.update(extra)
    return h


def _rest(path: str) -> str:
    return f"{get_settings().supabase_url.rstrip('/')}/rest/v1/{path}"


class Store:
    @property
    def enabled(self) -> bool:
        return get_settings().supabase_enabled

    async def _request(self, method: str, path: str, **kw: Any) -> httpx.Response | None:
        if not self.enabled:
            return None
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as c:
                r = await c.request(method, _rest(path), headers=_headers(kw.pop("headers", None)), **kw)
            if r.status_code >= 400:
                log.warning("supabase %s %s -> %s", method, path.split("?")[0], r.status_code)
                return None
            return r
        except httpx.HTTPError as exc:
            log.warning("supabase unreachable: %s", type(exc).__name__)
            return None

    # ---- cases --------------------------------------------------------------
    async def save_case(self, user_id: str, report: dict) -> str | None:
        row = {
            "user_id": user_id,
            "verdict": report["verdict"],
            "risk_score": report["risk_score"],
            "scam_type": report["scam_type"],
            "masked_message": report["masked_message"][:2000],
            "report": report,
        }
        r = await self._request("POST", "cases", json=row, headers={"Prefer": "return=representation"})
        return r.json()[0]["id"] if r is not None else None

    async def list_cases(self, user_id: str, limit: int = 50) -> list[dict]:
        r = await self._request(
            "GET",
            f"cases?user_id=eq.{user_id}&select=id,created_at,verdict,risk_score,scam_type,masked_message&order=created_at.desc&limit={limit}",
        )
        rows = r.json() if r is not None else []
        for row in rows:
            row["snippet"] = (row.pop("masked_message") or "")[:140]
        return rows

    async def get_case(self, user_id: str, case_id: str) -> dict | None:
        r = await self._request("GET", f"cases?id=eq.{case_id}&user_id=eq.{user_id}&select=*")
        rows = r.json() if r is not None else []
        return rows[0] if rows else None

    async def delete_case(self, user_id: str, case_id: str) -> bool:
        r = await self._request("DELETE", f"cases?id=eq.{case_id}&user_id=eq.{user_id}")
        return r is not None

    async def delete_all(self, user_id: str) -> bool:
        r = await self._request("DELETE", f"cases?user_id=eq.{user_id}")
        return r is not None

    # ---- follow-ups ------------------------------------------------------
    async def add_followup(self, user_id: str, case_id: str, question: str, answer: str) -> None:
        await self._request("POST", "followups", json={"user_id": user_id, "case_id": case_id, "question": question[:500], "answer": answer[:2000]})

    async def list_followups(self, user_id: str, case_id: str) -> list[dict]:
        r = await self._request(
            "GET", f"followups?case_id=eq.{case_id}&user_id=eq.{user_id}&select=id,created_at,question,answer&order=created_at.asc&limit=50"
        )
        return r.json() if r is not None else []

    # ---- feedback ----------------------------------------------------------
    async def save_feedback(self, row: dict) -> bool:
        r = await self._request("POST", "feedback", json=row)
        return r is not None

    # ---- result cache ----------------------------------------------------
    async def cache_get(self, fingerprint: str) -> dict | None:
        since = (datetime.now(timezone.utc) - timedelta(hours=CACHE_HOURS)).isoformat()
        # params= lets httpx URL-encode the '+' in the timestamp.
        r = await self._request("GET", "check_cache", params={"fingerprint": f"eq.{fingerprint}", "created_at": f"gte.{since}", "select": "report"})
        rows = r.json() if r is not None else []
        return rows[0]["report"] if rows else None

    async def cache_put(self, fingerprint: str, report: dict) -> None:
        await self._request(
            "POST",
            "check_cache?on_conflict=fingerprint",
            json={"fingerprint": fingerprint, "report": report, "created_at": datetime.now(timezone.utc).isoformat()},
            headers={"Prefer": "resolution=merge-duplicates"},
        )

    # ---- keep-alive ------------------------------------------------------
    async def purge_cache(self) -> None:
        """Delete cache rows older than 2 days (SQL function in schema.sql)."""
        await self._request("POST", "rpc/purge_old_cache", json={})

    async def ping(self) -> bool:
        r = await self._request("GET", "check_cache?select=fingerprint&limit=1")
        return r is not None


store = Store()


# ---------------------------------------------------------------------------
# Auth: verify a Supabase access token by asking Supabase Auth who it belongs
# to. Works with both legacy and new signing keys, no JWT secret needed.
# ---------------------------------------------------------------------------
_auth_cache: dict[str, tuple[float, dict | None]] = {}


async def verify_user(token: str | None) -> dict | None:
    s = get_settings()
    if not token or not s.supabase_enabled:
        return None
    key = hashlib.sha256(token.encode()).hexdigest()
    hit = _auth_cache.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            r = await c.get(
                f"{s.supabase_url.rstrip('/')}/auth/v1/user", headers={"apikey": s.supabase_publishable_key, "Authorization": f"Bearer {token}"}
            )
    except httpx.HTTPError:
        return None
    user = None
    if r.status_code == 200:
        data = r.json()
        if data.get("id"):
            user = {"id": data["id"], "email": data.get("email")}
    if len(_auth_cache) > 5000:
        _auth_cache.clear()
    _auth_cache[key] = (time.time() + (300 if user else 30), user)
    return user
