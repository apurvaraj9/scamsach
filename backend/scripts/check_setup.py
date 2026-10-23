"""Check every integration with one tiny live call and print a report.

Run from the backend folder:   python -m scripts.check_setup

It prints only OK / MISSING / FAILED and short reasons - never your keys -
so the output is safe to share when asking for help.
"""

from __future__ import annotations

import asyncio
import base64

import httpx

from app.config import get_settings

T = httpx.Timeout(15.0, connect=8.0)


async def gemini(s) -> str:
    if not s.gemini_api_key:
        return "MISSING (optional, but recommended)"
    async with httpx.AsyncClient(timeout=T) as c:
        r = await c.get("https://generativelanguage.googleapis.com/v1beta/models", headers={"x-goog-api-key": s.gemini_api_key})
        if r.status_code != 200:
            return f"FAILED (HTTP {r.status_code}) - check the key"
        available = {m["name"].removeprefix("models/") for m in r.json().get("models", [])}
        wanted = [m.strip() for m in s.gemini_models.split(",")]
        found = [m for m in wanted if m in available]
        if not found:
            lite = sorted(m for m in available if "flash-lite" in m)
            return f"KEY OK but none of GEMINI_MODELS exist. Flash-Lite models on your key: {', '.join(lite[:6]) or 'none'}"
        r2 = await c.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{found[0]}:generateContent",
            headers={"x-goog-api-key": s.gemini_api_key},
            json={"contents": [{"parts": [{"text": 'Reply with JSON {"ok": true}'}]}]},
        )
        return f"OK ({found[0]})" if r2.status_code == 200 else f"KEY OK, test call HTTP {r2.status_code}"


async def groq(s) -> str:
    if not s.groq_api_key:
        return "MISSING (optional fallback)"
    async with httpx.AsyncClient(timeout=T) as c:
        r = await c.get("https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {s.groq_api_key}"})
        if r.status_code != 200:
            return f"FAILED (HTTP {r.status_code}) - check the key"
        available = {m["id"] for m in r.json().get("data", [])}
        wanted = [m.strip() for m in s.groq_models.split(",")]
        found = [m for m in wanted if m in available]
        if not found:
            return f"KEY OK but none of GROQ_MODELS exist. Some available: {', '.join(sorted(available)[:6])}"
        return f"OK ({found[0]})"


async def safe_browsing(s) -> str:
    if not s.safe_browsing_api_key:
        return "MISSING (optional)"
    body = {
        "client": {"clientId": "scamsach", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": "http://testsafebrowsing.appspot.com/s/phishing.html"}],
        },
    }
    async with httpx.AsyncClient(timeout=T) as c:
        r = await c.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", json=body, headers={"X-Goog-Api-Key": s.safe_browsing_api_key})
    if r.status_code != 200:
        return f"FAILED (HTTP {r.status_code}) - is the Safe Browsing API enabled for this key's project?"
    return "OK (Google's test phishing page detected)" if r.json().get("matches") else "OK (key works)"


async def virustotal(s) -> str:
    if not s.virustotal_api_key:
        return "MISSING (optional)"
    url_id = base64.urlsafe_b64encode(b"http://example.com/").decode().strip("=")
    async with httpx.AsyncClient(timeout=T) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": s.virustotal_api_key})
    return "OK" if r.status_code in (200, 404) else f"FAILED (HTTP {r.status_code})"


async def urlhaus(s) -> str:
    if not s.urlhaus_auth_key:
        return "MISSING (optional)"
    async with httpx.AsyncClient(timeout=T) as c:
        r = await c.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": "example.com"}, headers={"Auth-Key": s.urlhaus_auth_key})
    return "OK" if r.status_code == 200 else f"FAILED (HTTP {r.status_code})"


async def rdap(_s) -> str:
    async with httpx.AsyncClient(timeout=T, follow_redirects=True) as c:
        r = await c.get("https://rdap.org/domain/google.com")
    return "OK (no key needed)" if r.status_code == 200 else f"FAILED (HTTP {r.status_code})"


async def supabase(s) -> str:
    if not s.supabase_enabled:
        return "MISSING (needed only for login + history)"
    headers = {"apikey": s.supabase_secret_key}
    if s.supabase_secret_key.startswith("eyJ"):
        headers["Authorization"] = f"Bearer {s.supabase_secret_key}"
    async with httpx.AsyncClient(timeout=T) as c:
        r = await c.get(f"{s.supabase_url.rstrip('/')}/rest/v1/cases?select=id&limit=1", headers=headers)
    if r.status_code == 200:
        return "OK (tables found)"
    if r.status_code == 404 or "does not exist" in r.text or "schema cache" in r.text:
        return "KEYS OK but tables missing - run supabase/schema.sql in the SQL editor"
    return f"FAILED (HTTP {r.status_code}) - check URL and secret key"


async def langfuse(s) -> str:
    if not s.langfuse_enabled:
        return "MISSING (optional tracing)"
    async with httpx.AsyncClient(timeout=T) as c:
        r = await c.get(f"{s.langfuse_base_url.rstrip('/')}/api/public/projects", auth=(s.langfuse_public_key, s.langfuse_secret_key))
    return "OK" if r.status_code == 200 else f"FAILED (HTTP {r.status_code}) - check keys and LANGFUSE_BASE_URL region"


async def main() -> None:
    s = get_settings()
    checks = [
        ("Gemini (main AI)", gemini),
        ("Groq (backup AI)", groq),
        ("Google Safe Browsing", safe_browsing),
        ("VirusTotal", virustotal),
        ("URLhaus", urlhaus),
        ("RDAP domain age", rdap),
        ("Supabase", supabase),
        ("Langfuse", langfuse),
    ]
    print(f"ScamSach setup check (environment={s.environment})\n")
    for name, fn in checks:
        try:
            result = await fn(s)
        except httpx.HTTPError as exc:
            result = f"FAILED (network: {type(exc).__name__})"
        print(f"  {name:<22} {result}")
    print("\nCORS allowed origins:", ", ".join(s.origins))


if __name__ == "__main__":
    asyncio.run(main())
