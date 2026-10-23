"""Provider-agnostic LLM calls with automatic fallback.

- Gemini (Google AI Studio free tier) and Groq (free tier) are called over
  plain HTTPS with httpx: no heavy SDKs, easy to mock in tests.
- Each provider has an ordered list of models. If Google or Groq retires a
  model name, the next one is tried and remembered.
- Each provider has its own per-minute and per-day budget kept *below* the
  free limits, so we fall back before ever receiving a 429.
- A 429 or outage on one provider moves the call to the next provider.
- If every provider fails, callers get ``None`` and use rule-based output:
  the app keeps working with zero LLM quota left.

Only masked text is ever passed in here (see security/masking.py).
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass

import httpx

from ..config import get_settings
from ..services.tracing import observe
from ..tools.cache import Quota

log = logging.getLogger("scamsach.llm")


@dataclass
class LLMResult:
    data: dict | None
    provider: str | None = None
    model: str | None = None
    error: str | None = None


class _Provider:
    def __init__(self, name: str, models: list[str], per_minute: int, per_day: int) -> None:
        self.name = name
        self.models = models
        self.quota = Quota(per_minute=per_minute, per_day=per_day)
        self.cooldown_until = 0.0

    def available(self) -> bool:
        return time.time() >= self.cooldown_until

    def cool_down(self, seconds: float = 60.0) -> None:
        self.cooldown_until = time.time() + seconds


_providers: dict[str, _Provider] = {}


def _get_provider(name: str) -> _Provider | None:
    s = get_settings()
    if name in _providers:
        return _providers[name]
    if name == "gemini" and s.gemini_api_key:
        p = _Provider("gemini", [m.strip() for m in s.gemini_models.split(",") if m.strip()], 9, s.llm_daily_budget)
    elif name == "groq" and s.groq_api_key:
        p = _Provider("groq", [m.strip() for m in s.groq_models.split(",") if m.strip()], 25, 900)
    else:
        return None
    _providers[name] = p
    return p


def reset_providers() -> None:
    _providers.clear()


def _parse_json(text: str) -> dict | None:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None


class _ModelGone(Exception):
    pass


class _RateLimited(Exception):
    pass


async def _call_gemini(client: httpx.AsyncClient, model: str, system: str, user: str) -> tuple[str, dict]:
    key = get_settings().gemini_api_key
    r = await client.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        headers={"x-goog-api-key": key},
        json={
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json", "maxOutputTokens": 2048},
        },
    )
    if r.status_code == 429:
        raise _RateLimited()
    if r.status_code == 404 or (r.status_code == 400 and "not found" in r.text.lower()):
        raise _ModelGone()
    r.raise_for_status()
    body = r.json()
    parts = body["candidates"][0]["content"]["parts"]
    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
    usage = body.get("usageMetadata", {})
    return text, {"input": usage.get("promptTokenCount", 0), "output": usage.get("candidatesTokenCount", 0)}


async def _call_groq(client: httpx.AsyncClient, model: str, system: str, user: str) -> tuple[str, dict]:
    key = get_settings().groq_api_key
    r = await client.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}"},
        json={
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.2,
            "max_tokens": 1500,
            "response_format": {"type": "json_object"},
        },
    )
    if r.status_code == 429:
        raise _RateLimited()
    if r.status_code == 404 or (r.status_code == 400 and ("decommission" in r.text or "not exist" in r.text or "model_not_found" in r.text)):
        raise _ModelGone()
    r.raise_for_status()
    body = r.json()
    usage = body.get("usage", {})
    return body["choices"][0]["message"]["content"], {"input": usage.get("prompt_tokens", 0), "output": usage.get("completion_tokens", 0)}


async def complete_json(task: str, system: str, user: str, providers: list[str]) -> LLMResult:
    """Ask for a JSON object, trying each provider (and model) in order."""
    errors: list[str] = []
    timeout = httpx.Timeout(get_settings().llm_timeout_seconds, connect=5.0)
    for name in providers:
        prov = _get_provider(name)
        if prov is None:
            errors.append(f"{name}: not configured")
            continue
        if not prov.available():
            errors.append(f"{name}: cooling down after rate limit")
            continue
        if not prov.quota.try_acquire():
            errors.append(f"{name}: our safety budget reached")
            continue
        call = _call_gemini if name == "gemini" else _call_groq
        for model in list(prov.models):
            with observe(
                f"llm:{task}", as_type="generation", model=model, input={"system": system, "user": user}, metadata={"provider": name}
            ) as gen:
                try:
                    async with httpx.AsyncClient(timeout=timeout) as client:
                        text, usage = await call(client, model, system, user)
                except _ModelGone:
                    log.warning("%s model %s unavailable, trying next", name, model)
                    if len(prov.models) > 1:
                        prov.models.remove(model)  # remember for next time
                    gen.update(level="WARNING", status_message="model not found")
                    errors.append(f"{name}/{model}: model not found")
                    continue
                except _RateLimited:
                    prov.cool_down(60)
                    gen.update(level="WARNING", status_message="rate limited")
                    errors.append(f"{name}: rate limited")
                    break
                except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
                    gen.update(level="ERROR", status_message=type(exc).__name__)
                    errors.append(f"{name}/{model}: {type(exc).__name__}")
                    break
                data = _parse_json(text)
                gen.update(output=data or text, usage_details=usage)
                if data is None:
                    errors.append(f"{name}/{model}: invalid JSON")
                    break
                return LLMResult(data=data, provider=name, model=model)
    return LLMResult(data=None, error="; ".join(errors) or "no providers")


def configured_providers() -> list[str]:
    s = get_settings()
    return [n for n, k in (("gemini", s.gemini_api_key), ("groq", s.groq_api_key)) if k]
