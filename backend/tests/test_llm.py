import httpx
import pytest
import respx

from app.agent import llm

pytestmark = pytest.mark.asyncio
GEMINI = r"https://generativelanguage.googleapis.com/v1beta/models/.*"
GROQ = "https://api.groq.com/openai/v1/chat/completions"


def gemini_ok(text):
    return httpx.Response(
        200, json={"candidates": [{"content": {"parts": [{"text": text}]}}], "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5}}
    )


def groq_ok(text):
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}], "usage": {}})


@respx.mock
async def test_gemini_rate_limit_falls_back_to_groq(settings_env):
    settings_env(gemini_api_key="g", groq_api_key="q")
    respx.post(url__regex=GEMINI).mock(return_value=httpx.Response(429))
    respx.post(GROQ).mock(return_value=groq_ok('{"verdict": "scam"}'))
    res = await llm.complete_json("judge", "sys", "user", ["gemini", "groq"])
    assert res.data == {"verdict": "scam"} and res.provider == "groq"


@respx.mock
async def test_retired_model_moves_to_next_model(settings_env):
    settings_env(gemini_api_key="g", gemini_models="old-model,new-model")
    respx.post(url__regex=r".*/models/old-model:generateContent").mock(return_value=httpx.Response(404))
    respx.post(url__regex=r".*/models/new-model:generateContent").mock(return_value=gemini_ok('```json\n{"a": 1}\n```'))
    res = await llm.complete_json("x", "s", "u", ["gemini"])
    assert res.data == {"a": 1} and res.model == "new-model"


@respx.mock
async def test_invalid_json_and_no_providers(settings_env):
    settings_env(groq_api_key="q")
    respx.post(GROQ).mock(return_value=groq_ok("not json at all"))
    res = await llm.complete_json("x", "s", "u", ["gemini", "groq"])
    assert res.data is None and "gemini: not configured" in res.error


async def test_budget_stops_calls(settings_env):
    settings_env(gemini_api_key="g", llm_daily_budget=0)
    res = await llm.complete_json("x", "s", "u", ["gemini"])
    assert res.data is None and "budget" in res.error
