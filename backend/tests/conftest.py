"""Test setup. Environment variables override any local .env file, so the
test suite never uses your real API keys or calls real services."""

import os

_BLANK = [
    "GEMINI_API_KEY",
    "GROQ_API_KEY",
    "SAFE_BROWSING_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "URLHAUS_AUTH_KEY",
    "SUPABASE_URL",
    "SUPABASE_PUBLISHABLE_KEY",
    "SUPABASE_SECRET_KEY",
    "LANGFUSE_PUBLIC_KEY",
    "LANGFUSE_SECRET_KEY",
]
for name in _BLANK:
    os.environ[name] = ""
os.environ["SCAMSACH_IGNORE_DOTENV"] = "1"  # never read the developer's local .env
os.environ["ENVIRONMENT"] = "test"
os.environ["ENABLE_NETWORK_TOOLS"] = "false"
os.environ["CACHE_SECRET"] = "test-secret"

import pytest  # noqa: E402

from app.agent import llm  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.security.ratelimit import limiter  # noqa: E402
from app.tools import cache  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_state():
    get_settings.cache_clear()
    cache.clear_all()
    limiter.reset()
    llm.reset_providers()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings_env(monkeypatch):
    """Set environment variables for one test and refresh settings."""

    def _set(**values):
        for k, v in values.items():
            monkeypatch.setenv(k.upper(), str(v))
        get_settings.cache_clear()
        llm.reset_providers()
        return get_settings()

    return _set
