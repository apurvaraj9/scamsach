"""Central configuration. Every secret comes from environment variables
(a local .env file in development, the hosting platform's secret store in
production). Nothing secret is ever hard-coded or sent to the browser."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "ScamSach"
    environment: str = "development"  # development | production | test

    # Comma-separated list of website origins allowed to call this API (CORS).
    allowed_origins: str = "http://localhost:3000"

    # Secret used to hash messages for the result cache (never stored raw).
    # In production set a long random value.
    cache_secret: str = "dev-only-change-me"  # noqa: S105 - refused in production, see main.py

    # --- LLMs -------------------------------------------------------------
    gemini_api_key: str = ""
    # Tried in order. If Google renames/retires a model, the next one is used.
    gemini_models: str = "gemini-3.5-flash-lite,gemini-3.1-flash-lite"
    groq_api_key: str = ""
    groq_models: str = "llama-3.3-70b-versatile,openai/gpt-oss-120b,meta-llama/llama-4-scout-17b-16e-instruct"
    # Which providers each agent step uses, in order of preference.
    planner_providers: str = "groq,gemini"
    judge_providers: str = "gemini,groq"
    llm_timeout_seconds: float = 20.0
    # Our own daily ceiling, kept below the free quotas so we never hit them.
    llm_daily_budget: int = 400

    # --- Threat intelligence ----------------------------------------------
    safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""
    urlhaus_auth_key: str = ""
    virustotal_daily_budget: int = 450  # free public API: 500/day, 4/min
    virustotal_per_minute: int = 4
    enable_network_tools: bool = True  # tests/evals switch this off

    # --- Supabase ----------------------------------------------------------
    supabase_url: str = ""
    supabase_publishable_key: str = ""  # a.k.a. anon key (public by design)
    supabase_secret_key: str = ""  # a.k.a. service_role key (backend only!)

    # --- Langfuse (tracing) ----------------------------------------------
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_base_url: str = "https://cloud.langfuse.com"

    # --- Abuse protection -------------------------------------------------
    anon_checks_per_hour: int = 5
    user_checks_per_day: int = 40
    followups_per_hour: int = 15
    max_concurrent_investigations: int = 3
    max_message_chars: int = 2000

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def supabase_enabled(self) -> bool:
        return bool(self.supabase_url and self.supabase_secret_key and self.supabase_publishable_key)

    @property
    def langfuse_enabled(self) -> bool:
        return bool(self.langfuse_public_key and self.langfuse_secret_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
