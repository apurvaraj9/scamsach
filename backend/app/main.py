"""ScamSach API (FastAPI).

Endpoints
  GET    /health                     fast liveness check (used by the website's wake-up screen)
  GET    /health/deep                also touches the database (daily keep-alive for Supabase)
  POST   /api/investigate            run the agent; streams Server-Sent Events
  GET    /api/cases                  your past checks            (login required)
  GET    /api/cases/{id}             one case with its follow-ups (login required)
  POST   /api/cases/{id}/followup    ask about a past case        (login required)
  DELETE /api/cases/{id} | /api/cases  delete one / all of your data (login required)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import unicodedata
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import __version__
from .agent.followup import answer_followup
from .agent.graph import investigate_stream
from .agent.llm import configured_providers
from .config import get_settings
from .security.masking import mask_text
from .security.ratelimit import client_ip, limiter
from .services import tracing
from .services.store import message_fingerprint, store, verify_user
from .tools.cache import cache_lookup, cache_set

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
# httpx logs full request URLs at INFO; keep it quiet so nothing sensitive is logged.
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("scamsach.api")

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):  # noqa: ANN201
    s = get_settings()
    if s.environment == "production" and s.cache_secret == "dev-only-change-me":  # noqa: S105
        raise RuntimeError("Set CACHE_SECRET to a long random value before running in production.")
    log.info(
        "ScamSach %s starting | llm=%s | safe_browsing=%s virustotal=%s urlhaus=%s | supabase=%s | langfuse=%s",
        __version__,
        configured_providers() or "none (rules-only mode)",
        bool(s.safe_browsing_api_key),
        bool(s.virustotal_api_key),
        bool(s.urlhaus_auth_key),
        s.supabase_enabled,
        s.langfuse_enabled,
    )
    yield
    tracing.flush()


app = FastAPI(
    lifespan=lifespan, title="ScamSach API", version=__version__, docs_url="/docs" if settings.environment != "production" else None, redoc_url=None
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)
_semaphore = asyncio.Semaphore(settings.max_concurrent_investigations)
ZERO_WIDTH = re.compile("[\u200b\u2060\ufeff\u00ad]")
GLOBAL_HOURLY_CHECKS = 150


@app.middleware("http")
async def security_headers(request: Request, call_next):  # noqa: ANN001, ANN201
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def normalize_message(text: str) -> str:
    """NFKC folds look-alike characters scammers use to dodge filters
    (e.g. bold 𝐒𝐁𝐈 -> SBI, full-width letters). Zero-width spaces are removed;
    the joiners Hindi needs (U+200C/U+200D) are kept."""
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH.sub("", text)
    text = "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C" or ch in "\u200c\u200d")
    return text.strip()


async def current_user(request: Request) -> dict | None:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
    return await verify_user(token)


async def require_user(user: dict | None = Depends(current_user)) -> dict:
    if not user:
        raise HTTPException(status_code=401, detail="Please log in to use this feature.")
    return user


def _valid_uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Case not found.") from exc


def _sse(event: dict[str, Any]) -> str:
    return f"event: {event.get('type', 'message')}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"


def _too_many(retry_after: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=429, content={"detail": message, "retry_after": retry_after}, headers={"Retry-After": str(retry_after)})


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/")
async def root() -> dict:
    return {"name": "ScamSach API", "status": "ok", "docs": "/docs"}


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/health/deep")
async def health_deep() -> dict:
    s = get_settings()
    db_ok = await store.ping() if store.enabled else None
    if db_ok:
        await store.purge_cache()  # daily keep-alive doubles as housekeeping
    return {
        "status": "ok",
        "version": __version__,
        "database": db_ok,
        "integrations": {
            "llm_providers": configured_providers(),
            "safe_browsing": bool(s.safe_browsing_api_key),
            "virustotal": bool(s.virustotal_api_key),
            "urlhaus": bool(s.urlhaus_auth_key),
            "supabase": s.supabase_enabled,
            "langfuse": s.langfuse_enabled,
        },
    }


# ---------------------------------------------------------------------------
# Investigate
# ---------------------------------------------------------------------------
class InvestigateIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)


@app.post("/api/investigate")
async def investigate(body: InvestigateIn, request: Request, user: dict | None = Depends(current_user)):
    s = get_settings()
    message = normalize_message(body.message)
    if len(message) < 3:
        raise HTTPException(status_code=422, detail="Please paste the message you want to check.")
    if len(message) > s.max_message_chars:
        raise HTTPException(status_code=422, detail=f"Message is too long (max {s.max_message_chars} characters).")

    if user:
        ok, retry = limiter.check(f"user:{user['id']}", s.user_checks_per_day, 86400)
        if not ok:
            return _too_many(retry, "Daily limit reached for your account. Please try again tomorrow.")
    else:
        ok, retry = limiter.check(f"ip:{client_ip(request)}", s.anon_checks_per_hour, 3600)
        if not ok:
            return _too_many(retry, "Too many checks from this connection. Log in for more, or try again later.")

    fingerprint = message_fingerprint(message)
    cached = cache_lookup("result", fingerprint) or await store.cache_get(fingerprint)
    if not cached:
        ok, retry = limiter.check("global", GLOBAL_HOURLY_CHECKS, 3600)
        if not ok:
            return _too_many(retry, "ScamSach is very busy right now. Please try again in a few minutes.")

    async def stream() -> AsyncIterator[str]:
        report: dict | None = None
        try:
            if cached:
                report = dict(cached)
                report["cached"] = True
                yield _sse(
                    {
                        "type": "step",
                        "id": "cache",
                        "status": "done",
                        "phase": "intake",
                        "title_en": "This exact message was checked recently - showing that result",
                        "title_hi": "यही संदेश हाल ही में जांचा गया था - वही नतीजा दिखाया जा रहा है",
                        "detail": "Saves free API quota. Results are kept for 24 hours.",
                        "finding": None,
                    }
                )
            else:
                try:
                    await asyncio.wait_for(_semaphore.acquire(), timeout=25)
                except TimeoutError:
                    yield _sse({"type": "error", "message": "ScamSach is busy. Please try again in a minute."})
                    return
                try:
                    async for event in investigate_stream(message):
                        if event.get("type") == "result":
                            report = event["report"]
                        else:
                            yield _sse(event)
                finally:
                    _semaphore.release()
                if report:
                    report["cached"] = False
                    cache_set("result", fingerprint, report, ttl=6 * 3600)
                    await store.cache_put(fingerprint, report)
            if report is None:
                yield _sse({"type": "error", "message": "Something went wrong. Please try again."})
                return
            case_id = await store.save_case(user["id"], report) if user else None
            yield _sse({"type": "result", "report": report, "case_id": case_id})
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("investigation failed")
            yield _sse({"type": "error", "message": "Something went wrong. Please try again."})
        finally:
            tracing.flush()

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# History and follow-ups (login required)
# ---------------------------------------------------------------------------
@app.get("/api/cases")
async def list_cases(user: dict = Depends(require_user)) -> dict:
    return {"cases": await store.list_cases(user["id"])}


@app.get("/api/cases/{case_id}")
async def get_case(case_id: str, user: dict = Depends(require_user)) -> dict:
    case_id = _valid_uuid(case_id)
    case = await store.get_case(user["id"], case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    case["followups"] = await store.list_followups(user["id"], case_id)
    return case


class FollowupIn(BaseModel):
    question: str = Field(..., min_length=2, max_length=500)
    lang: str = Field("en", pattern="^(en|hi)$")


@app.post("/api/cases/{case_id}/followup")
async def followup(case_id: str, body: FollowupIn, user: dict = Depends(require_user)):
    case_id = _valid_uuid(case_id)
    ok, retry = limiter.check(f"followup:{user['id']}", get_settings().followups_per_hour, 3600)
    if not ok:
        return _too_many(retry, "You have asked many questions. Please try again later.")
    case = await store.get_case(user["id"], case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    history = await store.list_followups(user["id"], case_id)
    question = normalize_message(body.question)
    answer, engine = await answer_followup(case["report"], history, question, body.lang)
    await store.add_followup(user["id"], case_id, mask_text(question).text, answer)
    tracing.flush()
    return {"answer": answer, "engine": engine}


@app.delete("/api/cases/{case_id}")
async def delete_case(case_id: str, user: dict = Depends(require_user)) -> dict:
    ok = await store.delete_case(user["id"], _valid_uuid(case_id))
    return {"deleted": ok}


@app.delete("/api/cases")
async def delete_all(user: dict = Depends(require_user)) -> dict:
    return {"deleted": await store.delete_all(user["id"])}
