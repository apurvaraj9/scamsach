"""Answer a follow-up question about a past case (the agent's long-term
memory is the case record in Postgres plus the earlier Q&A on that case)."""

from __future__ import annotations

import json

from ..config import get_settings
from ..security.masking import mask_text
from . import llm
from .prompts import FOLLOWUP_SYSTEM, language_name


def _fallback(report: dict, lang: str) -> str:
    verdict = report.get("verdict", "suspicious")
    if lang == "hi":
        v = {"scam": "धोखा", "suspicious": "संदिग्ध", "likely_safe": "शायद सुरक्षित"}.get(verdict, verdict)
        return (
            f"AI सहायक अभी व्यस्त है। इस केस का नतीजा: {v}। अगर पैसे गए हैं तो तुरंत 1930 पर कॉल करें और "
            "cybercrime.gov.in पर शिकायत करें। पैसे नहीं गए तो संदेश को चक्षु (sancharsaathi.gov.in/sfc) पर रिपोर्ट करें।"
        )
    v = {"scam": "scam", "suspicious": "suspicious", "likely_safe": "likely safe"}.get(verdict, verdict)
    return (
        f"The AI assistant is busy right now. This case was judged: {v}. If you lost money, call 1930 now and "
        "file at cybercrime.gov.in. If not, report the message on Chakshu (sancharsaathi.gov.in/sfc)."
    )


async def answer_followup(report: dict, history: list[dict], question: str, lang: str) -> tuple[str, str]:
    """Return (answer, engine)."""
    masked_q = mask_text(question).text
    context = {
        "case": {
            "verdict": report.get("verdict"),
            "scam_type": report.get("scam_type"),
            "summary": (report.get("summary") or {}).get("en"),
            "evidence": [
                {"finding": f.get("title_en"), "detail": f.get("detail"), "source": f.get("source_name")}
                for f in report.get("findings", [])
                if f.get("signal") in ("danger", "warning", "ok")
            ][:12],
            "message": f"<message>{report.get('masked_message', '')}</message>",
        },
        "previous_questions": [{"q": h.get("question"), "a": h.get("answer")} for h in history[-4:]],
        "question": masked_q,
    }
    system = FOLLOWUP_SYSTEM.replace("{language_name}", language_name(lang))
    providers = [p.strip() for p in get_settings().judge_providers.split(",")]
    res = await llm.complete_json("followup", system, json.dumps(context, ensure_ascii=False), providers)
    if res.data and isinstance(res.data.get("answer"), str) and res.data["answer"].strip():
        return res.data["answer"].strip()[:1500], f"ai:{res.provider}"
    return _fallback(report, lang), "rules"
