"""Deterministic risk scoring and the rules for combining it with the LLM.

Why both? The rules are cheap, explainable and cannot be talked out of a
verdict by text inside the message. The LLM understands wording the rules
miss (new scam scripts, Hinglish phrasing). The combination policy:

1. Hard evidence (threat-intel listing, brand lookalike, APK link, 'enter PIN
   to receive', 'digital arrest') => scam. The LLM cannot overrule this.
2. Otherwise the LLM may raise the level. A jump from 'likely_safe' straight
   to 'scam' needs confidence >= 0.8, else it is capped at 'suspicious'.
3. The LLM may lower the level by one step only, only when confident
   (>= 0.85), and never when the rule score is high (>= 70).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..tools.findings import Finding

LEVELS = {"likely_safe": 0, "suspicious": 1, "scam": 2}
NAMES = {v: k for k, v in LEVELS.items()}
SCAM_THRESHOLD = 55
SUSPICIOUS_THRESHOLD = 25


@dataclass
class RuleScore:
    score: int
    verdict: str
    hard_reasons: list[str]
    scam_type: str


def score_findings(findings: list[Finding]) -> RuleScore:
    total = 0
    hard: list[str] = []
    typed: list[tuple[int, int, str]] = []
    for f in findings:
        if f.signal in ("skipped", "error"):
            continue
        total += f.weight
        if f.hard and f.signal == "danger":
            hard.append(f.title_en)
        if f.scam_type and f.weight > 0:
            typed.append((1 if f.hard else 0, f.weight, f.scam_type))
    score = max(0, min(100, total))
    if hard:
        score = max(score, 85)
        verdict = "scam"
    elif score >= SCAM_THRESHOLD:
        verdict = "scam"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "likely_safe"

    # Prefer a specific scam story (kyc, courier...) over the generic "phishing".
    specific = [t for t in typed if t[2] != "phishing"]
    pool = specific or typed
    scam_type = max(pool)[2] if pool and verdict != "likely_safe" else ("none" if verdict == "likely_safe" else "other")
    return RuleScore(score=score, verdict=verdict, hard_reasons=hard, scam_type=scam_type)


def combine_verdicts(rule: RuleScore, llm_verdict: str | None, llm_confidence: float | None) -> tuple[str, str]:
    """Return (final_verdict, explanation_of_how_it_was_decided)."""
    if rule.hard_reasons:
        return "scam", "Hard evidence from our checks decided the verdict."
    if llm_verdict not in LEVELS:
        return rule.verdict, "Decided by our rule checks (AI analysis unavailable)."
    conf = llm_confidence if isinstance(llm_confidence, (int, float)) else 0.5
    r, m = LEVELS[rule.verdict], LEVELS[llm_verdict]
    if m == r:
        return rule.verdict, "Rule checks and AI analysis agree."
    if m > r:
        if m - r >= 2 and conf < 0.8:
            return NAMES[r + 1], "AI analysis raised the risk level (capped one step: not fully confident)."
        return llm_verdict, "AI analysis spotted risks the rules missed and raised the level."
    if conf >= 0.85 and rule.score < 70:
        return NAMES[r - 1], "AI analysis was confident the risk is lower and lowered the level by one step."
    return rule.verdict, "Rule checks kept the higher risk level."
