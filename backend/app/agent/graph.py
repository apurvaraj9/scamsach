"""The investigation agent, built as a LangGraph state machine.

    intake -> local_checks -> plan -> run_tools --(new link found?)--> plan
                                                \\-> score -> judge -> END

- intake        extract links/UPI/phones, detect language, mask personal data
- local_checks  free offline checks: scam wording + lookalike domains
- plan          an LLM (or the rule planner as fallback) chooses which network
                checks are worth running; guardrails then enforce a safety floor
                and the free-quota budget
- run_tools     runs the chosen checks concurrently, streaming each result
- (loop)        if a short link revealed a new destination, plan again for it
                (max 2 rounds) - the destination itself is never visited
- score         deterministic risk score
- judge         LLM verdict + plain-language summary in English and Hindi,
                combined with the score under fixed rules (scoring.py)

Every node streams progress events through LangGraph's stream writer, which
the API turns into Server-Sent Events for the live UI.
"""

from __future__ import annotations

import asyncio
import json
import operator
from datetime import datetime, timezone
from typing import Annotated, Any, TypedDict

from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph

from ..config import get_settings
from ..security.masking import mask_text
from ..services.tracing import current_trace_id, observe
from ..tools import local_checks, threat_intel
from ..tools.domains import is_risky_tld, is_shortener, official_owner, parse_url
from ..tools.extract import Entities, LinkEntity, extract_entities
from ..tools.findings import Finding, errored, skipped
from ..tools.patterns import SCAM_TYPE_LABELS
from ..tools.url_expand import UnsafeTarget, expand_shortlink
from . import llm
from .next_steps import build_next_steps
from .prompts import JUDGE_SYSTEM, PLANNER_SYSTEM
from .scoring import RuleScore, combine_verdicts, score_findings

NETWORK_TOOLS = ("expand_link", "domain_age", "safe_browsing", "urlhaus", "virustotal")
LOCAL_PLANNABLE = ("upi_check", "phone_check")
ALL_TOOLS = NETWORK_TOOLS + LOCAL_PLANNABLE
MAX_ROUNDS = 2
TOOL_LABELS = {
    "expand_link": ("Finding where the short link leads", "छोटा लिंक कहाँ ले जाता है, यह पता करना"),
    "domain_age": ("Checking how old the website is", "वेबसाइट कितनी पुरानी है, यह जांचना"),
    "safe_browsing": ("Checking Google Safe Browsing", "Google Safe Browsing में जांच"),
    "urlhaus": ("Checking the URLhaus malware database", "URLhaus मैलवेयर सूची में जांच"),
    "virustotal": ("Checking with 70+ security vendors (VirusTotal)", "70+ सुरक्षा कंपनियों से जांच (VirusTotal)"),
    "upi_check": ("Checking the UPI ID", "UPI ID की जांच"),
    "phone_check": ("Checking the phone number", "फ़ोन नंबर की जांच"),
}
DISCLAIMER = {
    "en": "This verdict is guidance based on automated checks, not a guarantee. Protection is never perfect: "
    "when in doubt, contact the organisation through its official number or website.",
    "hi": "यह नतीजा स्वचालित जांच पर आधारित सलाह है, गारंटी नहीं। कोई भी सुरक्षा पूरी तरह सटीक नहीं होती: शक हो तो संस्था के आधिकारिक नंबर या वेबसाइट से संपर्क करें।",
}


class AgentState(TypedDict, total=False):
    message: str  # raw text: stays in server memory only
    masked: str
    mask_counts: dict[str, int]
    entities: Entities
    inventory: dict[str, dict[str, Any]]
    plan: list[dict[str, str]]
    planner: dict[str, Any]
    findings: Annotated[list[Finding], operator.add]
    done_calls: Annotated[list[str], operator.add]
    pending_links: list[str]
    round: int
    vt_used: bool
    rule: RuleScore
    report: dict[str, Any]


def _emit(event: dict[str, Any]) -> None:
    try:
        get_stream_writer()(event)
    except Exception:  # noqa: S110 - no stream outside a graph run (e.g. unit tests)
        pass


def _step(step_id: str, status: str, en: str, hi: str, detail: str = "", finding: Finding | None = None, phase: str = "") -> None:
    _emit(
        {
            "type": "step",
            "id": step_id,
            "status": status,
            "phase": phase,
            "title_en": en,
            "title_hi": hi,
            "detail": detail,
            "finding": finding.to_dict() if finding else None,
        }
    )


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------
async def intake(state: AgentState) -> dict:
    with observe("intake", as_type="span") as span:
        _step("intake", "running", "Reading the message", "संदेश पढ़ा जा रहा है", phase="intake")
        ent = extract_entities(state["message"])
        masked = mask_text(state["message"])
        inventory: dict[str, dict[str, Any]] = {}
        for i, link in enumerate(ent.links, 1):
            inventory[f"L{i}"] = {"kind": "link", "link": link}
        for i, upi in enumerate(ent.upi_ids, 1):
            inventory[f"U{i}"] = {"kind": "upi", "upi": upi}
        for i, phone in enumerate(ent.phones, 1):
            inventory[f"P{i}"] = {"kind": "phone", "phone": phone}
        lang_names = {"en": ("English", "अंग्रेज़ी"), "hi": ("Hindi", "हिंदी"), "hinglish": ("Hinglish", "हिंग्लिश")}
        found = f"{len(ent.links)} link(s), {len(ent.upi_ids)} UPI ID(s), {len(ent.phones)} phone number(s)"
        _step(
            "intake",
            "done",
            f"Read the message ({lang_names[ent.language][0]})",
            f"संदेश पढ़ लिया ({lang_names[ent.language][1]})",
            detail=f"Found {found}.",
            phase="intake",
        )
        if masked.total:
            items = ", ".join(f"{v} {k.lower()}" for k, v in masked.counts.items())
            _step(
                "privacy",
                "done",
                f"Hid {masked.total} personal detail(s) before AI analysis",
                f"AI जांच से पहले {masked.total} निजी जानकारी छुपा दी",
                detail=f"Masked: {items}.",
                phase="intake",
            )
        span.update(output={"entities": ent.summary_for_llm(), "masked_counts": masked.counts})
    return {
        "entities": ent,
        "masked": masked.text,
        "mask_counts": masked.counts,
        "inventory": inventory,
        "round": 0,
        "vt_used": False,
        "pending_links": [k for k in inventory if k.startswith("L")],
    }


async def local_checks_node(state: AgentState) -> dict:
    findings: list[Finding] = []
    with observe("local_checks", as_type="tool") as span:
        _step("patterns", "running", "Looking for known scam wording", "जाने-पहचाने धोखे वाले शब्द खोजे जा रहे हैं", phase="local")
        pats = local_checks.pattern_scan(state["message"])
        findings += pats
        bad = [f for f in pats if f.signal in ("danger", "warning")]
        if bad:
            _step("patterns", "done", f"Found {len(bad)} warning sign(s) in the wording", f"शब्दों में {len(bad)} चेतावनी संकेत मिले", phase="local")
        else:
            _step("patterns", "done", "No known scam wording", "कोई जाना-पहचाना धोखे वाला शब्द नहीं", phase="local")
        for f in pats:
            if f.signal != "info":
                _step(f"pattern:{f.data.get('rule')}", "done", f.title_en, f.title_hi, f.detail, f, phase="local")

        for key, item in state["inventory"].items():
            if item["kind"] != "link":
                continue
            link: LinkEntity = item["link"]
            _step(f"lookalike:{key}", "running", f"Inspecting the web address {link.host}", f"वेब पता {link.host} जांचा जा रहा है", phase="local")
            for f in local_checks.lookalike_check(link):
                findings.append(f)
                _step(f"lookalike:{key}", "done", f.title_en, f.title_hi, f.detail, f, phase="local")
        span.update(output=[f.title_en for f in findings])
    return {"findings": findings}


def _inventory_for_llm(state: AgentState, keys: list[str]) -> list[dict]:
    out = []
    for key in keys:
        item = state["inventory"][key]
        if item["kind"] == "link":
            link: LinkEntity = item["link"]
            out.append(
                {
                    "id": key,
                    "type": "link",
                    "host": link.host,
                    "official_owner": link.official_owner,
                    "shortener": link.is_shortener,
                    "apk": link.is_apk,
                    "risky_tld": link.risky_tld,
                }
            )
        elif item["kind"] == "upi":
            out.append({"id": key, "type": "upi_id", "handle": "@" + item["upi"].handle})
        else:
            p = item["phone"]
            out.append({"id": key, "type": "phone", "kind": p.kind, "country": p.country})
    return out


def _rule_plan(state: AgentState, keys: list[str], has_hard_local: bool) -> list[dict[str, str]]:
    calls: list[dict[str, str]] = []
    s = get_settings()
    for key in keys:
        item = state["inventory"][key]
        if item["kind"] == "upi":
            calls.append({"tool": "upi_check", "target": key, "reason": "UPI IDs are how scammers collect money."})
        elif item["kind"] == "phone":
            calls.append({"tool": "phone_check", "target": key, "reason": "See if the number is foreign or a fake helpline."})
        else:
            link: LinkEntity = item["link"]
            if link.official_owner:
                continue
            if link.is_shortener:
                calls.append({"tool": "expand_link", "target": key, "reason": "Short links hide the real address."})
                continue
            calls.append({"tool": "domain_age", "target": key, "reason": "Scam websites are usually very new."})
            if s.virustotal_api_key and not has_hard_local and not state.get("vt_used"):
                calls.append({"tool": "virustotal", "target": key, "reason": "Ask many security vendors at once."})
    return calls


def _guardrails(state: AgentState, keys: list[str], proposed: list[dict]) -> list[dict[str, str]]:
    """Validate the planner's choices and enforce the safety floor."""
    done = set(state.get("done_calls", []))
    allowed = set(keys)
    final: list[dict[str, str]] = []
    seen: set[str] = set()
    vt_budget = 0 if state.get("vt_used") else 1

    def add(tool: str, target: str, reason: str, source: str) -> None:
        nonlocal vt_budget
        sig = f"{tool}:{target}"
        if sig in seen or sig in done or target not in allowed or tool not in ALL_TOOLS:
            return
        kind = state["inventory"][target]["kind"]
        if (tool in NETWORK_TOOLS and kind != "link") or (tool == "upi_check" and kind != "upi") or (tool == "phone_check" and kind != "phone"):
            return
        if tool == "expand_link" and not state["inventory"][target]["link"].is_shortener:
            return
        if tool == "virustotal":
            if vt_budget <= 0:
                return
            vt_budget -= 1
        seen.add(sig)
        final.append({"tool": tool, "target": target, "reason": reason[:120], "source": source})

    for call in proposed:
        add(str(call.get("tool", "")), str(call.get("target", "")), str(call.get("reason", "")), "planner")

    # Safety floor: free checks we always run, whatever the planner said.
    for key in keys:
        item = state["inventory"][key]
        if item["kind"] == "upi":
            add("upi_check", key, "Always checked: UPI IDs are how scammers collect money.", "safety floor")
        elif item["kind"] == "phone":
            add("phone_check", key, "Always checked: phone numbers in the message.", "safety floor")
        else:
            link: LinkEntity = item["link"]
            if link.is_shortener:
                add("expand_link", key, "Always checked: short links hide the real address.", "safety floor")
            elif not link.official_owner:
                add("safe_browsing", key, "Always checked: Google's list of known dangerous sites.", "safety floor")
                add("urlhaus", key, "Always checked: database of malware links.", "safety floor")
    return final


async def plan(state: AgentState) -> dict:
    keys = list(state.get("pending_links", [])) if state.get("round", 0) > 0 else list(state["inventory"].keys())
    rnd = state.get("round", 0)
    has_hard_local = any(f.hard and f.signal == "danger" for f in state.get("findings", []))
    planner: dict[str, Any] = dict(state.get("planner") or {})

    with observe("plan", as_type="chain", metadata={"round": rnd}) as span:
        if rnd == 0:
            _step("plan", "running", "Deciding which checks are worth running", "तय किया जा रहा है कि कौन-सी जांच ज़रूरी है", phase="plan")
        if not keys:
            proposed: list[dict] = []
            planner.setdefault("by", "rules")
        elif rnd == 0 and llm.configured_providers():
            user = json.dumps(
                {
                    "message": f"<message>{state['masked']}</message>",
                    "inventory": _inventory_for_llm(state, keys),
                    "already_found_locally": [f.title_en for f in state.get("findings", []) if f.signal in ("danger", "warning")],
                    "virustotal_available": bool(get_settings().virustotal_api_key),
                },
                ensure_ascii=False,
            )
            providers = [p.strip() for p in get_settings().planner_providers.split(",")]
            res = await llm.complete_json("planner", PLANNER_SYSTEM, user, providers)
            if res.data and isinstance(res.data.get("calls"), list):
                proposed = res.data["calls"]
                planner = {"by": "ai", "provider": res.provider, "model": res.model, "hypothesis": str(res.data.get("hypothesis", ""))[:240]}
            else:
                proposed = _rule_plan(state, keys, has_hard_local)
                planner = {"by": "rules", "note": "AI planner unavailable; used rule planner."}
        else:
            proposed = _rule_plan(state, keys, has_hard_local)
            planner.setdefault("by", "rules")

        calls = _guardrails(state, keys, proposed)
        span.update(output={"calls": calls, "planner": planner})

    if rnd == 0:
        who_en = "AI planner" if planner.get("by") == "ai" else "Rule planner"
        who_hi = "AI योजनाकार" if planner.get("by") == "ai" else "नियम-आधारित योजनाकार"
        _step(
            "plan",
            "done",
            f"{who_en} chose {len(calls)} check(s)",
            f"{who_hi} ने {len(calls)} जांच चुनीं",
            detail=planner.get("hypothesis", ""),
            phase="plan",
        )
    else:
        _step(
            f"plan:r{rnd}",
            "done",
            "Following the short link's destination (without opening it)",
            "छोटे लिंक की मंज़िल की जांच (उसे खोले बिना)",
            phase="plan",
        )
    _emit(
        {
            "type": "plan",
            "round": rnd,
            "planner": planner,
            "calls": [{k: c[k] for k in ("tool", "target", "reason", "source")} | {"target_label": _target_label(state, c["target"])} for c in calls],
        }
    )
    return {"plan": calls, "planner": planner, "pending_links": []}


def _target_label(state: AgentState, key: str) -> str:
    item = state["inventory"].get(key, {})
    if item.get("kind") == "link":
        return item["link"].host
    if item.get("kind") == "upi":
        u = item["upi"]
        return f"{u.name[:2]}***@{u.handle}"
    if item.get("kind") == "phone":
        return "*" * max(0, len(item["phone"].digits) - 4) + item["phone"].digits[-4:]
    return key


async def _run_one(state: AgentState, call: dict[str, str]) -> tuple[list[Finding], LinkEntity | None]:
    tool, key = call["tool"], call["target"]
    item = state["inventory"][key]
    label = _target_label(state, key)
    settings = get_settings()
    new_link: LinkEntity | None = None

    if tool == "upi_check":
        return [local_checks.upi_check(item["upi"])], None
    if tool == "phone_check":
        scam_context = any(
            f.tool == "pattern_scan" and (f.signal == "danger" or f.data.get("rule") in ("call_mobile_helpline", "threat"))
            for f in state.get("findings", [])
        )
        return [local_checks.phone_check(item["phone"], scam_context)], None

    link: LinkEntity = item["link"]
    if not settings.enable_network_tools:
        return [skipped(tool, label, "Network checks are switched off (offline mode).")], None
    try:
        if tool == "safe_browsing":
            return [await threat_intel.safe_browsing(link.url)], None
        if tool == "urlhaus":
            return [await threat_intel.urlhaus(link.url, link.host)], None
        if tool == "virustotal":
            return [await threat_intel.virustotal(link.url, link.registered)], None
        if tool == "domain_age":
            if link.is_ip:
                return [skipped(tool, label, "IP addresses have no registration date.", "RDAP")], None
            return [await threat_intel.domain_age(link.registered)], None
        if tool == "expand_link":
            res = await expand_shortlink(link.url)
            if res.final_url:
                parsed = parse_url(res.final_url)
                hops = len(res.chain) - 1
                f = Finding(
                    "expand_link",
                    label,
                    "warning",
                    f"Short link leads to {parsed.host if parsed else '?'}",
                    f"छोटा लिंक {parsed.host if parsed else '?'} पर ले जाता है",
                    detail=f"Resolved in {hops} hop(s) by asking the shortener only. The destination itself was not opened.",
                    source_name="Link shortener (redirect header)",
                    weight=5,
                    data={"final_url": res.final_url},
                )
                if parsed:
                    new_link = LinkEntity(
                        raw=res.final_url,
                        url=parsed.url,
                        host=parsed.host,
                        registered=parsed.registered,
                        suffix=parsed.suffix,
                        official_owner=official_owner(parsed.host),
                        is_shortener=is_shortener(parsed.host),
                        is_ip=parsed.is_ip,
                        risky_tld=is_risky_tld(parsed.suffix) if parsed.suffix else False,
                        is_apk=parsed.url.lower().split("?")[0].endswith(".apk"),
                        uses_http=parsed.scheme == "http",
                    )
                return [f], new_link
            return [
                Finding(
                    "expand_link",
                    label,
                    "warning",
                    "Could not see where the short link leads",
                    "छोटा लिंक कहाँ ले जाता है, पता नहीं चल सका",
                    detail=res.note,
                    source_name="Link shortener",
                    weight=5,
                )
            ], None
    except UnsafeTarget as exc:
        return [errored(tool, label, f"Blocked for safety: {exc}.")], None
    except Exception as exc:  # one failing tool must never break the investigation
        return [errored(tool, label, f"{type(exc).__name__}")], None
    return [skipped(tool, label, "Unknown tool.")], None


async def run_tools(state: AgentState) -> dict:
    calls = state.get("plan", [])
    inventory = dict(state["inventory"])
    findings: list[Finding] = []
    new_keys: list[str] = []
    vt_used = state.get("vt_used", False) or any(c["tool"] == "virustotal" for c in calls)

    async def run(call: dict[str, str]) -> tuple[dict, list[Finding], LinkEntity | None]:
        en, hi = TOOL_LABELS[call["tool"]]
        sid = f"{call['tool']}:{call['target']}"
        _step(sid, "running", en, hi, detail=_target_label(state, call["target"]), phase="tools")
        with observe(f"tool:{call['tool']}", as_type="tool", input={"target": _target_label(state, call["target"])}) as sp:
            fs, new_link = await asyncio.wait_for(_run_one(state, call), timeout=15)
            sp.update(output=[f.title_en for f in fs])
        for f in fs:
            _step(sid, "done", f.title_en, f.title_hi, f.detail, f, phase="tools")
        return call, fs, new_link

    results = await asyncio.gather(*(run(c) for c in calls), return_exceptions=True)
    for call, res in zip(calls, results, strict=True):
        if isinstance(res, BaseException):
            f = errored(call["tool"], _target_label(state, call["target"]), "Timed out.")
            findings.append(f)
            _step(f"{call['tool']}:{call['target']}", "done", f.title_en, f.title_hi, f.detail, f, phase="tools")
            continue
        _, fs, new_link = res
        findings += fs
        if new_link:
            key = f"L{sum(1 for k in inventory if k.startswith('L')) + 1}"
            inventory[key] = {"kind": "link", "link": new_link, "via": call["target"]}
            new_keys.append(key)
            for f in local_checks.lookalike_check(new_link):
                findings.append(f)
                _step(f"lookalike:{key}", "done", f.title_en, f.title_hi, f.detail, f, phase="tools")

    return {
        "findings": findings,
        "inventory": inventory,
        "pending_links": new_keys,
        "round": state.get("round", 0) + 1,
        "vt_used": vt_used,
        "done_calls": [f"{c['tool']}:{c['target']}" for c in calls],
    }


def after_tools(state: AgentState) -> str:
    if state.get("pending_links") and state.get("round", 0) < MAX_ROUNDS:
        return "plan"
    return "score"


async def score(state: AgentState) -> dict:
    rule = score_findings(state.get("findings", []))
    _step(
        "score",
        "done",
        f"Risk score: {rule.score}/100",
        f"जोखिम स्कोर: {rule.score}/100",
        detail="Hard evidence: " + "; ".join(rule.hard_reasons) if rule.hard_reasons else "",
        phase="score",
    )
    return {"rule": rule}


def _fallback_summary(verdict: str, findings: list[Finding]) -> tuple[dict, dict]:
    """Rule-based explanation, used when no LLM answer is available. The
    reasons are listed separately (red flags), so the summary stays short."""
    bad = sorted([f for f in findings if f.signal in ("danger", "warning")], key=lambda f: -f.weight)[:4]
    if verdict == "scam":
        summary = {
            "en": f"This message has {len(bad)} clear sign(s) of a scam, listed below. Do not click, call, reply or pay.",
            "hi": f"इस संदेश में धोखे के {len(bad)} साफ़ संकेत हैं, जो नीचे लिखे हैं। क्लिक, कॉल, जवाब या भुगतान न करें।",
        }
    elif verdict == "suspicious":
        summary = {
            "en": "Some warning signs were found (listed below). Treat it as suspicious and check through official channels.",
            "hi": "कुछ चेतावनी संकेत मिले (नीचे लिखे हैं)। इसे संदिग्ध मानें और आधिकारिक माध्यम से जांचें।",
        }
    else:
        summary = {
            "en": "We did not find scam signs. It looks like a normal message, but never share your OTP or PIN.",
            "hi": "हमें धोखे के संकेत नहीं मिले। यह सामान्य संदेश लगता है, फिर भी अपना OTP या PIN कभी न बताएं।",
        }
    flags = {"en": [f.title_en for f in bad], "hi": [f.title_hi for f in bad]}
    return summary, flags


async def judge(state: AgentState) -> dict:
    rule: RuleScore = state["rule"]
    findings = state.get("findings", [])
    _step("judge", "running", "Weighing the evidence", "सबूतों को तौला जा रहा है", phase="judge")

    llm_data: dict | None = None
    engine = "rules"
    if llm.configured_providers():
        evidence = [
            {"tool": f.tool, "target": f.target, "signal": f.signal, "finding": f.title_en, "detail": f.detail, "source": f.source_name}
            for f in findings
            if f.signal not in ("skipped",)
        ]
        user = json.dumps(
            {
                "message": f"<message>{state['masked']}</message>",
                "evidence": evidence,
                "rule_score": rule.score,
                "rule_verdict": rule.verdict,
                "hard_evidence": rule.hard_reasons,
            },
            ensure_ascii=False,
        )
        system = JUDGE_SYSTEM
        providers = [p.strip() for p in get_settings().judge_providers.split(",")]
        res = await llm.complete_json("judge", system, user, providers)
        if res.data and res.data.get("verdict") in ("scam", "suspicious", "likely_safe"):
            llm_data = res.data
            engine = f"ai:{res.provider}/{res.model}"

    conf = None
    if llm_data:
        try:
            conf = max(0.0, min(1.0, float(llm_data.get("confidence", 0.5))))
        except (TypeError, ValueError):
            conf = 0.5
    final, decision = combine_verdicts(rule, llm_data.get("verdict") if llm_data else None, conf)

    scam_type = rule.scam_type
    if llm_data and llm_data.get("scam_type") in SCAM_TYPE_LABELS and (rule.scam_type in ("other", "none") or not rule.hard_reasons):
        scam_type = llm_data["scam_type"] if final != "likely_safe" else "none"
    if final != "likely_safe" and scam_type == "none":
        scam_type = "other"
    if final == "likely_safe":
        scam_type = "none"

    fb_summary, fb_flags = _fallback_summary(final, findings)
    if llm_data and llm_data.get("verdict") == final:
        summary = {"en": str(llm_data.get("summary_en") or fb_summary["en"])[:600], "hi": str(llm_data.get("summary_hi") or fb_summary["hi"])[:600]}
        flags = {
            "en": [str(x)[:160] for x in (llm_data.get("red_flags_en") or [])][:4] or fb_flags["en"],
            "hi": [str(x)[:160] for x in (llm_data.get("red_flags_hi") or [])][:4] or fb_flags["hi"],
        }
        summary_by = "ai"
    else:  # never show an AI explanation that argues for a different verdict
        summary, flags, summary_by = fb_summary, fb_flags, "rules"

    impersonates = next((f.data.get("impersonates") for f in findings if f.data.get("impersonates")), None)
    links = [item["link"].host for item in state["inventory"].values() if item["kind"] == "link"]
    confidence = conf if (llm_data and llm_data.get("verdict") == final) else (0.9 if rule.hard_reasons else 0.6)

    report = {
        "verdict": final,
        "risk_score": rule.score,
        "scam_type": scam_type,
        "scam_type_label": {"en": SCAM_TYPE_LABELS[scam_type][0], "hi": SCAM_TYPE_LABELS[scam_type][1]},
        "confidence": round(confidence, 2),
        "summary": summary,
        "red_flags": flags,
        "summary_by": summary_by,
        "decision_note": decision,
        "hard_evidence": rule.hard_reasons,
        "findings": [f.to_dict() for f in findings],
        "plan": {"planner": state.get("planner", {}), "calls": state.get("plan", [])},
        "next_steps": build_next_steps(final, scam_type, impersonates, links),
        "impersonates": impersonates,
        "links": links,
        "language_detected": state["entities"].language,
        "masked_message": state["masked"],
        "privacy": {"masked_counts": state.get("mask_counts", {})},
        "engine": {"planner": state.get("planner", {}).get("by", "rules"), "judge": engine},
        "disclaimer": DISCLAIMER,
        "trace_id": current_trace_id(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    labels = {
        "scam": ("Verdict: SCAM", "नतीजा: धोखा"),
        "suspicious": ("Verdict: SUSPICIOUS", "नतीजा: संदिग्ध"),
        "likely_safe": ("Verdict: LIKELY SAFE", "नतीजा: शायद सुरक्षित"),
    }
    _step("judge", "done", labels[final][0], labels[final][1], detail=decision, phase="judge")
    return {"report": report}


def build_graph():
    g = StateGraph(AgentState)
    g.add_node("intake", intake)
    g.add_node("local_checks", local_checks_node)
    g.add_node("plan", plan)
    g.add_node("run_tools", run_tools)
    g.add_node("score", score)
    g.add_node("judge", judge)
    g.add_edge(START, "intake")
    g.add_edge("intake", "local_checks")
    g.add_edge("local_checks", "plan")
    g.add_edge("plan", "run_tools")
    g.add_conditional_edges("run_tools", after_tools, {"plan": "plan", "score": "score"})
    g.add_edge("score", "judge")
    g.add_edge("judge", END)
    return g.compile()


GRAPH = build_graph()


async def investigate_stream(message: str):
    """Yield progress events, ending with {"type": "result", "report": ...}."""
    with observe("investigate", as_type="agent", input={"message": mask_text(message).text}) as span:
        final_state: dict[str, Any] = {}
        async for mode, chunk in GRAPH.astream({"message": message, "findings": [], "done_calls": []}, stream_mode=["custom", "values"]):
            if mode == "custom":
                yield chunk
            else:
                final_state = chunk
        report = final_state.get("report")
        span.update(output={"verdict": report and report["verdict"], "score": report and report["risk_score"]})
    yield {"type": "result", "report": report}


async def investigate(message: str) -> dict:
    report = None
    async for ev in investigate_stream(message):
        if ev.get("type") == "result":
            report = ev["report"]
    return report
