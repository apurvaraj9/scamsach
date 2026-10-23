"""Lookups against free threat-intelligence and registry services.

All of these are *lookups by URL/domain name* sent to the service; none of
them touches the suspicious website itself. Results are cached to respect
the free quotas, and every function degrades to a 'skipped' finding when
its key is missing or its quota is used up, so the agent never crashes.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

import httpx

from ..config import get_settings
from .cache import Quota, cache_lookup, cache_set
from .findings import Finding, errored, skipped

TIMEOUT = httpx.Timeout(8.0, connect=4.0)
SB_ADVISORY = "https://developers.google.com/safe-browsing/v4/advisory"

_vt_quota: Quota | None = None


def _vt() -> Quota:
    global _vt_quota
    if _vt_quota is None:
        s = get_settings()
        _vt_quota = Quota(per_minute=s.virustotal_per_minute, per_day=s.virustotal_daily_budget)
    return _vt_quota


# ---------------------------------------------------------------------------
# Google Safe Browsing (Lookup API v4) - free, non-commercial use only.
# ---------------------------------------------------------------------------
async def safe_browsing(url: str) -> Finding:
    tool, src = "safe_browsing", "Google Safe Browsing"
    key = get_settings().safe_browsing_api_key
    if not key:
        return skipped(tool, url, "Safe Browsing key not configured.", src)
    cached = cache_lookup(tool, url)
    if cached:
        return cached
    body = {
        "client": {"clientId": "scamsach", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        # Key goes in a header, not the URL, so it can never end up in logs.
        async with httpx.AsyncClient(timeout=TIMEOUT, headers={"X-Goog-Api-Key": key}) as c:
            r = await c.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", json=body)
        r.raise_for_status()
        matches = r.json().get("matches", [])
    except httpx.HTTPError as exc:
        return errored(tool, url, f"Safe Browsing unavailable ({type(exc).__name__}).", src)

    if matches:
        kinds = sorted({m.get("threatType", "UNKNOWN").replace("_", " ").lower() for m in matches})
        ttl = float(str(matches[0].get("cacheDuration", "300s")).rstrip("s") or 300)
        f = Finding(
            tool,
            url,
            "danger",
            "Google Safe Browsing lists this link as unsafe",
            "Google Safe Browsing ने इस लिंक को असुरक्षित बताया है",
            detail=f"Flagged as: {', '.join(kinds)}. Advisory provided by Google.",
            source_name=src,
            source_url=SB_ADVISORY,
            weight=100,
            hard=True,
            scam_type="phishing",
        )
        cache_set(tool, url, f, ttl=ttl)
    else:
        f = Finding(
            tool,
            url,
            "info",
            "Not on Google's unsafe-sites list",
            "Google की असुरक्षित-साइट सूची में नहीं",
            detail="Not listed yet. New scam sites often are not listed for the first hours or days.",
            source_name=src,
            source_url=SB_ADVISORY,
        )
        cache_set(tool, url, f, ttl=300)
    return f


# ---------------------------------------------------------------------------
# URLhaus (abuse.ch) - malware distribution URLs. Needs a free Auth-Key.
# ---------------------------------------------------------------------------
async def urlhaus(url: str, host: str) -> Finding:
    tool, src = "urlhaus", "URLhaus (abuse.ch)"
    key = get_settings().urlhaus_auth_key
    if not key:
        return skipped(tool, url, "URLhaus key not configured.", src)
    cached = cache_lookup(tool, url)
    if cached:
        return cached
    headers = {"Auth-Key": key}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=headers) as c:
            r = await c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
            r.raise_for_status()
            data = r.json()
            if data.get("query_status") != "ok":
                r2 = await c.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host})
                r2.raise_for_status()
                host_data = r2.json()
            else:
                host_data = None
    except (httpx.HTTPError, ValueError) as exc:
        return errored(tool, url, f"URLhaus unavailable ({type(exc).__name__}).", src)

    if data.get("query_status") == "ok":
        f = Finding(
            tool,
            url,
            "danger",
            "URLhaus lists this link as spreading malware",
            "URLhaus ने इस लिंक को मैलवेयर फैलाने वाला बताया है",
            detail=f"Status: {data.get('url_status', 'unknown')}; threat: {data.get('threat', 'unknown')}.",
            source_name=src,
            source_url=data.get("urlhaus_reference", "https://urlhaus.abuse.ch/"),
            weight=100,
            hard=True,
            scam_type="malicious_app",
        )
    elif host_data and host_data.get("query_status") == "ok" and int(host_data.get("url_count", 0) or 0) > 0:
        f = Finding(
            tool,
            host,
            "danger",
            "This website has hosted malware before",
            "यह वेबसाइट पहले मैलवेयर फैला चुकी है",
            detail=f"URLhaus has {host_data.get('url_count')} malware link(s) on this host.",
            source_name=src,
            source_url=host_data.get("urlhaus_reference", "https://urlhaus.abuse.ch/"),
            weight=70,
            hard=True,
            scam_type="malicious_app",
        )
    else:
        f = Finding(
            tool,
            url,
            "info",
            "Not in the URLhaus malware database",
            "URLhaus मैलवेयर सूची में नहीं",
            source_name=src,
            source_url="https://urlhaus.abuse.ch/",
        )
    cache_set(tool, url, f, ttl=3600)
    return f


# ---------------------------------------------------------------------------
# VirusTotal public API - 4 requests/minute, 500/day, non-commercial.
# Used sparingly: only when the planner decides it adds value.
# ---------------------------------------------------------------------------
async def virustotal(url: str, domain: str) -> Finding:
    tool, src = "virustotal", "VirusTotal"
    key = get_settings().virustotal_api_key
    if not key:
        return skipped(tool, url, "VirusTotal key not configured.", src)
    cached = cache_lookup(tool, url)
    if cached:
        return cached
    if not _vt().try_acquire():
        return skipped(tool, url, "VirusTotal free quota reached for now; other checks still ran.", src)

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": key}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=headers) as c:
            r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}")
            target, ref = url, f"https://www.virustotal.com/gui/url/{url_id}"
            if r.status_code == 404:
                if not _vt().try_acquire():
                    return skipped(tool, url, "VirusTotal free quota reached for now.", src)
                r = await c.get(f"https://www.virustotal.com/api/v3/domains/{domain}")
                target, ref = domain, f"https://www.virustotal.com/gui/domain/{domain}"
            if r.status_code == 404:
                f = Finding(
                    tool,
                    url,
                    "info",
                    "VirusTotal has no record of this link yet",
                    "VirusTotal में इस लिंक का कोई रिकॉर्ड नहीं",
                    source_name=src,
                    source_url="https://www.virustotal.com/",
                )
                cache_set(tool, url, f, ttl=3600)
                return f
            r.raise_for_status()
            stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return errored(tool, url, f"VirusTotal unavailable ({type(exc).__name__}).", src)

    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    detail = f"{mal} of {total} security vendors say malicious, {sus} say suspicious."
    if mal >= 2:
        f = Finding(
            tool,
            target,
            "danger",
            "Security vendors on VirusTotal flag this",
            "VirusTotal पर सुरक्षा कंपनियों ने इसे खतरनाक बताया",
            detail=detail,
            source_name=src,
            source_url=ref,
            weight=90,
            hard=True,
            scam_type="phishing",
        )
    elif mal == 1 or sus >= 1:
        f = Finding(
            tool,
            target,
            "warning",
            "One or two vendors on VirusTotal are suspicious",
            "VirusTotal पर एक-दो कंपनियों को शक है",
            detail=detail,
            source_name=src,
            source_url=ref,
            weight=25,
        )
    else:
        f = Finding(
            tool,
            target,
            "info",
            "No VirusTotal vendor flags this yet",
            "VirusTotal पर अभी किसी ने इसे खतरनाक नहीं बताया",
            detail=detail,
            source_name=src,
            source_url=ref,
        )
    cache_set(tool, url, f, ttl=3 * 3600)
    return f


# ---------------------------------------------------------------------------
# RDAP - official registry data, used for the domain's age.
# ---------------------------------------------------------------------------
async def domain_age(domain: str) -> Finding:
    tool, src = "domain_age", "RDAP (domain registry)"
    cached = cache_lookup(tool, domain)
    if cached:
        return cached
    ref = f"https://rdap.org/domain/{domain}"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, max_redirects=3) as c:
            r = await c.get(ref, headers={"Accept": "application/rdap+json"})
    except httpx.HTTPError as exc:
        return errored(tool, domain, f"Registry lookup failed ({type(exc).__name__}).", src)

    if r.status_code == 404:
        f = Finding(
            tool,
            domain,
            "warning",
            "Domain not found in the registry",
            "डोमेन रजिस्ट्री में नहीं मिला",
            detail="It may be brand-new, already taken down, or its registry does not publish data.",
            source_name=src,
            source_url=ref,
            weight=10,
        )
        cache_set(tool, domain, f, ttl=3600)
        return f
    if r.status_code != 200:
        return errored(tool, domain, f"Registry answered {r.status_code}.", src)

    created = None
    try:
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
    except (ValueError, KeyError):
        created = None
    if not created:
        f = Finding(tool, domain, "info", "Registration date not published", "रजिस्ट्रेशन की तारीख उपलब्ध नहीं", source_name=src, source_url=ref)
    else:
        age = (datetime.now(timezone.utc) - created).days
        when = created.date().isoformat()
        if age < 30:
            f = Finding(
                tool,
                domain,
                "danger",
                f"Website is only {age} days old",
                f"वेबसाइट सिर्फ़ {age} दिन पुरानी है",
                detail=f"Registered on {when}. Scam sites are usually days or weeks old.",
                source_name=src,
                source_url=ref,
                weight=35,
                data={"age_days": age},
            )
        elif age < 180:
            f = Finding(
                tool,
                domain,
                "warning",
                f"Website is new ({age} days old)",
                f"वेबसाइट नई है ({age} दिन पुरानी)",
                detail=f"Registered on {when}.",
                source_name=src,
                source_url=ref,
                weight=15,
                data={"age_days": age},
            )
        else:
            years = age // 365
            label = f"{years} year(s)" if years else f"{age} days"
            label_hi = f"{years} साल" if years else f"{age} दिन"
            f = Finding(
                tool,
                domain,
                "info",
                f"Website has existed for {label}",
                f"वेबसाइट {label_hi} पुरानी है",
                detail=f"Registered on {when}. Age alone does not prove a site is safe.",
                source_name=src,
                source_url=ref,
                data={"age_days": age},
            )
    cache_set(tool, domain, f, ttl=24 * 3600)
    return f
