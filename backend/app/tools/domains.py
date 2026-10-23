"""Offline domain helpers: parsing, official-domain check and lookalike
(brand impersonation) detection. No network access happens here."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

from .data import BRAND_TOKENS, FREE_HOSTING, OFFICIAL_DOMAINS, OFFICIAL_SUFFIXES, RISKY_TLDS, SHORTENERS

# Use the public-suffix list bundled with the package; never download it at
# runtime (faster cold starts, no surprise network calls).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a"})


@dataclass
class ParsedURL:
    url: str
    host: str
    registered: str  # e.g. kyc-verify.xyz
    label: str  # e.g. kyc-verify
    suffix: str  # e.g. xyz
    subdomain: str
    is_ip: bool
    scheme: str


def normalize_url(raw: str) -> str:
    raw = raw.strip().rstrip(".,);]!>'\"")
    if not re.match(r"(?i)^https?://", raw):
        raw = "http://" + raw
    return raw


def parse_url(raw: str) -> ParsedURL | None:
    url = normalize_url(raw)
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    ext = _EXTRACT(host)
    registered = host if is_ip else (f"{ext.domain}.{ext.suffix}" if ext.suffix else host)
    return ParsedURL(
        url=url,
        host=host,
        registered=registered,
        label=ext.domain,
        suffix=ext.suffix,
        subdomain=ext.subdomain,
        is_ip=is_ip,
        scheme=parts.scheme.lower(),
    )


def official_owner(host: str) -> str | None:
    """Return the organisation name if ``host`` is a known official domain."""
    host = host.lower().rstrip(".")
    for suffix, owner in OFFICIAL_SUFFIXES.items():
        if host == suffix or host.endswith("." + suffix):
            return owner
    parsed = parse_url(host)
    if parsed and parsed.registered in OFFICIAL_DOMAINS:
        return OFFICIAL_DOMAINS[parsed.registered]
    return None


def is_shortener(host: str) -> bool:
    host = host.lower()
    return host in SHORTENERS or host.removeprefix("www.") in SHORTENERS


def is_risky_tld(suffix: str) -> bool:
    return suffix.split(".")[-1].lower() in RISKY_TLDS


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _official_labels() -> dict[str, str]:
    labels: dict[str, str] = {}
    for dom, owner in OFFICIAL_DOMAINS.items():
        label = dom.split(".")[0]
        if len(label) >= 5:
            labels[label] = owner
    return labels


_OFFICIAL_LABELS = _official_labels()


@dataclass
class LookalikeResult:
    impersonates: str | None  # organisation name
    category: str | None
    reason: str
    severity: str  # "danger" | "warning" | "ok" | "info"


def check_lookalike(host: str) -> LookalikeResult:
    """Decide whether a non-official domain pretends to be a known brand."""
    owner = official_owner(host)
    if owner:
        return LookalikeResult(None, None, f"Official domain of {owner}.", "ok")
    parsed = parse_url(host)
    if not parsed:
        return LookalikeResult(None, None, "Could not read this domain.", "info")
    if parsed.is_ip:
        return LookalikeResult(None, None, "Link uses a raw IP address instead of a name.", "warning")

    full = parsed.host
    if "xn--" in full:
        return LookalikeResult(None, None, "Domain uses special look-alike letters (punycode), a common phishing trick.", "danger")

    # 1. Brand name appears anywhere in the host (sub-domain or name).
    #    On free hosting platforms only the user-chosen sub-domain counts.
    on_free_host = parsed.registered in FREE_HOSTING
    searchable = parsed.subdomain if on_free_host else full
    tokens = [t for t in re.split(r"[^a-z0-9]+", searchable) if t]
    normalized_tokens = [t.translate(HOMOGLYPHS) for t in tokens]
    for token in dict.fromkeys(tokens + normalized_tokens):  # ordered + de-duplicated (deterministic)
        for brand, (org, cat) in BRAND_TOKENS.items():
            if (
                token == brand
                or (
                    len(brand) >= 3
                    and len(token) > len(brand)
                    and (token.startswith(brand) or token.endswith(brand))
                    and len(token) - len(brand) <= 10
                )
                or (len(brand) >= 6 and brand in token)
            ):
                where = f" (hosted on the free platform {parsed.registered})" if on_free_host else ""
                return LookalikeResult(
                    org,
                    cat,
                    f"Mentions '{brand}' but is not an official {org} website{where}.",
                    "danger" if cat in {"bank", "govt", "payments"} else "warning",
                )

    if on_free_host:
        return LookalikeResult(
            None,
            None,
            f"Hosted on a free website platform ({parsed.registered}); real banks never use these.",
            "warning",
        )

    # 2. Name is a near-miss spelling of an official name (hdfcbnak, amaz0n).
    label = parsed.label.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for official_label, org in _OFFICIAL_LABELS.items():
        if parsed.label == official_label:
            return LookalikeResult(
                org,
                "brand",
                f"Same name as {org}'s website but a different ending (.{parsed.suffix}). Check it carefully.",
                "warning",
            )
        dist = _levenshtein(label, official_label)
        if dist <= (1 if len(official_label) < 7 else 2):
            return LookalikeResult(org, "brand", f"Spelled almost like {org}'s website ('{official_label}') - a lookalike.", "danger")

    return LookalikeResult(None, None, "Does not imitate any brand on our list.", "info")
