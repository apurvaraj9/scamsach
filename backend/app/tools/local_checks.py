"""Checks that run on our own server with no external calls."""

from __future__ import annotations

from ..security.masking import mask_for_display
from .data import OPEN_PLATFORMS, UPI_HANDLES, UPI_IMPERSONATION_WORDS
from .domains import check_lookalike
from .extract import LinkEntity, PhoneEntity, UPIEntity
from .findings import Finding
from .patterns import scan_patterns

SRC_RULES = "ScamSach pattern rules"
SRC_DOMAIN = "ScamSach domain analysis"


def pattern_scan(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for hit in scan_patterns(text):
        if hit.weight < 0:
            signal = "ok"
        elif hit.hard or hit.weight >= 30:
            signal = "danger"
        else:
            signal = "warning"
        findings.append(
            Finding(
                "pattern_scan",
                "message",
                signal,
                hit.title_en,
                hit.title_hi,
                detail=f'Matched wording: "{hit.evidence}"',
                source_name=SRC_RULES,
                weight=hit.weight,
                hard=hit.hard,
                scam_type=hit.scam_type,
                data={"rule": hit.rule_id},
            )
        )
    if not findings:
        findings.append(
            Finding("pattern_scan", "message", "info", "No known scam wording found", "कोई जाना-पहचाना धोखे वाला वाक्य नहीं मिला", source_name=SRC_RULES)
        )
    return findings


def lookalike_check(link: LinkEntity) -> list[Finding]:
    out: list[Finding] = []
    if link.official_owner and link.registered in OPEN_PLATFORMS:
        out.append(
            Finding(
                "lookalike",
                link.host,
                "info",
                f"Link to {link.official_owner}, a public platform anyone can post on",
                f"{link.official_owner} का लिंक - ऐसा प्लेटफ़ॉर्म जहाँ कोई भी पोस्ट कर सकता है",
                detail="The platform is real, but groups, channels and forms on it can be created by scammers.",
                source_name=SRC_DOMAIN,
            )
        )
        return out
    if link.official_owner:
        out.append(
            Finding(
                "lookalike",
                link.host,
                "ok",
                f"Official website of {link.official_owner}",
                f"{link.official_owner} की आधिकारिक वेबसाइट",
                detail="Domain is on our verified list.",
                source_name=SRC_DOMAIN,
                weight=-25,
            )
        )
        return out
    if link.is_shortener:
        out.append(
            Finding(
                "lookalike",
                link.host,
                "warning",
                "Shortened link hides the real address",
                "छोटा किया गया लिंक असली पता छुपाता है",
                detail="Banks and government offices do not send bit.ly-style links.",
                source_name=SRC_DOMAIN,
                weight=10,
            )
        )
        return out

    res = check_lookalike(link.host)
    if res.severity in ("danger", "warning"):
        is_brand = res.impersonates is not None
        title_en = f"Pretends to be {res.impersonates}" if is_brand else "Suspicious website address"
        title_hi = f"{res.impersonates} होने का दिखावा" if is_brand else "संदिग्ध वेबसाइट पता"
        weight = 60 if res.severity == "danger" else 20
        out.append(
            Finding(
                "lookalike",
                link.host,
                res.severity,
                title_en,
                title_hi,
                detail=res.reason,
                source_name=SRC_DOMAIN,
                weight=weight,
                hard=res.severity == "danger" and is_brand,
                scam_type="phishing",
                data={"impersonates": res.impersonates, "category": res.category},
            )
        )
    if link.is_apk:
        out.append(
            Finding(
                "lookalike",
                link.host,
                "danger",
                "Link downloads an app file (APK)",
                "लिंक से ऐप फ़ाइल (APK) डाउनलोड होती है",
                detail="Apps from links can read your SMS and OTPs. Install apps only from Play Store.",
                source_name=SRC_DOMAIN,
                weight=60,
                hard=True,
                scam_type="malicious_app",
            )
        )
    if link.is_ip:
        out.append(
            Finding(
                "lookalike", link.host, "danger", "Link uses a bare IP address", "लिंक में नाम की जगह सिर्फ़ IP नंबर है", source_name=SRC_DOMAIN, weight=30
            )
        )
    if link.risky_tld:
        out.append(
            Finding(
                "lookalike",
                link.host,
                "warning",
                f"Cheap, often-abused web address ending (.{link.suffix})",
                f"सस्ता और अक्सर गलत इस्तेमाल होने वाला पता (.{link.suffix})",
                source_name=SRC_DOMAIN,
                weight=12,
            )
        )
    if not out:
        out.append(
            Finding(
                "lookalike",
                link.host,
                "info",
                "Does not imitate a known brand",
                "किसी जानी-मानी कंपनी की नकल नहीं करता",
                detail=res.reason,
                source_name=SRC_DOMAIN,
            )
        )
    return out


def upi_check(upi: UPIEntity) -> Finding:
    shown = f"{upi.name[:2]}***@{upi.handle}"
    name = upi.name.lower()
    bad_word = next((w for w in UPI_IMPERSONATION_WORDS if w in name), None)
    if bad_word:
        return Finding(
            "upi_check",
            shown,
            "danger",
            "UPI ID poses as an official body",
            "UPI ID किसी आधिकारिक संस्था होने का दिखावा करता है",
            detail=f"Contains '{bad_word}'. Banks, police and government never collect money via such UPI IDs.",
            source_name="ScamSach UPI rules",
            weight=45,
            hard=False,
            scam_type="upi_collect",
        )
    if upi.handle not in UPI_HANDLES:
        return Finding(
            "upi_check",
            shown,
            "warning",
            "Unusual UPI handle",
            "असामान्य UPI हैंडल",
            detail=f"'@{upi.handle}' is not on our list of common bank handles.",
            source_name="ScamSach UPI rules",
            weight=10,
        )
    return Finding(
        "upi_check",
        shown,
        "info",
        "UPI ID format looks normal",
        "UPI ID का फ़ॉर्मेट सामान्य है",
        detail="A normal-looking UPI ID can still belong to a scammer. Remember: you never need your PIN to RECEIVE money.",
        source_name="ScamSach UPI rules",
    )


def phone_check(phone: PhoneEntity, scam_context: bool) -> Finding:
    """``scam_context``: the wording already looks like a scam (threat, fake
    helpline...). A personal mobile number to call in such a message is a
    classic pattern; on its own a phone number means nothing."""
    shown = mask_for_display(phone.digits)
    src = "ScamSach phone rules"
    if phone.kind == "toll_free":
        return Finding(
            "phone_check",
            shown,
            "ok",
            "Toll-free number (1800/1860)",
            "टोल-फ़्री नंबर (1800/1860)",
            detail="Real banks use toll-free numbers, but always confirm the number on the bank's own website or card.",
            source_name=src,
            weight=-5,
        )
    if phone.kind == "international":
        return Finding(
            "phone_check",
            shown,
            "danger",
            f"Foreign number ({phone.country})",
            f"विदेशी नंबर ({phone.country})",
            detail="Job, investment and 'digital arrest' scams often come from foreign WhatsApp numbers.",
            source_name=src,
            weight=25,
        )
    if phone.kind == "indian_mobile" and scam_context:
        return Finding(
            "phone_check",
            shown,
            "warning",
            "Asks you to contact a personal mobile number",
            "निजी मोबाइल नंबर पर संपर्क करने को कहना",
            detail="Banks, electricity companies and government offices do not ask you to call or WhatsApp a 10-digit mobile number.",
            source_name=src,
            weight=15,
        )
    return Finding(
        "phone_check",
        shown,
        "info",
        "Indian phone number",
        "भारतीय फ़ोन नंबर",
        detail="Report misuse of this number on Chakshu (Sanchar Saathi).",
        source_name=src,
    )
