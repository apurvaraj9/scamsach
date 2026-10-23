"""Entity extraction: pull links, UPI IDs, phone numbers and amounts out of
a pasted message, and guess its language. Pure functions, no network."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from ..security.masking import EMAIL_RE, URL_RE, VEHICLE_RE
from .data import COUNTRY_CODES
from .domains import is_risky_tld, is_shortener, official_owner, parse_url

UPI_ID_RE = re.compile(r"\b([\w.\-]{2,64})@([a-zA-Z][a-zA-Z0-9]{1,30})\b(?!\.[a-zA-Z])")
PHONE_CANDIDATE_RE = re.compile(r"(?<![\w/])\+?\d[\d\s-]{8,16}\d\b")
AMOUNT_RE = re.compile(r"(?i)(?:rs\.?|inr|₹|रु\.?|रुपये)\s?([\d,]+(?:\.\d{1,2})?)")
DEVANAGARI_RE = re.compile(r"[ऀ-ॿ]")
HINGLISH_WORDS = {
    "aap",
    "aapka",
    "aapke",
    "apka",
    "apke",
    "hai",
    "hain",
    "ho",
    "kare",
    "karein",
    "karen",
    "kijiye",
    "turant",
    "jaldi",
    "nahi",
    "nahin",
    "band",
    "jayega",
    "jaega",
    "hoga",
    "paise",
    "paisa",
    "kya",
    "abhi",
    "mein",
    "par",
    "ke",
    "ki",
    "ka",
    "liye",
    "beta",
    "bhai",
    "ji",
    "bhejo",
    "bhej",
    "milega",
    "kripya",
    "dhanyavaad",
    "khata",
    "bijli",
    "aaj",
    "raat",
    "ghar",
    "baithe",
    "kamaye",
    "kamao",
}


@dataclass
class LinkEntity:
    raw: str
    url: str
    host: str
    registered: str
    suffix: str
    official_owner: str | None
    is_shortener: bool
    is_ip: bool
    risky_tld: bool
    is_apk: bool
    uses_http: bool


@dataclass
class PhoneEntity:
    digits: str  # normalised digits only (kept server-side, never sent to the LLM)
    kind: str  # indian_mobile | toll_free | international | landline | unknown
    country: str | None = None


@dataclass
class UPIEntity:
    vpa: str
    name: str
    handle: str


@dataclass
class Entities:
    links: list[LinkEntity] = field(default_factory=list)
    upi_ids: list[UPIEntity] = field(default_factory=list)
    phones: list[PhoneEntity] = field(default_factory=list)
    amounts: list[str] = field(default_factory=list)
    language: str = "en"  # en | hi | hinglish
    has_apk_mention: bool = False
    vehicle_numbers: int = 0  # count only; the numbers themselves are personal data

    def to_dict(self) -> dict:
        return asdict(self)

    def summary_for_llm(self) -> dict:
        """What the LLM may see: links and counts, never raw numbers."""
        return {
            "links": [{"host": link.host, "official_owner": link.official_owner, "shortener": link.is_shortener} for link in self.links],
            "upi_ids_count": len(self.upi_ids),
            "phone_numbers": [{"kind": p.kind, "country": p.country} for p in self.phones],
            "amounts": self.amounts[:5],
            "language": self.language,
        }


def detect_language(text: str) -> str:
    if DEVANAGARI_RE.search(text):
        return "hi"
    words = re.findall(r"[a-z]+", text.lower())
    if not words:
        return "en"
    hits = sum(1 for w in words if w in HINGLISH_WORDS)
    return "hinglish" if hits >= 2 and hits / len(words) >= 0.08 else "en"


def _classify_phone(raw: str) -> PhoneEntity | None:
    has_plus = raw.strip().startswith("+")
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 10 or len(digits) > 15:
        return None
    if digits.startswith(("1800", "1860")):
        return PhoneEntity(digits, "toll_free")
    if digits.startswith("91") and len(digits) == 12 and digits[2] in "6789":
        return PhoneEntity(digits[2:], "indian_mobile", "India")
    if digits.startswith("0") and len(digits) == 11 and digits[1] in "6789":
        return PhoneEntity(digits[1:], "indian_mobile", "India")
    if len(digits) == 10 and digits[0] in "6789":
        return PhoneEntity(digits, "indian_mobile", "India")
    if has_plus:
        for length in (3, 2, 1):
            cc = digits[:length]
            if cc in COUNTRY_CODES:
                return PhoneEntity(digits, "international", COUNTRY_CODES[cc])
        return PhoneEntity(digits, "international", "unknown country")
    if digits.startswith("0") and len(digits) == 11:
        return PhoneEntity(digits, "landline", "India")
    return None  # probably an account/reference number, not a phone


def extract_entities(text: str) -> Entities:
    ent = Entities()
    ent.language = detect_language(text)
    ent.has_apk_mention = bool(re.search(r"(?i)\.apk\b|\bapk\b|एपीके", text))

    emails = {m.group(0) for m in EMAIL_RE.finditer(text)}
    text_no_email = EMAIL_RE.sub(" ", text)

    seen_hosts: set[str] = set()
    for m in URL_RE.finditer(text_no_email):
        raw = m.group(0)
        parsed = parse_url(raw)
        if not parsed or "." not in parsed.host and not parsed.is_ip:
            continue
        key = parsed.url.lower()
        if key in seen_hosts:
            continue
        seen_hosts.add(key)
        ent.links.append(
            LinkEntity(
                raw=raw,
                url=parsed.url,
                host=parsed.host,
                registered=parsed.registered,
                suffix=parsed.suffix,
                official_owner=official_owner(parsed.host),
                is_shortener=is_shortener(parsed.host),
                is_ip=parsed.is_ip,
                risky_tld=is_risky_tld(parsed.suffix) if parsed.suffix else False,
                is_apk=parsed.url.lower().split("?")[0].endswith(".apk"),
                uses_http=raw.lower().startswith("http://"),
            )
        )

    for m in UPI_ID_RE.finditer(text):
        vpa = m.group(0)
        if any(vpa in e for e in emails):
            continue
        ent.upi_ids.append(UPIEntity(vpa=vpa, name=m.group(1), handle=m.group(2).lower()))

    url_spans = [m.span() for m in URL_RE.finditer(text)]
    seen_digits: set[str] = set()
    for m in PHONE_CANDIDATE_RE.finditer(text):
        if any(s <= m.start() < e for s, e in url_spans):
            continue
        phone = _classify_phone(m.group(0))
        if phone and phone.digits not in seen_digits:
            seen_digits.add(phone.digits)
            ent.phones.append(phone)

    ent.amounts = [m.group(0) for m in AMOUNT_RE.finditer(text)][:10]
    ent.vehicle_numbers = len(set(VEHICLE_RE.findall(text)))
    return ent
