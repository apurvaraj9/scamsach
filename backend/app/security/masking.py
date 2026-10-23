"""Mask personal data before any text leaves our server for an LLM, a trace,
or the database.

Design notes
- Placeholders are numbered ([PHONE_1], [PHONE_2]) so the LLM can still
  reason about "the same number appears twice" without seeing it.
- URLs are kept (they are the scammer's infrastructure and the LLM needs
  them), but long digit runs inside them and query-string values are masked
  because tracking links often embed the victim's phone number.
- Toll-free numbers (1800/1860) are business numbers, not personal data, and
  they are a useful "genuine bank" signal, so they are left visible.
- Regex masking is best-effort. It cannot catch names or addresses; the
  README lists this as a known limitation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

URL_RE = re.compile(
    r"""(?ix)
    \b(?:https?://|www\.)[^\s<>"']+
    |
    \b(?:[a-z0-9-]+\.)+(?:com|in|net|org|info|xyz|top|online|site|live|shop|club|co|io|me|ly|gy|cc|link|click|vip|icu|buzz|sbi|bank|apk|app)
      (?:/[^\s<>"']*)?
    """
)

EMAIL_RE = re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{2,63})+\b")
UPI_RE = re.compile(r"\b[\w.\-]{2,64}@[a-zA-Z][a-zA-Z0-9]{1,30}\b(?!\.[a-zA-Z])")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
AADHAAR_RE = re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b")
CARD_RE = re.compile(r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{1,7}\b|\b\d{15,19}\b")
TOLL_FREE_RE = re.compile(r"\b(?:1800|1860)[\s-]?\d{3}[\s-]?\d{3,4}\b")
PHONE_RE = re.compile(
    r"(?<![\w])(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}\b"  # Indian mobile
    r"|(?<![\w])\+(?!91)\d{1,3}[\s-]?\d{2,5}[\s-]?\d{3,5}[\s-]?\d{2,5}\b"  # international
)
ACCOUNT_RE = re.compile(r"\b\d{9,18}\b")
OTP_RE = re.compile(r"(?i)(\b(?:otp|one[\s-]?time[\s-]?password|verification code|code|ओटीपी|कोड)\b\D{0,25}?)(\d{4,8})\b")
LONG_DIGITS_RE = re.compile(r"\d{7,}")


@dataclass
class MaskResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class _Masker:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.seen: dict[tuple[str, str], str] = {}

    def token(self, kind: str, value: str) -> str:
        key = (kind, re.sub(r"[\s-]", "", value))
        if key not in self.seen:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            self.seen[key] = f"[{kind}_{self.counts[kind]}]"
        return self.seen[key]

    def sub(self, pattern: re.Pattern[str], kind: str, text: str) -> str:
        return pattern.sub(lambda m: self.token(kind, m.group(0)), text)


def _mask_url(url: str) -> str:
    base, sep, query = url.partition("?")
    base = LONG_DIGITS_RE.sub("[NUM]", base)
    if sep:
        parts = []
        for pair in query.split("&"):
            k, eq, _ = pair.partition("=")
            parts.append(f"{k}=[REDACTED]" if eq else "[REDACTED]")
        return base + "?" + "&".join(parts)
    return base


def mask_text(text: str) -> MaskResult:
    """Return a copy of ``text`` with personal data replaced by placeholders."""
    if not text:
        return MaskResult(text="", counts={})
    m = _Masker()

    # 1. Protect URLs and toll-free numbers by swapping them for sentinels.
    protected: list[str] = []

    def protect(value: str) -> str:
        protected.append(value)
        return f"\x00{len(protected) - 1}\x00"

    # (E-mails go first, otherwise "gmail.com" would be protected as a URL.)
    work = m.sub(EMAIL_RE, "EMAIL", text)
    work = URL_RE.sub(lambda x: protect(_mask_url(x.group(0))), work)
    work = TOLL_FREE_RE.sub(lambda x: protect(x.group(0)), work)

    # 2. Mask personal identifiers, most specific first.
    work = m.sub(UPI_RE, "UPI", work)
    work = m.sub(PAN_RE, "PAN", work)
    work = OTP_RE.sub(lambda x: x.group(1) + m.token("OTP", x.group(2)), work)
    work = m.sub(CARD_RE, "CARD", work)
    work = m.sub(AADHAAR_RE, "AADHAAR", work)
    work = m.sub(PHONE_RE, "PHONE", work)
    work = m.sub(ACCOUNT_RE, "ACCOUNT", work)

    # 3. Restore protected spans.
    work = re.sub(r"\x00(\d+)\x00", lambda x: protected[int(x.group(1))], work)
    return MaskResult(text=work, counts=dict(m.counts))


def mask_any(data):  # noqa: ANN001, ANN201 - generic by design
    """Recursively mask strings inside dicts/lists. Used as the Langfuse
    ``mask`` hook so even an accidental raw string never reaches a trace."""
    if isinstance(data, str):
        return mask_text(data).text
    if isinstance(data, dict):
        return {k: mask_any(v) for k, v in data.items()}
    if isinstance(data, list):
        return [mask_any(v) for v in data]
    return data


def mask_for_display(value: str, keep: int = 4) -> str:
    """'9876543210' -> '******3210' for showing a number back to the user."""
    digits = re.sub(r"\D", "", value)
    if len(digits) <= keep:
        return value
    return "*" * (len(digits) - keep) + digits[-keep:]
