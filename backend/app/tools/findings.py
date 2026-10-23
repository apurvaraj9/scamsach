"""The single data shape every tool returns, so the UI, the scorer and the
LLM all read evidence the same way. Every finding names its source."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SIGNALS = ("danger", "warning", "ok", "info", "skipped", "error")


@dataclass
class Finding:
    tool: str
    target: str  # what was checked, safe to display (numbers are masked)
    signal: str  # one of SIGNALS
    title_en: str
    title_hi: str
    detail: str = ""
    source_name: str = ""
    source_url: str = ""
    weight: int = 0  # contribution to the risk score
    hard: bool = False  # conclusive on its own (e.g. listed by threat intel)
    scam_type: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def skipped(tool: str, target: str, reason: str, source: str = "") -> Finding:
    return Finding(tool, target, "skipped", "Check skipped", "जांच छोड़ी गई", detail=reason, source_name=source)


def errored(tool: str, target: str, reason: str, source: str = "") -> Finding:
    return Finding(tool, target, "error", "Check could not finish", "जांच पूरी नहीं हो सकी", detail=reason, source_name=source)
