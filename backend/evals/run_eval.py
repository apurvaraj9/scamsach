"""Evaluate the agent on labelled scam and genuine messages.

Usage (from the backend folder):
    python -m evals.run_eval                 # offline: rules only, no network, free, deterministic (CI runs this)
    python -m evals.run_eval --live          # full agent: uses the LLM + threat-intel keys in your .env
    python -m evals.run_eval --min-recall 0.9 --max-fpr 0.1   # fail (exit 1) below these targets

Metrics
- accuracy           exact 3-class match (scam / suspicious / likely_safe)
- scam recall        share of real scams we flagged (verdict scam OR suspicious) - the number that matters most
- strict scam recall share of real scams we called exactly "scam"
- false-positive rate share of genuine messages we wrongly flagged

Two files: dataset.jsonl (dev, used while building the rules) and holdout.jsonl
(written before tuning and never tuned on) - report both, honestly.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).parent
LABELS = ("scam", "suspicious", "likely_safe")


def load(name: str) -> list[dict]:
    return [json.loads(line) for line in (HERE / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def metrics(rows: list[dict]) -> dict:
    n = len(rows)
    scams = [r for r in rows if r["label"] == "scam"]
    genuine = [r for r in rows if r["label"] == "likely_safe"]
    flagged = ("scam", "suspicious")
    confusion = Counter((r["label"], r["pred"]) for r in rows)
    return {
        "n": n,
        "accuracy": sum(r["label"] == r["pred"] for r in rows) / n if n else 0,
        "scam_recall": sum(r["pred"] in flagged for r in scams) / len(scams) if scams else 1,
        "strict_scam_recall": sum(r["pred"] == "scam" for r in scams) / len(scams) if scams else 1,
        "false_positive_rate": sum(r["pred"] in flagged for r in genuine) / len(genuine) if genuine else 0,
        "confusion": {f"{a}->{b}": c for (a, b), c in sorted(confusion.items())},
    }


def to_markdown(mode: str, results: dict[str, dict], rows: list[dict]) -> str:
    lines = [f"# ScamSach evaluation ({mode})", "", f"Generated: {time.strftime('%Y-%m-%d %H:%M')}", ""]
    lines += ["| Split | N | Accuracy (3-class) | Scam recall (flagged) | Strict scam recall | False-positive rate |", "|---|---|---|---|---|---|"]
    for split, m in results.items():
        lines.append(
            f"| {split} | {m['n']} | {m['accuracy']:.0%} | {m['scam_recall']:.0%} | {m['strict_scam_recall']:.0%} | {m['false_positive_rate']:.0%} |"
        )
    lines += ["", "## Confusion (label -> prediction)", ""]
    for split, m in results.items():
        lines.append(f"- **{split}**: " + ", ".join(f"{k}: {v}" for k, v in m["confusion"].items()))
    lines += ["", "## Misses", "", "| ID | Lang | Expected | Got | Score | Message |", "|---|---|---|---|---|---|"]
    for r in rows:
        if r["label"] != r["pred"]:
            text = r["text"][:90].replace("|", "/")
            lines.append(f"| {r['id']} | {r['lang']} | {r['label']} | {r['pred']} | {r['score']} | {text} |")
    return "\n".join(lines) + "\n"


async def run(live: bool, delay: float) -> tuple[dict, list[dict]]:
    if not live:
        # Offline mode: blank every key so nothing leaves this machine.
        for key in (
            "GEMINI_API_KEY",
            "GROQ_API_KEY",
            "SAFE_BROWSING_API_KEY",
            "VIRUSTOTAL_API_KEY",
            "URLHAUS_AUTH_KEY",
            "LANGFUSE_PUBLIC_KEY",
            "LANGFUSE_SECRET_KEY",
        ):
            os.environ[key] = ""
        os.environ["ENABLE_NETWORK_TOOLS"] = "false"
    from app.agent.graph import investigate  # imported after env is set
    from app.services import tracing

    rows = []
    for item in load("dataset.jsonl") + load("holdout.jsonl"):
        report = await investigate(item["text"])
        rows.append(item | {"pred": report["verdict"], "score": report["risk_score"], "pred_type": report["scam_type"]})
        mark = "OK " if item["label"] == report["verdict"] else "XX "
        print(f"{mark}{item['id']} expected={item['label']:<11} got={report['verdict']:<11} score={report['risk_score']:>3}")
        if live and delay:
            time.sleep(delay)  # stay under free-tier requests-per-minute limits
    tracing.flush()
    results = {split: metrics([r for r in rows if r["split"] == split]) for split in ("dev", "holdout")}
    results["all"] = metrics(rows)
    return results, rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="use LLM + threat-intel keys from .env")
    ap.add_argument("--delay", type=float, default=8.0, help="seconds between live calls")
    ap.add_argument("--min-recall", type=float, default=None)
    ap.add_argument("--max-fpr", type=float, default=None)
    args = ap.parse_args()

    mode = "live" if args.live else "offline"
    results, rows = asyncio.run(run(args.live, args.delay))
    (HERE / f"results_{mode}.md").write_text(to_markdown(mode, results, rows), encoding="utf-8")
    (HERE / f"results_{mode}.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print()
    for split, m in results.items():
        print(
            f"{split:8} n={m['n']:<3} acc={m['accuracy']:.0%} scam_recall={m['scam_recall']:.0%} "
            f"strict={m['strict_scam_recall']:.0%} fpr={m['false_positive_rate']:.0%}"
        )
    print(f"\nWrote evals/results_{mode}.md")

    allm = results["all"]
    if args.min_recall is not None and allm["scam_recall"] < args.min_recall:
        print(f"FAIL: scam recall {allm['scam_recall']:.0%} < {args.min_recall:.0%}")
        return 1
    if args.max_fpr is not None and allm["false_positive_rate"] > args.max_fpr:
        print(f"FAIL: false-positive rate {allm['false_positive_rate']:.0%} > {args.max_fpr:.0%}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
