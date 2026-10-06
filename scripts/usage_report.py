"""Summarize the JSONL audit log for Shadow-AI governance reviews.

Usage: python -m scripts.usage_report [logs/audit.jsonl] [--json]
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def summarize(path: str | Path) -> dict:
    per_client: dict[str, dict] = defaultdict(lambda: {"requests": 0, "blocked": 0, "tokens": 0, "models": Counter()})
    decisions, reasons, detections = Counter(), Counter(), Counter()
    total = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            e = json.loads(line)
            total += 1
            decisions[e["decision"]] += 1
            if e.get("reason"):
                reasons[e["reason"]] += 1
            for k in e.get("input_detections", []) + e.get("output_detections", []):
                detections[k] += 1
            c = per_client[e.get("client_id") or "<unauthenticated>"]
            c["requests"] += 1
            c["blocked"] += e["decision"] == "blocked"
            c["tokens"] += e.get("prompt_tokens", 0) + e.get("completion_tokens", 0)
            if e.get("model"):
                c["models"][e["model"]] += 1
    return {
        "total_events": total,
        "decisions": dict(decisions),
        "block_reasons": dict(reasons.most_common()),
        "pii_secret_detections": dict(detections.most_common()),
        "clients": {k: {**v, "models": dict(v["models"])} for k, v in sorted(per_client.items())},
    }


def render(s: dict) -> str:
    lines = [f"Total events: {s['total_events']}", "Decisions: " + ", ".join(f"{k}={v}" for k, v in s["decisions"].items())]
    lines.append("Block reasons:")
    lines += [f"  {k:<22}{v}" for k, v in s["block_reasons"].items()] or ["  (none)"]
    lines.append("Detections:")
    lines += [f"  {k:<22}{v}" for k, v in s["pii_secret_detections"].items()] or ["  (none)"]
    lines.append(f"{'client':<22}{'requests':>9}{'blocked':>9}{'tokens':>9}  models")
    for name, c in s["clients"].items():
        lines.append(f"{name:<22}{c['requests']:>9}{c['blocked']:>9}{c['tokens']:>9}  {', '.join(c['models'])}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default="logs/audit.jsonl")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    s = summarize(a.path)
    print(json.dumps(s, indent=2) if a.json else render(s))


if __name__ == "__main__":
    main()
