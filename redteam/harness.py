"""Automated red-team harness for the gateway's guardrails.

Every attack in `attacks.jsonl` is labeled with its OWASP LLM Top 10 (2025) category
and MITRE ATLAS technique, and the vector it arrives through:

    direct    user prompt            -> sdk.validate_prompt
    secret    credential in prompt   -> sdk.validate_prompt
    indirect  retrieved RAG document -> rag.scan_chunk
    output    model output to a sink -> sdk.guard_output

Text attacks are replayed through every mutator in `mutators.py`, so the result is
not just "does the detector catch the textbook phrasing" but "which evasion
techniques get through". Benign controls run through the same path to measure
false positives. Attack success rate (ASR) = share of attacks that were not blocked.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from gateway import sdk
from gateway.guardrails import rag

from .mutators import MUTATORS

CORPUS = Path(__file__).resolve().parent / "attacks.jsonl"
TEXT_VECTORS = ("direct", "indirect")


@dataclass
class Result:
    id: str
    vector: str
    owasp: str
    atlas: str
    technique: str
    mutator: str
    expect: str
    blocked: bool
    detail: str

    @property
    def correct(self) -> bool:
        return self.blocked == (self.expect == "block")


def load(path: str | Path = CORPUS) -> list[dict]:
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def run_one(case: dict, text: str, threshold: float) -> tuple[bool, str]:
    vector = case["vector"]
    if vector in ("direct", "secret"):
        try:
            sdk.validate_prompt(text, threshold=threshold)
            return False, "passed"
        except sdk.UnsafePrompt as e:
            return True, e.reason + ": " + ",".join(e.detail)
    if vector == "indirect":
        v = rag.scan_chunk(text, threshold=0.5)
        return v.quarantined, ",".join(v.matched) or "passed"
    if vector == "output":
        try:
            sdk.guard_output(text, case["sink"])
            return False, "passed"
        except sdk.InsecureOutput as e:
            return True, ",".join(f.rule for f in e.verdict.findings)
    raise ValueError(f"unknown vector {vector}")


def run(cases: list[dict] | None = None, mutators: list[str] | None = None, threshold: float = 0.7) -> list[Result]:
    cases = cases if cases is not None else load()
    names = mutators or list(MUTATORS)
    results = []
    for case in cases:
        applicable = names if case["vector"] in TEXT_VECTORS and case["expect"] == "block" else ["identity"]
        for name in applicable:
            blocked, detail = run_one(case, MUTATORS[name](case["text"]), threshold)
            results.append(Result(case["id"], case["vector"], case["owasp"], case["atlas"], case["technique"],
                                  name, case["expect"], blocked, detail))
    return results


def _rate(rows: list[Result]) -> float:
    return round(sum(r.blocked for r in rows) / len(rows), 3) if rows else 0.0


def summarize(results: list[Result]) -> dict:
    attacks = [r for r in results if r.expect == "block"]
    benign = [r for r in results if r.expect == "allow"]
    baseline = [r for r in attacks if r.mutator == "identity"]
    by = defaultdict(lambda: defaultdict(list))
    for r in attacks:
        by["owasp"][r.owasp].append(r)
        by["atlas"][r.atlas].append(r)
        by["vector"][r.vector].append(r)
        by["mutator"][r.mutator].append(r)
    return {
        "attacks_run": len(attacks),
        "block_rate_overall": _rate(attacks),
        "block_rate_unmutated": _rate(baseline),
        "attack_success_rate": round(1 - _rate(attacks), 3),
        "false_positive_rate": _rate(benign),
        "benign_run": len(benign),
        **{f"by_{k}": {name: {"n": len(rows), "block_rate": _rate(rows)} for name, rows in sorted(v.items())}
           for k, v in by.items()},
        "bypasses": [asdict(r) for r in attacks if not r.blocked],
        "false_positives": [asdict(r) for r in benign if r.blocked],
    }


def to_markdown(s: dict) -> str:
    out = ["# Red-team report", "",
           f"- Attacks run (incl. mutations): **{s['attacks_run']}**",
           f"- Block rate, unmutated payloads: **{s['block_rate_unmutated']:.0%}**",
           f"- Block rate, all mutations: **{s['block_rate_overall']:.0%}** (attack success rate {s['attack_success_rate']:.0%})",
           f"- False positives on {s['benign_run']} benign controls: **{s['false_positive_rate']:.0%}**", ""]
    for key, title in (("by_vector", "Vector"), ("by_owasp", "OWASP LLM Top 10"), ("by_atlas", "MITRE ATLAS"),
                       ("by_mutator", "Evasion technique")):
        out += [f"## By {title.lower()}", "", f"| {title} | Runs | Blocked |", "|---|---|---|"]
        out += [f"| {k} | {v['n']} | {v['block_rate']:.0%} |" for k, v in s[key].items()]
        out.append("")
    out += ["## Bypasses", "", "| ID | Technique | Mutator | Vector |", "|---|---|---|---|"]
    out += [f"| {b['id']} | {b['technique']} | {b['mutator']} | {b['vector']} |" for b in s["bypasses"]]
    if s["false_positives"]:
        out += ["", "## False positives", ""] + [f"- {f['id']} ({f['mutator']}): {f['detail']}" for f in s["false_positives"]]
    return "\n".join(out) + "\n"
