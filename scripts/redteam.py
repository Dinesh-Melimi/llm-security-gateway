"""Run the red-team harness and write a report.

Usage:
    python -m scripts.redteam                      # both corpora, writes reports/redteam.{md,json}
    python -m scripts.redteam --gate               # also fail if the tuned-set gate is not met (CI)

Two corpora on purpose:
  attacks.jsonl  the set the rules were developed against. CI gates on it so a rule
                 change cannot silently undo a fix (regression test).
  holdout.jsonl  attacks written after tuning and never used to tune. Reported, never
                 gated, because gating on it would turn it into a second training set.
                 This is the number that says how well the detector generalizes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from redteam import harness

ROOT = Path(__file__).resolve().parent.parent
CORPORA = {"tuned": ROOT / "redteam" / "attacks.jsonl", "holdout": ROOT / "redteam" / "holdout.jsonl"}
GATE = {"min_unmutated_block_rate": 0.95, "min_overall_block_rate": 0.90, "max_false_positive_rate": 0.0}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "reports"))
    ap.add_argument("--gate", action="store_true")
    args = ap.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    summaries, md = {}, []
    for name, path in CORPORA.items():
        s = harness.summarize(harness.run(harness.load(path)))
        summaries[name] = s
        md.append(harness.to_markdown(s).replace("# Red-team report", f"# Red-team report: {name} set", 1))
        print(f"{name:8} unmutated={s['block_rate_unmutated']:.0%} all={s['block_rate_overall']:.0%} "
              f"ASR={s['attack_success_rate']:.0%} FP={s['false_positive_rate']:.0%} runs={s['attacks_run']}")
    (out / "redteam.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    (out / "redteam.md").write_text("\n".join(md), encoding="utf-8")

    if args.gate:
        t = summaries["tuned"]
        failures = []
        if t["block_rate_unmutated"] < GATE["min_unmutated_block_rate"]:
            failures.append(f"unmutated block rate {t['block_rate_unmutated']:.0%} < {GATE['min_unmutated_block_rate']:.0%}")
        if t["block_rate_overall"] < GATE["min_overall_block_rate"]:
            failures.append(f"overall block rate {t['block_rate_overall']:.0%} < {GATE['min_overall_block_rate']:.0%}")
        if t["false_positive_rate"] > GATE["max_false_positive_rate"]:
            failures.append(f"false positive rate {t['false_positive_rate']:.0%}")
        if failures:
            print("red-team gate FAILED: " + "; ".join(failures))
            return 1
        print("red-team gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
