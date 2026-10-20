"""Precision/recall of the execution output guard on a hand-labeled set.

python -m scripts.evaluate_exec [--dataset eval/exec_output_dataset.jsonl]
"""
from __future__ import annotations

import argparse
import json

from gateway.guardrails.exec_guard import check_output

ALLOW = {"schwab.example"}  # sample allow-list for markdown image hosts


def evaluate(path: str) -> dict:
    tp = fp = tn = fn = 0
    misses = []
    for line in open(path, encoding="utf-8"):
        row = json.loads(line)
        blocked = not check_output(row["output"], row["sink"], allow_domains=ALLOW).allowed
        if row["unsafe"] and blocked:
            tp += 1
        elif row["unsafe"]:
            fn += 1
            misses.append(("FN", row["sink"], row["output"][:60]))
        elif blocked:
            fp += 1
            misses.append(("FP", row["sink"], row["output"][:60]))
        else:
            tn += 1
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(p, 3), "recall": round(r, 3),
            "f1": round(f1, 3), "misses": misses}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="eval/exec_output_dataset.jsonl")
    m = evaluate(ap.parse_args(argv).dataset)
    print(f"TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}  "
          f"precision={m['precision']} recall={m['recall']} f1={m['f1']}")
    for kind, sink, text in m["misses"]:
        print(f"  {kind} [{sink}] {text!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
