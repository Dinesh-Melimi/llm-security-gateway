"""Evaluate the heuristic injection detector against a labeled dataset.

Usage: python -m scripts.evaluate [eval/injection_dataset.jsonl] [--threshold 0.7]
Reports confusion matrix, precision, recall, F1, and lists every misclassification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from gateway.guardrails.injection import score_prompt

DEFAULT = Path(__file__).resolve().parent.parent / "eval" / "injection_dataset.jsonl"


def evaluate(path: str | Path = DEFAULT, threshold: float = 0.7) -> dict:
    tp = fp = tn = fn = 0
    errors = []
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        row = json.loads(line)
        res = score_prompt(row["text"])
        pred = res.score >= threshold
        actual = row["label"] == "injection"
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
            errors.append(("FP", res.score, row["text"]))
        elif not pred and actual:
            fn += 1
            errors.append(("FN", res.score, row["text"]))
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": tp + fp + tn + fn,
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3), "errors": errors}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=DEFAULT)
    ap.add_argument("--threshold", type=float, default=0.7)
    a = ap.parse_args()
    r = evaluate(a.path, a.threshold)
    print(f"n={r['n']} threshold={r['threshold']}")
    print(f"TP={r['tp']} FP={r['fp']} TN={r['tn']} FN={r['fn']}")
    print(f"precision={r['precision']} recall={r['recall']} f1={r['f1']}")
    for kind, score, text in r["errors"]:
        print(f"  {kind} score={score:.2f}  {text[:90]}")
    print("\nNote: small hand-built dataset; numbers are indicative, not a benchmark.")


if __name__ == "__main__":
    main()
