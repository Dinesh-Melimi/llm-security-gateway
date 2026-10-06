"""Output guardrails: PII leakage and system-prompt canary detection."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import pii


@dataclass
class OutputVerdict:
    text: str
    canary_leak: bool = False
    pii_kinds: list[str] = field(default_factory=list)


def inspect_output(text: str, canary: str, redact_pii: bool = True) -> OutputVerdict:
    if canary and canary in text:
        # The model echoed content only present in the system prompt -> prompt leakage.
        return OutputVerdict(text="", canary_leak=True)
    findings = pii.detect(text)
    kinds = sorted({f.kind for f in findings})
    if findings and redact_pii:
        text = pii.redact(text, findings)
    return OutputVerdict(text=text, pii_kinds=kinds)
