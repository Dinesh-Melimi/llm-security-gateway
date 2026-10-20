"""In-process library API: the same guardrails without running the gateway.

For teams that call an LLM directly from their service, this is the
three-line adoption path:

    from gateway.sdk import validate_prompt, guard_output, guarded

    validate_prompt(user_text)                 # raises UnsafePrompt on injection or secrets
    sql = guard_output(llm_text, sink="sql")   # raises InsecureOutput, returns the code to run

    @guarded(sink="shell")
    def run_suggested(cmd: str): ...           # first argument is checked before the call
"""
from __future__ import annotations

import functools
from dataclasses import dataclass

from .guardrails import exec_guard, injection, pii


class GuardrailError(Exception):
    """Base class so callers can catch every guardrail decision at once."""


class UnsafePrompt(GuardrailError):
    def __init__(self, reason: str, detail: list[str]):
        super().__init__(f"{reason}: {', '.join(detail)}")
        self.reason, self.detail = reason, detail


class InsecureOutput(GuardrailError):
    def __init__(self, verdict: exec_guard.ExecVerdict):
        rules = ", ".join(f"{f.rule} ({f.why})" for f in verdict.findings)
        super().__init__(f"model output blocked for {verdict.sink} sink: {rules}")
        self.verdict = verdict


@dataclass
class PromptCheck:
    text: str                 # PII-redacted text, safe to forward
    injection_score: float
    redactions: list[str]


def validate_prompt(text: str, threshold: float = 0.7, block_secrets: bool = True,
                    redact_pii: bool = True) -> PromptCheck:
    inj = injection.score_prompt(text)
    if inj.blocked(threshold):
        raise UnsafePrompt("prompt_injection", inj.matched)
    findings = pii.detect(text)
    if block_secrets and any(f.category == "secret" for f in findings):
        raise UnsafePrompt("secret_detected", sorted({f.kind for f in findings if f.category == "secret"}))
    kinds = sorted({f.kind for f in findings})
    out = pii.redact(text, findings) if (findings and redact_pii) else text
    return PromptCheck(out, inj.score, kinds)


def redact(text: str) -> str:
    return pii.redact(text)


def guard_output(text: str, sink: str, allow_domains: set[str] | None = None,
                 block_at: str = "high") -> str:
    """Return the payload (code blocks extracted) if safe for `sink`, else raise InsecureOutput."""
    v = exec_guard.check_output(text, sink, allow_domains, block_at)
    if not v.allowed:
        raise InsecureOutput(v)
    return text if sink in ("html", "markdown") else exec_guard.extract_code(text)


def guarded(sink: str, allow_domains: set[str] | None = None, block_at: str = "high"):
    """Decorator: checks the function's first argument as model output headed to `sink`."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(payload, *args, **kwargs):
            return fn(guard_output(payload, sink, allow_domains, block_at), *args, **kwargs)
        return wrapper
    return deco
