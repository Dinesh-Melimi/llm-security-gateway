"""Generate a client-ready AI security risk assessment from the gateway policy and audit log.

Reviews configuration (policy-as-code) and runtime evidence (audit events), rates each
finding, and maps it to the OWASP Top 10 for LLM Applications (2025) and NIST AI RMF.

Usage: python -m scripts.risk_assessment [--policy config/policy.yaml] [--log logs/audit.jsonl]
                                         [--client "Acme Health"] [--out report.md] [--json]
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from gateway.config import Settings, load_settings
from scripts.usage_report import summarize

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
BLOCK_RATE_ALERT = 0.10        # a client with >10% blocked requests needs a look
RECOMMENDED_THRESHOLD = 0.7    # validated by scripts/evaluate.py (95% precision, 80% recall)


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    owasp: str
    nist: str
    evidence: str
    recommendation: str


def assess_config(s: Settings) -> list[Finding]:
    out: list[Finding] = []
    if s.store_raw_prompts:
        out.append(Finding("CFG-01", "Raw prompts are written to the audit log", "High",
                           "LLM02 Sensitive Information Disclosure", "Govern GV-1 / Manage MG-2",
                           "audit.store_raw_prompts is true",
                           "Set store_raw_prompts: false so only SHA-256 hashes are kept; restrict log access."))
    if not s.block_secrets:
        out.append(Finding("CFG-02", "Secrets in prompts are not blocked", "High",
                           "LLM02 Sensitive Information Disclosure", "Manage MG-2",
                           "guardrails.block_secrets is false",
                           "Enable block_secrets so API keys and private keys never reach a third-party model."))
    if not s.redact_pii:
        out.append(Finding("CFG-03", "PII redaction is disabled", "Medium",
                           "LLM02 Sensitive Information Disclosure", "Manage MG-2",
                           "guardrails.redact_pii is false",
                           "Enable redact_pii, especially for teams handling customer or patient data."))
    if s.injection_block_threshold > RECOMMENDED_THRESHOLD:
        out.append(Finding("CFG-04", "Prompt-injection threshold is looser than the tested value", "Medium",
                           "LLM01 Prompt Injection", "Measure MS-2.7",
                           f"injection_block_threshold is {s.injection_block_threshold} "
                           f"(tested value {RECOMMENDED_THRESHOLD})",
                           "Lower the threshold to the evaluated value, then re-run make eval to confirm recall."))
    for team in s.teams.values():
        if team.max_tokens > 4096:
            out.append(Finding(f"CFG-05:{team.name}", f"High token cap for team '{team.name}'", "Low",
                               "LLM10 Unbounded Consumption", "Manage MG-2",
                               f"max_tokens is {team.max_tokens}",
                               "Cap tokens to what the use case needs to limit cost and abuse."))
        if not team.blocked_topics and not s.global_blocked_topics:
            out.append(Finding(f"CFG-06:{team.name}", f"No topic restrictions for team '{team.name}'", "Low",
                               "LLM06 Excessive Agency", "Govern GV-1",
                               "no team or global blocked_topics",
                               "Agree acceptable-use topics with the business owner and encode them in policy."))
    return out


def assess_runtime(summary: dict) -> list[Finding]:
    out: list[Finding] = []
    reasons = summary["block_reasons"]
    if reasons.get("system_prompt_leak"):
        out.append(Finding("RT-01", "System prompt leakage attempts reached the model", "Critical",
                           "LLM07 System Prompt Leakage", "Manage MG-4",
                           f"{reasons['system_prompt_leak']} response(s) withheld after canary match",
                           "Treat as an incident: pull event IDs, identify the client, and rotate any "
                           "sensitive instructions held in the system prompt."))
    if reasons.get("secret_detected"):
        out.append(Finding("RT-02", "Users are pasting secrets into prompts", "High",
                           "LLM02 Sensitive Information Disclosure", "Manage MG-4",
                           f"{reasons['secret_detected']} request(s) blocked for credentials",
                           "Rotate the exposed credentials and run awareness training for the affected teams."))
    if reasons.get("prompt_injection"):
        out.append(Finding("RT-03", "Prompt-injection attempts observed", "Medium",
                           "LLM01 Prompt Injection", "Measure MS-3",
                           f"{reasons['prompt_injection']} request(s) blocked",
                           "Review the matched rules per client; repeated attempts from one app may mean "
                           "untrusted content is being forwarded to the model."))
    if reasons.get("auth_failed"):
        out.append(Finding("RT-04", "Unauthenticated access attempts", "Medium",
                           "LLM10 Unbounded Consumption", "Govern GV-6",
                           f"{reasons['auth_failed']} request(s) without a valid key",
                           "Find the source apps; this is often Shadow AI or a leaked/rotated key."))
    for name, c in summary["clients"].items():
        if name == "<unauthenticated>" or not c["requests"]:
            continue
        rate = c["blocked"] / c["requests"]
        if rate > BLOCK_RATE_ALERT:
            out.append(Finding(f"RT-05:{name}", f"High block rate for client '{name}'", "Medium",
                               "LLM01 / LLM02", "Measure MS-3",
                               f"{c['blocked']} of {c['requests']} requests blocked ({rate:.0%})",
                               "Meet with the app owner to tell misuse apart from false positives and tune policy."))
    return out


def assess(settings: Settings, log_path: str | Path | None) -> dict:
    findings = assess_config(settings)
    summary = None
    if log_path and Path(log_path).exists():
        summary = summarize(log_path)
        findings += assess_runtime(summary)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.id))
    counts = {k: sum(f.severity == k for f in findings) for k in SEVERITY_ORDER}
    return {"counts": counts, "findings": [asdict(f) for f in findings],
            "events": summary["total_events"] if summary else 0}


def render_markdown(result: dict, client: str = "Client") -> str:
    c = result["counts"]
    worst = next((k for k in SEVERITY_ORDER if c[k]), None)
    head = f"Reviewed the LLM gateway policy and {result['events']} audit events. "
    if result["findings"]:
        head += f"Found {len(result['findings'])} issue(s): " + ", ".join(f"{v} {k}" for k, v in c.items() if v) + "."
    else:
        head += "No issues found."
    lines = [f"# AI Security Risk Assessment - {client}", "", "## Executive summary", "", head, ""]
    if worst:
        lines += [f"Highest risk: **{worst}**. Address Critical and High items before expanding AI use.", ""]
    lines += ["## Findings", "", "| ID | Severity | Finding | OWASP LLM | NIST AI RMF |", "|---|---|---|---|---|"]
    lines += [f"| {f['id']} | {f['severity']} | {f['title']} | {f['owasp']} | {f['nist']} |" for f in result["findings"]]
    lines += ["", "## Details and recommendations", ""]
    for f in result["findings"]:
        lines += [f"### {f['id']} - {f['title']} ({f['severity']})", "",
                  f"- Evidence: {f['evidence']}", f"- Recommendation: {f['recommendation']}", ""]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=None)
    ap.add_argument("--log", default="logs/audit.jsonl")
    ap.add_argument("--client", default="Client")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    result = assess(load_settings(a.policy), a.log)
    text = json.dumps(result, indent=2) if a.json else render_markdown(result, a.client)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"wrote {a.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
