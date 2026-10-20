"""Output guard for model text that is about to be executed or rendered.

OWASP LLM05 (Improper Output Handling): when an app pipes model output into a
shell, a database, `eval`, or a web page, the model is effectively writing
code that runs with the app's privileges. A prompt injection upstream turns
into command execution, SQL injection, or XSS downstream.

`check_output(text, sink)` looks only at what matters for the sink the output
is headed to, and returns every finding with a rule id and a reason, so a
developer can see exactly why something was stopped.

Sinks: shell, sql, python, html, markdown. Fenced code blocks are extracted
first; if there are none, the whole text is treated as the payload.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

SINKS = ("shell", "sql", "python", "html", "markdown")
SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class ExecRule:
    id: str
    sink: str
    pattern: re.Pattern
    severity: str
    why: str


def _r(rule_id: str, sink: str, regex: str, severity: str, why: str) -> ExecRule:
    return ExecRule(rule_id, sink, re.compile(regex, re.IGNORECASE | re.MULTILINE), severity, why)


RULES: list[ExecRule] = [
    # shell
    _r("SH-01", "shell", r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/|~|\*|\$HOME)(\s|$)", "critical", "recursive delete of root, home or wildcard"),
    _r("SH-02", "shell", r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", "critical", "downloads and runs a remote script"),
    _r("SH-03", "shell", r"(/dev/tcp/|\bnc\b[^\n]*\s-e\s|\bbash\s+-i\b|\bmkfifo\b)", "critical", "reverse shell pattern"),
    _r("SH-04", "shell", r"base64\s+(-d|--decode)[^|\n]*\|\s*(ba)?sh\b", "critical", "decodes and runs hidden commands"),
    _r("SH-05", "shell", r"\bsudo\b|\bsu\s+-", "high", "privilege escalation"),
    _r("SH-06", "shell", r"\bchmod\s+(-R\s+)?777\b|\bchmod\s+[+ugo]*s\b", "high", "world-writable or setuid permissions"),
    _r("SH-07", "shell", r"(>>?\s*~?/?\.ssh/|authorized_keys|\bcrontab\b|/etc/(passwd|shadow|sudoers))", "high", "persistence or credential file access"),
    _r("SH-08", "shell", r"\b(mkfs|dd\s+if=|shutdown|reboot|:\(\)\s*\{)", "high", "destructive system command"),
    # sql
    _r("SQL-01", "sql", r"\b(drop|truncate)\s+(table|database|schema)\b", "critical", "drops or empties data"),
    _r("SQL-02", "sql", r"\b(delete\s+from|update)\s+[\w.\"`\[\]]+(\s+set\s+[^;]*?)?\s*(;|$)(?![^;]*\bwhere\b)", "critical", "DELETE/UPDATE with no WHERE clause"),
    _r("SQL-03", "sql", r";\s*(select|insert|update|delete|drop|alter|create|grant|exec)\b", "high", "stacked statements"),
    _r("SQL-04", "sql", r"\b(grant|revoke|alter\s+user|create\s+user)\b", "high", "changes database privileges"),
    _r("SQL-05", "sql", r"\bunion\s+(all\s+)?select\b", "medium", "UNION SELECT can pull data from other tables"),
    _r("SQL-06", "sql", r"\b(xp_cmdshell|load_file|into\s+outfile|copy\s+\w+\s+(from|to)\s+program)\b", "critical", "file or OS access from SQL"),
    _r("SQL-07", "sql", r"\b(sleep|pg_sleep|benchmark|waitfor\s+delay)\s*\(?", "medium", "time-delay function"),
    # python
    _r("PY-01", "python", r"\b(eval|exec|compile)\s*\(", "critical", "dynamic code execution"),
    _r("PY-02", "python", r"\bos\.(system|popen|exec\w*|spawn\w*)\s*\(", "critical", "runs OS commands"),
    _r("PY-03", "python", r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True", "critical", "subprocess with shell=True"),
    _r("PY-04", "python", r"\b(pickle|marshal|dill)\.loads?\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)", "high", "unsafe deserialization"),
    _r("PY-05", "python", r"__import__\s*\(|\bimportlib\.import_module\s*\(", "high", "dynamic import"),
    _r("PY-06", "python", r"\bopen\s*\(\s*['\"](/etc/|/root/|~/.ssh|/proc/)", "high", "reads sensitive system files"),
    _r("PY-07", "python", r"\b(requests|httpx|urllib\.request)\.\w+\s*\(\s*['\"]https?://", "medium", "makes outbound network calls"),
    # html
    _r("HT-01", "html", r"<\s*script\b", "critical", "script tag"),
    _r("HT-02", "html", r"\son\w+\s*=\s*['\"]?", "high", "inline event handler"),
    _r("HT-03", "html", r"(href|src|action)\s*=\s*['\"]?\s*javascript:", "critical", "javascript: URL"),
    _r("HT-04", "html", r"<\s*(iframe|object|embed|form)\b", "high", "embeds content or posts data"),
]

MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(<?)([^)\s>]+)")
MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*([^)\s]+)")
FENCE = re.compile(r"```[\w+-]*\n(.*?)```", re.DOTALL)


@dataclass
class ExecFinding:
    rule: str
    severity: str
    why: str
    match: str


@dataclass
class ExecVerdict:
    sink: str
    allowed: bool
    findings: list[ExecFinding] = field(default_factory=list)

    @property
    def worst(self) -> str:
        return max((f.severity for f in self.findings), key=SEV_ORDER.get, default="none")


def extract_code(text: str) -> str:
    blocks = FENCE.findall(text)
    return "\n".join(blocks) if blocks else text


def _markdown(text: str, allow_domains: set[str]) -> list[ExecFinding]:
    out = []
    for _, url in MD_IMAGE.findall(text):
        host = (urlparse(url).hostname or "").lower()
        if host and not any(host == d or host.endswith("." + d) for d in allow_domains):
            # Images load automatically when rendered: a query string is a silent data channel.
            sev = "critical" if urlparse(url).query else "high"
            out.append(ExecFinding("MD-01", sev, f"auto-loading image from non-allowed host {host}", url[:120]))
    for url in MD_LINK.findall(text):
        if url.lower().startswith(("javascript:", "data:", "vbscript:")):
            out.append(ExecFinding("MD-02", "critical", "link with script or data scheme", url[:120]))
    return out


def check_output(text: str, sink: str, allow_domains: set[str] | None = None,
                 block_at: str = "high", read_only_sql: bool = True) -> ExecVerdict:
    """Scan model output before it reaches `sink`. Blocks at or above `block_at` severity."""
    if sink not in SINKS:
        raise ValueError(f"unknown sink {sink!r}; expected one of {SINKS}")
    findings: list[ExecFinding] = []
    if sink == "markdown":
        findings = _markdown(text, allow_domains or set())
        payload = text
        sink_rules = "html"  # raw HTML inside markdown renders too
    else:
        payload = text if sink == "html" else extract_code(text)
        sink_rules = sink
    for r in RULES:
        if r.sink != sink_rules:
            continue
        m = r.pattern.search(payload)
        if m:
            findings.append(ExecFinding(r.id, r.severity, r.why, m.group(0).strip()[:120]))
    if sink == "sql" and read_only_sql:
        stmts = [s.strip() for s in payload.strip().rstrip(";").split(";") if s.strip()]
        if stmts and not all(re.match(r"(?is)^\s*(--[^\n]*\n\s*)*(select|with)\b", s) for s in stmts):
            findings.append(ExecFinding("SQL-00", "high", "read-only sink got a statement that is not SELECT",
                                        stmts[0][:120]))
    floor = SEV_ORDER[block_at]
    allowed = not any(SEV_ORDER[f.severity] >= floor for f in findings)
    return ExecVerdict(sink, allowed, findings)
