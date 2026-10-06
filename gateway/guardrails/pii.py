"""PII and secret detection + redaction."""
from __future__ import annotations

import re
from dataclasses import dataclass


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ssn_valid(m: str) -> bool:
    area, group, serial = m[0:3], m[4:6], m[7:11]
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


# (kind, category, regex, validator)
PATTERNS = [
    ("PRIVATE_KEY", "secret",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", re.DOTALL), None),
    ("AWS_ACCESS_KEY", "secret", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"), None),
    ("AWS_SECRET_KEY", "secret",
     re.compile(r"(?i)aws.{0,20}(?:secret|private).{0,20}[=:]\s*['\"]?([A-Za-z0-9/+=]{40})\b"), None),
    ("EMAIL", "pii", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("SSN", "pii", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), _ssn_valid),
    ("CREDIT_CARD", "pii", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), luhn_valid),
    ("PHONE", "pii", re.compile(r"(?<![\w-])(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b"), None),
]


@dataclass(frozen=True)
class Finding:
    kind: str
    category: str  # "pii" | "secret"
    start: int
    end: int


def detect(text: str) -> list[Finding]:
    findings: list[Finding] = []
    taken: list[tuple[int, int]] = []
    for kind, category, rx, validator in PATTERNS:
        for m in rx.finditer(text):
            s, e = m.span()
            if any(s < te and e > ts for ts, te in taken):
                continue  # earlier (higher-priority) pattern already covers it
            if validator and not validator(m.group(0)):
                continue
            findings.append(Finding(kind, category, s, e))
            taken.append((s, e))
    return sorted(findings, key=lambda f: f.start)


def redact(text: str, findings: list[Finding] | None = None) -> str:
    findings = detect(text) if findings is None else findings
    out, last = [], 0
    for f in findings:
        out.append(text[last:f.start])
        out.append(f"[REDACTED_{f.kind}]")
        last = f.end
    out.append(text[last:])
    return "".join(out)
