"""Heuristic prompt-injection / jailbreak detector.

Each rule has a weight in [0, 1]. Scores combine as noisy-OR:
    score = 1 - prod(1 - w_i)
so several weak signals add up, but no single weak rule blocks alone.
This is a *first line* filter, not a guarantee - see README limitations.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern
    weight: float
    description: str


def _r(rule_id: str, regex: str, weight: float, desc: str) -> Rule:
    return Rule(rule_id, re.compile(regex, re.IGNORECASE | re.DOTALL), weight, desc)


RULES: tuple[Rule, ...] = (
    _r("INJ-001", r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|your|system)\b.{0,30}\b(instructions?|rules?|prompts?|guidelines?|directives?|context)\b",
       0.8, "Instruction override attempt"),
    _r("INJ-002", r"\b(reveal|show|print|repeat|output|display|leak|tell me)\b.{0,40}\b(system prompt|hidden (prompt|instructions)|initial instructions|your instructions|developer message)\b",
       0.75, "System prompt extraction"),
    _r("INJ-003", r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|roleplay as)\b.{0,60}\b(DAN|unfiltered|unrestricted|jailbroken|no (rules|restrictions|limits|filters)|evil)\b",
       0.8, "Persona jailbreak (DAN-style)"),
    _r("INJ-004", r"\b(developer|god|admin|debug|maintenance|sudo)\s+mode\b", 0.5, "Privileged mode request"),
    _r("INJ-005", r"\b(without|no|ignore|bypass|disable|skip|turn off)\b.{0,20}\b(safety|content|ethical|moral)\b.{0,15}\b(filters?|guidelines?|restrictions?|policies|guardrails?)\b",
       0.7, "Safety bypass request"),
    _r("INJ-006", r"(^|\n)\s*(system|assistant)\s*:|<\|?(im_start|system|endoftext)\|?>|\[/?INST\]|###\s*(system|instruction)",
       0.7, "Chat-template / role delimiter injection"),
    _r("INJ-007", r"\b(base64|rot13|hex)\b.{0,40}\b(decode|decoded|execute|follow|run)\b", 0.35, "Encoded payload smuggling"),
    _r("INJ-008", r"\bnew (instructions?|task|rules?)\s*:", 0.4, "Inline instruction replacement"),
    _r("INJ-009", r"\b(do anything now|jailbreak|jailbroken)\b", 0.7, "Explicit jailbreak keywords"),
    _r("INJ-010", r"\b(hypothetically|in a fictional story|for a novel)\b.{0,80}\b(how to (make|build|synthesi[sz]e)|step[- ]by[- ]step)\b",
       0.3, "Fictional framing for harmful instructions"),
    _r("INJ-011", r"\b(the (above|previous) (text|message) (was|is) (fake|a test))\b|\bend of (user )?input\b", 0.45, "Context termination trick"),
    _r("INJ-012", r"\b(ignore|disregard)\s+(the\s+)?(above|previous|prior|preceding)\b", 0.7, "Short-form override ('ignore the above')"),
    _r("INJ-013", r"\b(print|output|repeat|show|dump)\b.{0,15}\b(everything|all( the)? text|whatever)\b.{0,10}\babove\b", 0.6,
       "Context dump request"),
    _r("INJ-014", r"\b(forget|drop|abandon|stop)\b.{0,20}\b(the|your|current|original)\b.{0,15}\b(task|assignment|job|instructions?)\b", 0.5,
       "Task abandonment"),
    _r("INJ-015", r"\b(guidance|instructions?|rules|guidelines|directions)\b.{0,40}\b(no longer appl(y|ies)|(don't|do not|doesn't) apply|(is|are) (void|outdated|obsolete|cancell?ed))\b",
       0.7, "Paraphrased override ('earlier rules no longer apply')"),
    _r("INJ-016", r"\b(list|reveal|give|show|send|dump)\b.{0,25}\b(api keys?|passwords?|credentials|secrets|access tokens?)\b", 0.45,
       "Credential harvesting request"),
    _r("INJ-017", r"\b(concatenate|combine|join|merge)\b.{0,40}\b(do|follow|execute|run|carry out)\b.{0,40}\b(says|result|instructions?)\b", 0.7,
       "Split payload reassembly"),
    _r("INJ-018", r"\b(carry out|follow|execute|obey)\b.{0,10}\b(the )?(request|instructions?|commands?)\b.{0,10}\b(it|that|they) (contains?|says?)\b", 0.45,
       "Execute embedded request"),
)

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
# Cyrillic and Greek letters that look identical to Latin ones (NFKC leaves them alone).
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0456": "i", "\u0441": "c", "\u0440": "p", "\u0445": "x",
    "\u0443": "y", "\u043a": "k", "\u043c": "m", "\u0442": "t", "\u043d": "h", "\u0432": "b", "\u0455": "s",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0406": "I", "\u0421": "C", "\u0420": "P", "\u0425": "X",
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03c1": "p", "\u039f": "O", "\u0391": "A",
})
_LEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "@": "a", "$": "s", "7": "t"})
_SPACED_RUN = re.compile(r"(?<!\S)(?:\S ){2,}\S(?!\S)")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _fold(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).translate(_CONFUSABLES)


def normalize(text: str) -> str:
    """NFKC fold + drop zero-width chars + collapse whitespace (defeats trivial obfuscation)."""
    return re.sub(r"[ \t]+", " ", _fold(text))


def _despace(text: str) -> str | None:
    """'i g n o r e  a l l' -> 'ignore all': join runs of 4+ single characters separated by one space."""
    if not _SPACED_RUN.search(text):
        return None
    joined = _SPACED_RUN.sub(lambda m: m.group(0).replace(" ", ""), text)
    return re.sub(r" {2,}", " ", joined)


def _decoded_b64(text: str) -> list[str]:
    out = []
    for blob in _B64.findall(text):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable() and len(decoded) >= 8:
            out.append(decoded)
    return out


def variants(text: str) -> list[tuple[str, str]]:
    """Views of the prompt an attacker might hide behind: as written, de-leeted, de-spaced, base64-decoded."""
    norm = normalize(text)
    views = [("plain", norm)]
    if re.search(r"[a-z][0-9@$][a-z]", norm, re.IGNORECASE):
        views.append(("leet", norm.translate(_LEET)))
    spaced = _despace(_fold(text))
    if spaced:
        views.append(("despaced", spaced))
    views += [("base64", normalize(d)) for d in _decoded_b64(norm)]
    return views


@dataclass
class InjectionResult:
    score: float
    matched: list[str]

    def blocked(self, threshold: float) -> bool:
        return self.score >= threshold


def _score_view(text: str) -> tuple[float, list[str]]:
    remaining, matched = 1.0, []
    for rule in RULES:
        if rule.pattern.search(text):
            matched.append(rule.rule_id)
            remaining *= 1.0 - rule.weight
    return round(1.0 - remaining, 4), matched


def score_prompt(text: str) -> InjectionResult:
    """Score every de-obfuscated view and keep the worst; non-plain hits are tagged with the view name."""
    best = InjectionResult(score=0.0, matched=[])
    for name, view in variants(text):
        score, matched = _score_view(view)
        if score > best.score:
            tag = [] if name == "plain" else [f"OBF-{name}"]
            best = InjectionResult(score=score, matched=matched + tag)
    return best
