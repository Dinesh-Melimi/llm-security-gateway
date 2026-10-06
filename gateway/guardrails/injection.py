"""Heuristic prompt-injection / jailbreak detector.

Each rule has a weight in [0, 1]. Scores combine as noisy-OR:
    score = 1 - prod(1 - w_i)
so several weak signals add up, but no single weak rule blocks alone.
This is a *first line* filter, not a guarantee - see README limitations.
"""
from __future__ import annotations

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
    _r("INJ-005", r"\b(without|no|ignore|bypass|disable)\b.{0,20}\b(safety|content|ethical|moral)\b.{0,15}\b(filters?|guidelines?|restrictions?|policies|guardrails?)\b",
       0.6, "Safety bypass request"),
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
)

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


def normalize(text: str) -> str:
    """NFKC fold + drop zero-width chars + collapse whitespace (defeats trivial obfuscation)."""
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return re.sub(r"[ \t]+", " ", text)


@dataclass
class InjectionResult:
    score: float
    matched: list[str]

    def blocked(self, threshold: float) -> bool:
        return self.score >= threshold


def score_prompt(text: str) -> InjectionResult:
    norm = normalize(text)
    remaining, matched = 1.0, []
    for rule in RULES:
        if rule.pattern.search(norm):
            matched.append(rule.rule_id)
            remaining *= 1.0 - rule.weight
    return InjectionResult(score=round(1.0 - remaining, 4), matched=matched)
