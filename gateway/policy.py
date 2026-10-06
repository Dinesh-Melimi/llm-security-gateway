"""Team-level policy checks (model allow-list, token caps, blocked topics)."""
from __future__ import annotations

import re

from .config import Settings, TeamPolicy


class PolicyViolation(Exception):
    def __init__(self, code: str, message: str, status: int = 403):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def check_request(team: TeamPolicy, settings: Settings, model: str, max_tokens: int | None, text: str) -> int:
    """Raise PolicyViolation or return the effective max_tokens."""
    if model not in team.allowed_models:
        raise PolicyViolation("model_not_allowed", f"model '{model}' not permitted for team '{team.name}'")
    effective = min(max_tokens or team.max_tokens, team.max_tokens)
    lowered = text.lower()
    for topic in team.blocked_topics + settings.global_blocked_topics:
        if re.search(rf"\b{re.escape(topic)}\b", lowered):
            raise PolicyViolation("blocked_topic", f"request touches blocked topic '{topic}'")
    return effective
