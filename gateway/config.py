"""Policy configuration loading (YAML -> typed objects)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "policy.yaml"


@dataclass(frozen=True)
class Client:
    client_id: str
    team: str
    key_sha256: str


@dataclass(frozen=True)
class TeamPolicy:
    name: str
    allowed_models: tuple[str, ...]
    max_tokens: int
    requests_per_minute: int
    blocked_topics: tuple[str, ...] = ()


@dataclass
class Settings:
    clients: dict[str, Client]  # keyed by sha256 of API key
    teams: dict[str, TeamPolicy]
    injection_block_threshold: float = 0.7
    redact_pii: bool = True
    block_secrets: bool = True
    store_raw_prompts: bool = False
    audit_log_path: str = "logs/audit.jsonl"
    provider: str = "mock"
    canary_token: str = "CANARY-7f3a9c"  # noqa: S105 - not a credential, a leak-detection marker
    global_blocked_topics: tuple[str, ...] = field(default_factory=tuple)


def load_settings(path: str | os.PathLike | None = None) -> Settings:
    path = Path(path or os.environ.get("GATEWAY_POLICY", DEFAULT_POLICY_PATH))
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    teams = {
        name: TeamPolicy(
            name=name,
            allowed_models=tuple(t.get("allowed_models", [])),
            max_tokens=int(t.get("max_tokens", 1024)),
            requests_per_minute=int(t.get("requests_per_minute", 60)),
            blocked_topics=tuple(s.lower() for s in t.get("blocked_topics", [])),
        )
        for name, t in (raw.get("teams") or {}).items()
    }
    clients = {}
    for c in raw.get("clients") or []:
        if c["team"] not in teams:
            raise ValueError(f"client {c['id']} references unknown team {c['team']}")
        clients[c["key_sha256"].lower()] = Client(c["id"], c["team"], c["key_sha256"].lower())

    g = raw.get("guardrails") or {}
    a = raw.get("audit") or {}
    return Settings(
        clients=clients,
        teams=teams,
        injection_block_threshold=float(g.get("injection_block_threshold", 0.7)),
        redact_pii=bool(g.get("redact_pii", True)),
        block_secrets=bool(g.get("block_secrets", True)),
        canary_token=str(g.get("canary_token", "CANARY-7f3a9c")),
        global_blocked_topics=tuple(s.lower() for s in g.get("blocked_topics", [])),
        store_raw_prompts=bool(a.get("store_raw_prompts", False)),
        audit_log_path=os.environ.get("GATEWAY_AUDIT_LOG", a.get("path", "logs/audit.jsonl")),
        provider=os.environ.get("GATEWAY_PROVIDER", raw.get("provider", "mock")),
    )
