"""Structured JSONL audit log. Prompts are SHA-256 hashed by default (privacy by design)."""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from pathlib import Path


class AuditLogger:
    def __init__(self, path: str, store_raw: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.store_raw = store_raw
        self._lock = threading.Lock()

    def log(self, *, client_id: str | None, team: str | None, model: str | None, decision: str,
            reason: str | None = None, prompt: str = "", **extra) -> str:
        event_id = str(uuid.uuid4())
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_id": event_id,
            "client_id": client_id,
            "team": team,
            "model": model,
            "decision": decision,  # allowed | blocked | redacted
            "reason": reason,
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest() if prompt else None,
            "prompt_chars": len(prompt),
            **extra,
        }
        if self.store_raw:
            record["prompt_raw"] = prompt
        line = json.dumps(record, separators=(",", ":"))
        with self._lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return event_id
