"""API-key authentication. Keys are never stored in plaintext - only SHA-256 digests."""
from __future__ import annotations

import hashlib
import hmac

from .config import Client, Settings


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def authenticate(authorization: str | None, settings: Settings) -> Client | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    digest = hash_key(authorization[7:].strip())
    # constant-time compare against every stored digest (avoid timing oracle)
    match = None
    for stored, client in settings.clients.items():
        if hmac.compare_digest(stored, digest):
            match = client
    return match
