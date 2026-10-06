"""In-memory sliding-window rate limiter (per client). Swap for Redis in multi-replica deploys."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, window_seconds: float = 60.0, clock=time.monotonic):
        self.window = window_seconds
        self.clock = clock
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds)."""
        now = self.clock()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= limit:
                return False, max(0.0, self.window - (now - q[0]))
            q.append(now)
            return True, 0.0
