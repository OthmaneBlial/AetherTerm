"""Bounded in-process rate and session limits for the single-worker server."""

from collections import OrderedDict
import time


MAX_FRAME_BYTES = 64 * 1024
MAX_TERMINAL_BYTES = 16 * 1024
MAX_SESSIONS_PER_BROWSER = 4
MAX_SESSIONS_PER_AGENT = 4
MAX_SESSIONS_TOTAL = 32
MAX_CONNECTED_AGENTS = 64
MAX_OPEN_AGENT_SOCKETS = 80
MAX_OPEN_BROWSER_SOCKETS = 32
SESSION_START_TIMEOUT = 10


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float, max_keys: int = 4096):
        self.max_events = max_events
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.events: OrderedDict[str, list[float]] = OrderedDict()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        if key not in self.events and len(self.events) >= self.max_keys:
            self.events.popitem(last=False)
        recent = [when for when in self.events.get(key, ()) if now - when < self.window_seconds]
        self.events[key] = recent
        self.events.move_to_end(key)
        if len(recent) >= self.max_events:
            return False
        recent.append(now)
        return True


class ConnectionLimiter:
    def __init__(self):
        self.minute = SlidingWindowLimiter(10, 60)
        self.hour = SlidingWindowLimiter(50, 3600)

    def allow(self, key: str) -> bool:
        return self.minute.allow(key) and self.hour.allow(key)
