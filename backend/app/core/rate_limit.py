"""In-process login throttling: per-account lockout plus a per-IP attempt budget.

State lives in process memory, so it protects a single Uvicorn worker. A
multi-worker or multi-instance deployment should move this to a shared store
(e.g. Redis) or enforce it at the reverse proxy; see docs/DEVELOPMENT.md.
"""
import threading
import time
from collections import defaultdict, deque

from app.core.config import settings


class LoginThrottle:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: dict[str, deque] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._ip_attempts: dict[str, deque] = defaultdict(deque)

    @staticmethod
    def _prune(events: deque, horizon: float) -> None:
        while events and events[0] < horizon:
            events.popleft()

    def check(self, username: str, ip: str) -> float:
        """Return 0 when an attempt is allowed, else seconds until retry.

        Every call counts against the IP budget, whether or not it succeeds.
        """
        now = self._clock()
        key = username.lower()
        with self._lock:
            locked = self._locked_until.get(key, 0.)
            if locked > now:
                return locked - now
            attempts = self._ip_attempts[ip]
            window = settings.LOGIN_IP_WINDOW_MINUTES * 60
            self._prune(attempts, now - window)
            if len(attempts) >= settings.LOGIN_IP_MAX_ATTEMPTS:
                return attempts[0] + window - now
            attempts.append(now)
            return 0.

    def record_failure(self, username: str) -> None:
        now = self._clock()
        key = username.lower()
        window = settings.LOGIN_LOCKOUT_MINUTES * 60
        with self._lock:
            failures = self._failures[key]
            self._prune(failures, now - window)
            failures.append(now)
            if len(failures) >= settings.LOGIN_MAX_FAILURES:
                self._locked_until[key] = now + window
                failures.clear()

    def record_success(self, username: str) -> None:
        key = username.lower()
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()
            self._ip_attempts.clear()


login_throttle = LoginThrottle()
