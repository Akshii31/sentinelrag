"""Basic, explainable request checks for a portfolio security demonstration.

These heuristics are not a complete prompt-injection defense. They should be
presented as a baseline control with known false positives and false negatives.
"""

import hashlib
import re
import secrets
import time
from collections import defaultdict, deque
from threading import Lock

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("override_instructions", re.compile(r"\b(ignore|disregard|forget|override)\b.{0,80}\b(previous|prior|above|all|system|developer|instructions?|rules?)\b", re.I | re.S)),
    ("reveal_prompt", re.compile(r"\b(reveal|show|print|repeat|expose|leak)\b.{0,60}\b(system prompt|hidden prompt|developer message|instructions?)\b", re.I | re.S)),
    ("role_override", re.compile(r"\b(you are now|act as an? unrestricted|pretend to be|enter developer mode|jailbreak)\b", re.I)),
    ("safety_bypass", re.compile(r"\b(bypass|disable|ignore)\b.{0,50}\b(safety|guardrails?|security policy|content policy)\b", re.I | re.S)),
    ("secret_extraction", re.compile(r"\b(exfiltrate|dump|expose|reveal)\b.{0,50}\b(secret|api key|password|credential|token)\b", re.I | re.S)),
)


def check_injection(text: str) -> tuple[bool, str]:
    """Return whether a known suspicious instruction pattern was detected."""
    normalized = text.strip()
    for rule_name, pattern in INJECTION_PATTERNS:
        if pattern.search(normalized):
            return True, rule_name
    # Conservative heuristic for long, likely encoded blobs; not a classifier.
    if re.search(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{160,}={0,2}(?![A-Za-z0-9+/])", normalized):
        return True, "long_encoded_blob"
    return False, ""


def check_api_key(provided: str | None, expected: str) -> bool:
    """Compare API keys without timing-sensitive direct string equality."""
    if not provided or not expected:
        return False
    return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def api_key_is_configured(value: str) -> bool:
    """Reject empty and example placeholder values so the API fails closed."""
    normalized = value.strip().lower()
    if not normalized:
        return False
    placeholders = {
        "replace-with-a-long-random-local-key",
        "replace-me",
        "change-me",
        "your-api-key",
    }
    return normalized not in placeholders and not normalized.startswith("replace-with-")


def key_fingerprint(value: str | None) -> str:
    """Return a non-reversible identifier for rate limiting/log grouping."""
    return hashlib.sha256((value or "missing").encode("utf-8")).hexdigest()[:16]


class InMemoryRateLimiter:
    """Simple per-key sliding-window limiter; state resets when the process restarts."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("max_requests and window_seconds must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, identity: str, now: float | None = None) -> bool:
        moment = time.monotonic() if now is None else now
        cutoff = moment - self.window_seconds
        with self._lock:
            events = self._events[identity]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self.max_requests:
                return False
            events.append(moment)
            return True
