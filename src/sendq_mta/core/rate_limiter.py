"""Rate limiter for inbound/outbound traffic control."""

import time
import threading
import logging
from collections import defaultdict

from sendq_mta.core.config import Config

logger = logging.getLogger("sendq-mta.rate_limiter")


class TokenBucket:
    """Token bucket rate limiter — thread-safe."""

    def __init__(self, rate: float, capacity: int):
        self.rate = rate              # tokens per second
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class SlidingWindowCounter:
    """Sliding window counter for per-minute / per-hour limits."""

    def __init__(self, window_seconds: int, max_count: int):
        self.window = window_seconds
        self.max_count = max_count
        self.entries: list[float] = []
        self.lock = threading.Lock()

    def record(self) -> bool:
        """Record an event. Returns True if within limit, False if exceeded."""
        now = time.monotonic()
        with self.lock:
            cutoff = now - self.window
            self.entries = [t for t in self.entries if t > cutoff]
            if len(self.entries) >= self.max_count:
                return False
            self.entries.append(now)
            return True

    @property
    def count(self) -> int:
        now = time.monotonic()
        with self.lock:
            cutoff = now - self.window
            self.entries = [t for t in self.entries if t > cutoff]
            return len(self.entries)


class RateLimiter:
    """Manages all rate limiting for the MTA."""

    def __init__(self, config: Config):
        self.config = config
        self._lock = threading.Lock()

        # Per-IP inbound counters
        self._ip_message_counters: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(
                60, self.config.get("rate_limiting.inbound.max_messages_per_ip_per_minute", 100)
            )
        )
        self._ip_connection_counts: dict[str, int] = defaultdict(int)
        self._ip_error_counts: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(
                3600, self.config.get("rate_limiting.inbound.max_errors_per_ip", 10)
            )
        )
        self._banned_ips: dict[str, float] = {}

        # Per-domain outbound counters
        self._domain_counters: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(
                60,
                self.config.get(
                    "rate_limiting.outbound.max_messages_per_domain_per_minute", 200
                ),
            )
        )

        # Per-user counters
        self._user_message_counters: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(
                3600, self.config.get("rate_limiting.per_user.max_messages_per_hour", 500)
            )
        )
        self._user_recipient_counters: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(
                3600, self.config.get("rate_limiting.per_user.max_recipients_per_hour", 2000)
            )
        )

        # Global outbound rate
        global_rate = self.config.get("rate_limiting.outbound.max_messages_per_second", 500)
        self._global_outbound = TokenBucket(rate=global_rate, capacity=global_rate * 2)

        # Cleanup thread
        self._cleanup_running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            if ip in self._banned_ips:
                if time.monotonic() > self._banned_ips[ip]:
                    del self._banned_ips[ip]
                    return False
                return True
        return False

    def ban_ip(self, ip: str) -> None:
        duration = self.config.get("rate_limiting.inbound.ban_duration", 3600)
        with self._lock:
            self._banned_ips[ip] = time.monotonic() + duration
        logger.warning("Banned IP %s for %d seconds", ip, duration)

    def record_error(self, ip: str) -> None:
        if not self._ip_error_counts[ip].record():
            self.ban_ip(ip)

    def check_inbound_rate(self, ip: str) -> bool:
        if not self.config.get("rate_limiting.enabled", True):
            return True
        return self._ip_message_counters[ip].record()

    def check_outbound_rate(self, domain: str) -> bool:
        if not self.config.get("rate_limiting.enabled", True):
            return True
        if not self._global_outbound.consume():
            return False
        return self._domain_counters[domain].record()

    def check_user_rate(self, username: str, recipient_count: int = 1) -> bool:
        if not self.config.get("rate_limiting.enabled", True):
            return True
        if not self._user_message_counters[username].record():
            return False
        for _ in range(recipient_count):
            if not self._user_recipient_counters[username].record():
                return False
        return True

    def check_connection_limit(self, ip: str) -> bool:
        max_conn = self.config.get("rate_limiting.inbound.max_connections_per_ip", 50)
        with self._lock:
            return self._ip_connection_counts[ip] < max_conn

    def track_connection(self, ip: str, connected: bool) -> None:
        with self._lock:
            if connected:
                self._ip_connection_counts[ip] += 1
            else:
                self._ip_connection_counts[ip] = max(0, self._ip_connection_counts[ip] - 1)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "banned_ips": len(self._banned_ips),
                "tracked_ips": len(self._ip_message_counters),
                "tracked_domains": len(self._domain_counters),
                "tracked_users": len(self._user_message_counters),
            }

    def _cleanup_loop(self) -> None:
        """Periodically clean up expired entries."""
        while self._cleanup_running:
            time.sleep(300)
            now = time.monotonic()
            with self._lock:
                expired = [ip for ip, exp in self._banned_ips.items() if now > exp]
                for ip in expired:
                    del self._banned_ips[ip]

    def shutdown(self) -> None:
        self._cleanup_running = False
