"""Tests for the rate limiter module."""

import time

import pytest

from sendq_mta.core.config import Config
from sendq_mta.core.rate_limiter import RateLimiter, TokenBucket, SlidingWindowCounter


class TestTokenBucket:
    def test_allows_within_capacity(self):
        bucket = TokenBucket(rate=10.0, capacity=10)
        for _ in range(10):
            assert bucket.consume() is True

    def test_rejects_over_capacity(self):
        bucket = TokenBucket(rate=1.0, capacity=5)
        for _ in range(5):
            bucket.consume()
        assert bucket.consume() is False

    def test_refills_over_time(self):
        bucket = TokenBucket(rate=100.0, capacity=10)
        for _ in range(10):
            bucket.consume()
        assert bucket.consume() is False
        time.sleep(0.15)
        assert bucket.consume() is True


class TestSlidingWindowCounter:
    def test_allows_within_limit(self):
        counter = SlidingWindowCounter(window_seconds=60, max_count=5)
        for _ in range(5):
            assert counter.record() is True

    def test_rejects_over_limit(self):
        counter = SlidingWindowCounter(window_seconds=60, max_count=3)
        for _ in range(3):
            counter.record()
        assert counter.record() is False

    def test_count_property(self):
        counter = SlidingWindowCounter(window_seconds=60, max_count=10)
        assert counter.count == 0
        counter.record()
        counter.record()
        assert counter.count == 2


class TestRateLimiter:
    def test_inbound_rate_allowed(self):
        config = Config("/nonexistent/path.yml")
        limiter = RateLimiter(config)
        assert limiter.check_inbound_rate("192.168.1.1") is True
        limiter.shutdown()

    def test_ban_and_check(self):
        config = Config("/nonexistent/path.yml")
        limiter = RateLimiter(config)
        assert limiter.is_banned("192.168.1.1") is False
        limiter.ban_ip("192.168.1.1")
        assert limiter.is_banned("192.168.1.1") is True
        limiter.shutdown()

    def test_connection_limit(self):
        config = Config("/nonexistent/path.yml")
        limiter = RateLimiter(config)
        assert limiter.check_connection_limit("10.0.0.1") is True
        limiter.shutdown()

    def test_get_stats(self):
        config = Config("/nonexistent/path.yml")
        limiter = RateLimiter(config)
        stats = limiter.get_stats()
        assert "banned_ips" in stats
        assert "tracked_ips" in stats
        limiter.shutdown()
