"""Tests for configuration loading and validation."""

import os
import tempfile

import pytest
import yaml

from sendq_mta.core.config import Config, _deep_merge


class TestDeepMerge:
    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"server": {"hostname": "old", "port": 25}}
        override = {"server": {"hostname": "new"}}
        result = _deep_merge(base, override)
        assert result == {"server": {"hostname": "new", "port": 25}}

    def test_deep_nested_merge(self):
        base = {"a": {"b": {"c": 1, "d": 2}}}
        override = {"a": {"b": {"c": 10}}}
        result = _deep_merge(base, override)
        assert result == {"a": {"b": {"c": 10, "d": 2}}}


class TestConfig:
    def test_loads_defaults_without_file(self):
        config = Config("/nonexistent/path.yml")
        assert config.get("server.hostname") == "localhost"
        assert config.get("server.max_message_size") == 52428800
        assert config.path is None

    def test_loads_from_file(self):
        data = {
            "server": {"hostname": "test.example.com"},
            "relay": {"enabled": True, "host": "relay.example.com"},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            yaml.dump(data, f)
            f.flush()
            config = Config(f.name)

        try:
            assert config.get("server.hostname") == "test.example.com"
            assert config.get("relay.enabled") is True
            assert config.get("relay.host") == "relay.example.com"
            # Defaults still present for unset keys
            assert config.get("relay.port") == 587
            assert config.path == f.name
        finally:
            os.unlink(f.name)

    def test_get_dotted_key(self):
        config = Config("/nonexistent/path.yml")
        assert config.get("queue.workers") == 16
        assert config.get("rate_limiting.inbound.max_connections_per_ip") == 50
        assert config.get("nonexistent.key", "default") == "default"

    def test_set_and_get(self):
        config = Config("/nonexistent/path.yml")
        config.set("server.hostname", "custom.host")
        assert config.get("server.hostname") == "custom.host"

    def test_validate_defaults_pass(self):
        config = Config("/nonexistent/path.yml")
        errors = config.validate()
        # Defaults should have minimal errors (TLS cert missing if listeners use TLS)
        # But hostname is "localhost" which is valid
        hostname_errors = [e for e in errors if "hostname" in e]
        assert len(hostname_errors) == 0

    def test_validate_missing_relay_host(self):
        data = {"relay": {"enabled": True, "host": ""}}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            yaml.dump(data, f)
            f.flush()
            config = Config(f.name)

        try:
            errors = config.validate()
            relay_errors = [e for e in errors if "relay.host" in e]
            assert len(relay_errors) > 0
        finally:
            os.unlink(f.name)

    def test_as_dict_returns_copy(self):
        config = Config("/nonexistent/path.yml")
        d = config.as_dict()
        d["server"]["hostname"] = "modified"
        assert config.get("server.hostname") != "modified"

    def test_reload(self):
        data = {"server": {"hostname": "original.com"}}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            yaml.dump(data, f)
            f.flush()
            config = Config(f.name)
            assert config.get("server.hostname") == "original.com"

            # Update file
            data["server"]["hostname"] = "updated.com"
            with open(f.name, "w") as fh:
                yaml.dump(data, fh)

            config.reload()
            assert config.get("server.hostname") == "updated.com"

        os.unlink(f.name)
