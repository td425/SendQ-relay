"""Configuration loader and validator for SendQ-MTA."""

import os
import sys
import copy
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("sendq-mta.config")

DEFAULT_CONFIG_PATHS = [
    "/etc/sendq-mta/sendq-mta.yml",
    "/etc/sendq-mta/sendq-mta.yaml",
    os.path.expanduser("~/.config/sendq-mta/sendq-mta.yml"),
    "./config/sendq-mta.yml",
]

DEFAULTS = {
    "server": {
        "hostname": "localhost",
        "banner": "SendQ-MTA Enterprise ESMTP",
        "pid_file": "/var/run/sendq-mta/sendq-mta.pid",
        "data_dir": "/var/lib/sendq-mta",
        "run_as_user": "sendq",
        "run_as_group": "sendq",
        "max_message_size": 52428800,
    },
    "listeners": [
        {
            "name": "smtp",
            "address": "0.0.0.0",
            "port": 25,
            "protocol": "smtp",
            "tls_mode": "starttls",
            "max_connections": 1000,
            "timeout": 300,
            "require_auth": False,
        }
    ],
    "tls": {
        "cert_file": "",
        "key_file": "",
        "ca_file": "",
        "min_version": "TLSv1.2",
        "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20",
        "prefer_server_ciphers": True,
    },
    "relay": {
        "enabled": False,
        "host": "",
        "port": 587,
        "username": "",
        "password": "",
        "auth_method": "auto",
        "tls_mode": "starttls",
        "tls_verify": True,
        "connection_pool_size": 20,
        "max_connections": 50,
        "failover": [],
    },
    "queue": {
        "directory": "/var/spool/sendq-mta/queue",
        "deferred_directory": "/var/spool/sendq-mta/deferred",
        "failed_directory": "/var/spool/sendq-mta/failed",
        "max_queue_size": 1000000,
        "workers": 16,
        "batch_size": 100,
        "retry_intervals": [60, 300, 900, 1800, 3600, 7200, 14400, 28800, 43200],
        "max_retries": 30,
        "max_age": 432000,
        "bounce_notify": True,
        "flush_interval": 30,
    },
    "delivery": {
        "dns_timeout": 10,
        "dns_servers": [],
        "connect_timeout": 30,
        "read_timeout": 120,
        "write_timeout": 60,
        "ehlo_timeout": 30,
        "connection_pool": {
            "enabled": True,
            "size_per_domain": 10,
            "max_total": 500,
            "idle_timeout": 300,
            "max_lifetime": 1800,
        },
    },
    "rate_limiting": {
        "enabled": True,
        "inbound": {
            "max_connections_per_ip": 50,
            "max_messages_per_ip_per_minute": 100,
            "max_recipients_per_message": 500,
            "max_errors_per_ip": 10,
            "ban_duration": 3600,
        },
        "outbound": {
            "max_messages_per_domain_per_minute": 200,
            "max_messages_per_second": 500,
            "max_concurrent_deliveries": 100,
        },
        "per_user": {
            "max_messages_per_hour": 500,
            "max_recipients_per_hour": 2000,
        },
    },
    "auth": {
        "backend": "internal",
        "password_hash": "argon2",
        "users_file": "/etc/sendq-mta/users.yml",
        "min_password_length": 12,
        "require_auth_for_relay": True,
    },
    "domains": {
        "local_domains": [],
        "relay_domains": [],
        "blocked_domains": [],
        "alias_file": "/etc/sendq-mta/aliases.yml",
    },
    "dkim": {
        "enabled": False,
        "selector": "sendq",
        "key_file": "",
        "signing_domains": [],
        "headers_to_sign": [
            "From", "To", "Subject", "Date", "Message-ID",
            "MIME-Version", "Content-Type",
        ],
        "algorithm": "rsa-sha256",
        "key_bits": 2048,
    },
    "spf": {
        "enabled": True,
        "hard_fail_action": "reject",
        "soft_fail_action": "tag",
        "neutral_action": "accept",
    },
    "dmarc": {
        "enabled": True,
        "reject_action": "reject",
        "quarantine_action": "quarantine",
        "report_email": "",
    },
    "logging": {
        "level": "info",
        "file": "/var/log/sendq-mta/sendq-mta.log",
        "max_size": "100M",
        "max_files": 30,
        "format": "json",
        "log_mail_body": False,
        "syslog": {"enabled": False, "facility": "mail"},
    },
    "metrics": {
        "enabled": True,
        "prometheus": {"enabled": True, "address": "127.0.0.1", "port": 9225},
        "stats_interval": 60,
    },
    "management_api": {
        "enabled": True,
        "socket": "/var/run/sendq-mta/mgmt.sock",
        "http": {
            "enabled": False,
            "address": "127.0.0.1",
            "port": 8225,
            "api_key": "",
        },
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base dict."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"Config validation failed: {'; '.join(errors)}")


class Config:
    """Manages loading, merging, validating, and accessing SendQ-MTA config."""

    def __init__(self, config_path: str | None = None):
        self._path: str | None = None
        self._data: dict[str, Any] = {}
        self._raw: dict[str, Any] = {}
        self.load(config_path)

    def load(self, config_path: str | None = None) -> None:
        """Load configuration from file, merging with defaults."""
        if config_path:
            paths = [config_path]
        else:
            paths = DEFAULT_CONFIG_PATHS

        for path in paths:
            expanded = os.path.expandvars(os.path.expanduser(path))
            if os.path.isfile(expanded):
                self._path = expanded
                break

        if self._path is None:
            logger.warning("No config file found; using defaults")
            self._data = copy.deepcopy(DEFAULTS)
            self._raw = {}
            return

        logger.info("Loading config from %s", self._path)
        with open(self._path, "r") as fh:
            raw = yaml.safe_load(fh) or {}

        self._raw = raw
        self._data = _deep_merge(DEFAULTS, raw)

    def reload(self) -> None:
        """Reload configuration from the same file."""
        if self._path:
            self.load(self._path)
        else:
            logger.warning("No config file path set; cannot reload")

    def validate(self) -> list[str]:
        """Validate configuration and return list of errors (empty = valid)."""
        errors: list[str] = []

        # Server
        if not self._data.get("server", {}).get("hostname"):
            errors.append("server.hostname is required")

        # Listeners
        listeners = self._data.get("listeners", [])
        if not listeners:
            errors.append("At least one listener must be configured")
        for i, listener in enumerate(listeners):
            if not listener.get("address"):
                errors.append(f"listeners[{i}].address is required")
            port = listener.get("port", 0)
            if not (1 <= port <= 65535):
                errors.append(f"listeners[{i}].port must be 1-65535")
            if listener.get("tls_mode") not in ("none", "starttls", "implicit"):
                errors.append(
                    f"listeners[{i}].tls_mode must be none|starttls|implicit"
                )

        # TLS — required if any listener uses TLS
        tls_needed = any(
            l.get("tls_mode") in ("starttls", "implicit") for l in listeners
        )
        tls_cfg = self._data.get("tls", {})
        if tls_needed:
            if not tls_cfg.get("cert_file"):
                errors.append("tls.cert_file required when TLS listeners exist")
            elif not os.path.isfile(tls_cfg["cert_file"]):
                errors.append(f"tls.cert_file not found: {tls_cfg['cert_file']}")
            if not tls_cfg.get("key_file"):
                errors.append("tls.key_file required when TLS listeners exist")
            elif not os.path.isfile(tls_cfg["key_file"]):
                errors.append(f"tls.key_file not found: {tls_cfg['key_file']}")

        # Relay
        relay = self._data.get("relay", {})
        if relay.get("enabled"):
            if not relay.get("host"):
                errors.append("relay.host is required when relay is enabled")
            if not (1 <= relay.get("port", 0) <= 65535):
                errors.append("relay.port must be 1-65535")

        # Queue
        queue = self._data.get("queue", {})
        if queue.get("workers", 0) < 1:
            errors.append("queue.workers must be >= 1")
        if queue.get("max_retries", 0) < 1:
            errors.append("queue.max_retries must be >= 1")

        # Auth
        auth = self._data.get("auth", {})
        valid_backends = ("internal", "ldap", "mysql", "pgsql")
        if auth.get("backend") not in valid_backends:
            errors.append(f"auth.backend must be one of {valid_backends}")

        # DKIM
        dkim = self._data.get("dkim", {})
        if dkim.get("enabled"):
            if not dkim.get("key_file"):
                errors.append("dkim.key_file required when DKIM is enabled")
            if not dkim.get("signing_domains"):
                errors.append("dkim.signing_domains required when DKIM is enabled")

        return errors

    def validate_or_exit(self) -> None:
        """Validate config; print errors and exit if invalid."""
        errors = self.validate()
        if errors:
            print("Configuration errors:", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            sys.exit(1)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Get a config value using dotted notation (e.g. 'relay.host')."""
        keys = dotted_key.split(".")
        node = self._data
        for key in keys:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                return default
        return node

    def set(self, dotted_key: str, value: Any) -> None:
        """Set a config value using dotted notation."""
        keys = dotted_key.split(".")
        node = self._data
        for key in keys[:-1]:
            if key not in node or not isinstance(node[key], dict):
                node[key] = {}
            node = node[key]
        node[keys[-1]] = value

    def save(self, path: str | None = None) -> None:
        """Save current configuration to YAML file."""
        target = path or self._path
        if not target:
            raise RuntimeError("No config file path set")
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w") as fh:
            yaml.dump(self._data, fh, default_flow_style=False, sort_keys=False)
        logger.info("Config saved to %s", target)

    @property
    def path(self) -> str | None:
        return self._path

    @property
    def data(self) -> dict[str, Any]:
        return self._data

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)

    def __repr__(self) -> str:
        return f"<Config path={self._path}>"
