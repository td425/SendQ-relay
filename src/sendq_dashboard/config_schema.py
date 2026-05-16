"""Declarative form schema for the GUI config editor.

The SPA fetches this schema and renders an HTML form with labelled inputs
and dropdowns per field, instead of asking operators to edit raw YAML.

Field types:
  text       — single-line string
  password   — write-only, masked on read
  number     — integer
  bool       — checkbox
  select     — dropdown with ``options``
  multitext  — list of strings, one per line in a textarea
"""

from typing import Any

SCHEMA: list[dict[str, Any]] = [
    {
        "section": "server",
        "label": "Server",
        "fields": [
            {"key": "server.hostname", "label": "Hostname", "type": "text",
             "required": True, "help": "FQDN used in SMTP greetings."},
            {"key": "server.banner", "label": "SMTP Banner", "type": "text"},
            {"key": "server.max_message_size", "label": "Max message size (bytes)",
             "type": "number", "min": 1024},
            {"key": "server.trusted_networks", "label": "Trusted networks (CIDR)",
             "type": "multitext"},
        ],
    },
    {
        "section": "tls",
        "label": "TLS",
        "fields": [
            {"key": "tls.cert_file", "label": "Certificate file", "type": "text"},
            {"key": "tls.key_file", "label": "Private key file", "type": "text"},
            {"key": "tls.min_version", "label": "Minimum TLS version",
             "type": "select", "options": ["TLSv1.2", "TLSv1.3"]},
            {"key": "tls.ciphers", "label": "Cipher list", "type": "text"},
            {"key": "tls.prefer_server_ciphers", "label": "Prefer server ciphers",
             "type": "bool"},
        ],
    },
    {
        "section": "relay",
        "label": "Relay",
        "fields": [
            {"key": "relay.enabled", "label": "Enable relay", "type": "bool"},
            {"key": "relay.host", "label": "Relay host", "type": "text"},
            {"key": "relay.port", "label": "Relay port", "type": "number",
             "min": 1, "max": 65535},
            {"key": "relay.username", "label": "Auth username", "type": "text"},
            {"key": "relay.password", "label": "Auth password", "type": "password"},
            {"key": "relay.tls_mode", "label": "TLS mode", "type": "select",
             "options": ["none", "starttls", "implicit"]},
            {"key": "relay.tls_verify", "label": "Verify certificate", "type": "bool"},
            {"key": "relay.auth_method", "label": "Auth method", "type": "select",
             "options": ["auto", "plain", "login", "cram-md5"]},
        ],
    },
    {
        "section": "queue",
        "label": "Queue",
        "fields": [
            {"key": "queue.workers", "label": "Worker count", "type": "number",
             "min": 1, "max": 256},
            {"key": "queue.batch_size", "label": "Batch size", "type": "number"},
            {"key": "queue.max_retries", "label": "Max retries", "type": "number",
             "min": 1},
            {"key": "queue.max_age", "label": "Max age (seconds)", "type": "number"},
            {"key": "queue.bounce_notify", "label": "Notify on bounce", "type": "bool"},
        ],
    },
    {
        "section": "rate_limiting",
        "label": "Rate limiting",
        "fields": [
            {"key": "rate_limiting.enabled", "label": "Enable rate limiting",
             "type": "bool"},
            {"key": "rate_limiting.inbound.max_connections_per_ip",
             "label": "Max inbound connections per IP", "type": "number"},
            {"key": "rate_limiting.inbound.max_messages_per_ip_per_minute",
             "label": "Max inbound messages / IP / minute", "type": "number"},
            {"key": "rate_limiting.inbound.max_recipients_per_message",
             "label": "Max recipients per message", "type": "number"},
            {"key": "rate_limiting.outbound.max_messages_per_second",
             "label": "Max outbound msgs / second", "type": "number"},
        ],
    },
    {
        "section": "auth",
        "label": "SMTP auth",
        "fields": [
            {"key": "auth.backend", "label": "Backend", "type": "select",
             "options": ["internal", "ldap", "mysql", "pgsql"]},
            {"key": "auth.password_hash", "label": "Password hash", "type": "select",
             "options": ["argon2", "bcrypt"]},
            {"key": "auth.min_password_length", "label": "Min password length",
             "type": "number", "min": 8},
            {"key": "auth.require_auth_for_relay",
             "label": "Require auth for relay", "type": "bool"},
        ],
    },
    {
        "section": "dkim",
        "label": "DKIM",
        "fields": [
            {"key": "dkim.enabled", "label": "Enable DKIM signing", "type": "bool"},
            {"key": "dkim.selector", "label": "Default selector", "type": "text"},
            {"key": "dkim.key_dir", "label": "Key directory", "type": "text"},
            {"key": "dkim.algorithm", "label": "Algorithm", "type": "select",
             "options": ["rsa-sha256", "ed25519-sha256"]},
            {"key": "dkim.headers_to_sign", "label": "Headers to sign",
             "type": "multitext"},
        ],
    },
    {
        "section": "spf",
        "label": "SPF",
        "fields": [
            {"key": "spf.enabled", "label": "Enable SPF", "type": "bool"},
            {"key": "spf.hard_fail_action", "label": "Hard fail action",
             "type": "select", "options": ["reject", "tag", "accept"]},
            {"key": "spf.soft_fail_action", "label": "Soft fail action",
             "type": "select", "options": ["reject", "tag", "accept"]},
        ],
    },
    {
        "section": "dmarc",
        "label": "DMARC",
        "fields": [
            {"key": "dmarc.enabled", "label": "Enable DMARC", "type": "bool"},
            {"key": "dmarc.reject_action", "label": "Reject action",
             "type": "select", "options": ["reject", "quarantine", "tag"]},
            {"key": "dmarc.quarantine_action", "label": "Quarantine action",
             "type": "select", "options": ["quarantine", "tag", "accept"]},
            {"key": "dmarc.report_email", "label": "Report email", "type": "text"},
        ],
    },
    {
        "section": "logging",
        "label": "Logging",
        "fields": [
            {"key": "logging.level", "label": "Log level", "type": "select",
             "options": ["debug", "info", "warning", "error"]},
            {"key": "logging.format", "label": "Format", "type": "select",
             "options": ["json", "text"]},
            {"key": "logging.file", "label": "Log file", "type": "text"},
            {"key": "logging.max_size", "label": "Max log file size", "type": "text",
             "help": "Examples: 100M, 1G"},
            {"key": "logging.max_files", "label": "Max log files", "type": "number"},
        ],
    },
    {
        "section": "dashboard",
        "label": "Dashboard",
        "fields": [
            {"key": "dashboard.bind_address", "label": "Bind address", "type": "text"},
            {"key": "dashboard.port", "label": "Port", "type": "number",
             "min": 1, "max": 65535},
            {"key": "dashboard.session_timeout_minutes",
             "label": "Session idle timeout (minutes)", "type": "number", "min": 1},
            {"key": "dashboard.trusted_proxies",
             "label": "Trusted proxy CIDRs", "type": "multitext",
             "help": "Only requests from these proxies have X-Forwarded-* honored."},
            {"key": "dashboard.admin_ip_allowlist",
             "label": "Admin route IP allowlist (CIDR)", "type": "multitext",
             "help": "Empty = no restriction. Applies to admin-only API routes."},
            {"key": "dashboard.sqlite_path",
             "label": "SQLite DB path", "type": "text"},
            {"key": "dashboard.history_retention_days",
             "label": "Message history retention (days)", "type": "number", "min": 1},
            {"key": "dashboard.audit_retention_days",
             "label": "Audit log retention (days)", "type": "number", "min": 1},
        ],
    },
]
