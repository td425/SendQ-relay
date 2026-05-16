"""DKIM signing and verification for SendQ-MTA."""

import logging
import os
from email import message_from_bytes
from typing import Any

from sendq_mta.core.config import Config

logger = logging.getLogger("sendq-mta.dkim")

try:
    import dkim as _dkim

    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False


class DKIMSigner:
    """Signs outbound messages with DKIM."""

    def __init__(self, config: Config):
        self.config = config
        self._enabled = config.get("dkim.enabled", False)
        self._selector = config.get("dkim.selector", "sendq").encode()
        self._key_file = config.get("dkim.key_file", "")
        # Normalize signing domains to lowercase for case-insensitive matching
        self._signing_domains = {
            d.lower() for d in config.get("dkim.signing_domains", []) if d
        }
        self._headers_to_sign = [
            h.encode() for h in config.get("dkim.headers_to_sign", [])
        ]
        self._algorithm = config.get("dkim.algorithm", "rsa-sha256")
        self._private_key: bytes = b""

        if self._enabled:
            if not DKIM_AVAILABLE:
                logger.error(
                    "DKIM enabled but 'dkimpy' package not installed — "
                    "install with: pip install 'sendq-mta[dkim]'. "
                    "Signing will be skipped; mail will still send unsigned."
                )
                self._enabled = False
            elif not self._key_file:
                logger.error("DKIM enabled but dkim.key_file is not set — signing disabled")
                self._enabled = False
            elif not os.path.isfile(self._key_file):
                logger.error(
                    "DKIM key file not found: %s — signing disabled", self._key_file
                )
                self._enabled = False
            else:
                try:
                    with open(self._key_file, "rb") as f:
                        self._private_key = f.read()
                except OSError as exc:
                    # Most commonly a PermissionError when the key was generated
                    # as root (0600) but the service runs as an unprivileged user.
                    logger.error(
                        "Cannot read DKIM key %s: %s — signing disabled. "
                        "Ensure the service user can read the key file.",
                        self._key_file, exc,
                    )
                    self._enabled = False
                else:
                    logger.info(
                        "DKIM signing enabled (selector=%s, domains=%s)",
                        self._selector.decode(), sorted(self._signing_domains),
                    )

    def sign(self, message_data: bytes, sender_domain: str) -> bytes:
        """Sign a message with DKIM. Returns signed message data."""
        if not self._enabled:
            return message_data

        if sender_domain.lower() not in self._signing_domains:
            return message_data

        try:
            signature = _dkim.sign(
                message=message_data,
                selector=self._selector,
                domain=sender_domain.encode(),
                privkey=self._private_key,
                include_headers=self._headers_to_sign or None,
            )
            return signature + message_data
        except Exception:
            logger.exception("DKIM signing failed for domain %s", sender_domain)
            return message_data

    @property
    def enabled(self) -> bool:
        return self._enabled


class DKIMVerifier:
    """Verifies DKIM signatures on inbound messages."""

    def __init__(self, config: Config):
        self.config = config

    def verify(self, message_data: bytes) -> dict[str, Any]:
        """Verify DKIM signature. Returns result dict."""
        if not DKIM_AVAILABLE:
            return {"status": "skipped", "reason": "dkim package not installed"}

        try:
            result = _dkim.verify(message_data)
            return {
                "status": "pass" if result else "fail",
                "verified": result,
            }
        except Exception as exc:
            return {"status": "temperror", "reason": str(exc)}
