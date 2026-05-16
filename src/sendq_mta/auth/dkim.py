"""DKIM signing and verification for SendQ-MTA."""

import base64
import logging
import os
import re
from typing import Any

from sendq_mta.core.config import Config

logger = logging.getLogger("sendq-mta.dkim")

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")


def generate_domain_key(
    domain: str,
    selector: str,
    bits: int = 2048,
    output_dir: str = "/etc/sendq-mta/dkim",
    chown_to: str | None = "sendq",
) -> dict[str, str]:
    """Generate an RSA DKIM key pair for ``domain`` and write key + DNS record.

    Returns a dict with the file paths and the DNS TXT record. Used by both
    the ``generate-dkim`` CLI command and the dashboard's
    ``POST /api/dkim/keys`` endpoint, so the generation logic stays in one
    place.

    Raises:
        ValueError: on invalid domain/selector input.
        RuntimeError: if the ``cryptography`` package isn't installed.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as exc:
        raise RuntimeError(
            "'cryptography' package required to generate DKIM keys. "
            "Install with: pip install cryptography"
        ) from exc

    if not _HOSTNAME_RE.match(domain) or ".." in domain:
        raise ValueError(f"Invalid domain name: {domain!r}")
    if not _HOSTNAME_RE.match(selector) or ".." in selector:
        raise ValueError(f"Invalid selector: {selector!r}")

    os.makedirs(output_dir, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(public_der).decode()

    key_path = os.path.join(output_dir, f"{domain}.{selector}.private.pem")
    dns_path = os.path.join(output_dir, f"{domain}.{selector}.dns.txt")
    dns_record = f'{selector}._domainkey.{domain} IN TXT "v=DKIM1; k=rsa; p={pub_b64}"'

    with open(key_path, "wb") as f:
        f.write(private_pem)
    os.chmod(key_path, 0o640)
    with open(dns_path, "w") as f:
        f.write(dns_record + "\n")

    if chown_to and os.geteuid() == 0:
        try:
            import grp
            import pwd
            uid = pwd.getpwnam(chown_to).pw_uid
            gid = grp.getgrnam(chown_to).gr_gid
            os.chown(key_path, uid, gid)
            os.chown(dns_path, uid, gid)
        except (KeyError, PermissionError) as exc:
            logger.warning(
                "Could not chown %s to %s: %s — service may be unable to read.",
                key_path, chown_to, exc,
            )

    return {
        "key_path": key_path,
        "dns_path": dns_path,
        "dns_record": dns_record,
    }

try:
    import dkim as _dkim

    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False


class DKIMSigner:
    """Signs outbound messages with DKIM, one key per signing domain.

    Per-domain keys are discovered automatically from ``dkim.key_dir`` using
    the naming convention ``<domain>.<selector>.private.pem`` (the same
    layout produced by the ``generate-dkim`` CLI). Explicit overrides may
    be supplied via ``dkim.keys`` as a ``{domain: path}`` map. The legacy
    ``dkim.key_file`` setting is honored as a fallback when only one
    signing domain is configured.
    """

    def __init__(self, config: Config):
        self.config = config
        self._enabled = config.get("dkim.enabled", False)
        self._selector = config.get("dkim.selector", "sendq").encode()
        self._signing_domains = {
            d.lower() for d in config.get("dkim.signing_domains", []) if d
        }
        self._headers_to_sign = [
            h.encode() for h in config.get("dkim.headers_to_sign", [])
        ]
        self._algorithm = config.get("dkim.algorithm", "rsa-sha256")
        self._keys: dict[str, bytes] = {}

        if not self._enabled:
            return

        if not DKIM_AVAILABLE:
            logger.error(
                "DKIM enabled but 'dkimpy' package not installed — "
                "install with: pip install dkimpy. "
                "Signing will be skipped; mail will still send unsigned."
            )
            self._enabled = False
            return

        if not self._signing_domains:
            logger.error("DKIM enabled but dkim.signing_domains is empty — signing disabled")
            self._enabled = False
            return

        key_dir = config.get("dkim.key_dir", "/etc/sendq-mta/dkim")
        explicit_keys = {
            d.lower(): path
            for d, path in (config.get("dkim.keys", {}) or {}).items()
        }
        legacy_key_file = config.get("dkim.key_file", "")
        selector_str = self._selector.decode()

        for domain in self._signing_domains:
            key_path = self._resolve_key_path(
                domain, selector_str, key_dir, explicit_keys, legacy_key_file
            )
            if key_path is None:
                logger.error(
                    "No DKIM key for %s — expected %s/%s.%s.private.pem "
                    "(or set dkim.keys.%s). Mail from this domain will be UNSIGNED.",
                    domain, key_dir, domain, selector_str, domain,
                )
                continue
            try:
                with open(key_path, "rb") as f:
                    self._keys[domain] = f.read()
            except OSError as exc:
                logger.error(
                    "Cannot read DKIM key %s for %s: %s — domain will be UNSIGNED. "
                    "Ensure the service user can read the file.",
                    key_path, domain, exc,
                )

        if self._keys:
            logger.info(
                "DKIM signing enabled (selector=%s, signed_domains=%s)",
                selector_str, sorted(self._keys.keys()),
            )
        else:
            logger.error(
                "DKIM enabled but no usable keys loaded — signing disabled. "
                "Run `sendq-mta generate-dkim -d <domain>` for each domain "
                "in signing_domains."
            )
            self._enabled = False

    def _resolve_key_path(
        self,
        domain: str,
        selector: str,
        key_dir: str,
        explicit_keys: dict[str, str],
        legacy_key_file: str,
    ) -> str | None:
        # 1. Explicit dkim.keys override
        path = explicit_keys.get(domain)
        if path and os.path.isfile(path):
            return path
        # 2. Convention: <key_dir>/<domain>.<selector>.private.pem
        candidate = os.path.join(key_dir, f"{domain}.{selector}.private.pem")
        if os.path.isfile(candidate):
            return candidate
        # 3. Legacy single-key back-compat: only when there's exactly one
        #    signing domain and the operator hasn't migrated to key_dir yet.
        if (
            len(self._signing_domains) == 1
            and legacy_key_file
            and os.path.isfile(legacy_key_file)
        ):
            return legacy_key_file
        return None

    def sign(self, message_data: bytes, sender_domain: str) -> bytes:
        """Sign a message with DKIM. Returns signed message data unchanged
        if the signer is disabled or no key is loaded for ``sender_domain``."""
        if not self._enabled:
            return message_data

        domain = sender_domain.lower()
        privkey = self._keys.get(domain)
        if privkey is None:
            return message_data

        try:
            signature = _dkim.sign(
                message=message_data,
                selector=self._selector,
                domain=domain.encode(),
                privkey=privkey,
                include_headers=self._headers_to_sign or None,
            )
            return signature + message_data
        except Exception:
            logger.exception("DKIM signing failed for domain %s", sender_domain)
            return message_data

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def signed_domains(self) -> set[str]:
        return set(self._keys.keys())


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
