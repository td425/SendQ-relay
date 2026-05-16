"""Portal user store — YAML-backed, separate pool from SMTP-AUTH users.

Portal users log into the dashboard only. They have no SMTP send rights.
File default: ``/etc/sendq-mta/portal-users.yml`` (mode 0600).
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

import yaml

from sendq_mta.auth.authenticator import Authenticator
from sendq_mta.core.config import Config, atomic_write_yaml

logger = logging.getLogger("sendq-dashboard.portal_auth")

# Per-account exponential lockout schedule (failed_attempts -> seconds locked).
# Anything beyond the last threshold uses the last value (24h).
_LOCKOUT_SCHEDULE = [
    (5, 60),
    (10, 5 * 60),
    (20, 60 * 60),
    (30, 24 * 60 * 60),
]


@dataclass
class PortalUser:
    username: str
    role: str  # "admin" | "user"
    enabled: bool
    totp_enrolled: bool
    assigned_domains: list[str]


class AuthError(Exception):
    """Raised when authentication fails. Message is safe to surface to the UI."""


class PortalAuth:
    """YAML-backed portal user manager."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._path = config.get("portal.users_file", "/etc/sendq-mta/portal-users.yml")
        self._users: dict[str, dict[str, Any]] = {}
        self._hasher = Authenticator(config)
        self._min_password_length = int(config.get("auth.min_password_length", 12))
        self._ip_failures: dict[str, list[float]] = {}
        self._load()

    def _check_password(self, password: str) -> None:
        if len(password) < self._min_password_length:
            raise ValueError(
                f"Password must be at least {self._min_password_length} characters"
            )

    # ── persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        if not os.path.isfile(self._path):
            self._users = {}
            return
        with open(self._path) as f:
            data = yaml.safe_load(f) or {}
        self._users = data.get("users", {}) or {}

    def _save(self) -> None:
        atomic_write_yaml(self._path, {"users": self._users}, mode=0o600)

    def _try_save(self) -> None:
        """Persist users file, swallowing OSError.

        Used on hot paths (login success / failure bookkeeping) where the
        user's auth outcome shouldn't be discarded just because the
        process couldn't update last_login or failed_attempts. The actual
        problem (typically a file-permissions misconfiguration) is logged
        so the operator can fix it.
        """
        try:
            self._save()
        except OSError:
            logger.warning(
                "Could not persist portal-users.yml at %s. "
                "Check that the dashboard user can write the file.",
                self._path,
                exc_info=True,
            )

    # ── public read API ──────────────────────────────────────────────────

    def list_users(self) -> list[dict[str, Any]]:
        out = []
        for username, u in self._users.items():
            out.append({
                "username": username,
                "role": u.get("role", "user"),
                "enabled": u.get("enabled", True),
                "totp_enrolled": bool(u.get("totp_secret")),
                "assigned_domains": list(u.get("assigned_domains", []) or []),
                "created_at": u.get("created_at", ""),
                "last_login": u.get("last_login", ""),
                "locked": self._is_locked(u),
            })
        return out

    def get(self, username: str) -> PortalUser | None:
        u = self._users.get(username)
        if not u:
            return None
        return PortalUser(
            username=username,
            role=u.get("role", "user"),
            enabled=u.get("enabled", True),
            totp_enrolled=bool(u.get("totp_secret")),
            assigned_domains=list(u.get("assigned_domains", []) or []),
        )

    def has_admin(self) -> bool:
        return any(u.get("role") == "admin" for u in self._users.values())

    # ── CRUD ────────────────────────────────────────────────────────────

    def add_user(
        self,
        username: str,
        password: str,
        role: str = "user",
        assigned_domains: list[str] | None = None,
    ) -> None:
        if role not in ("admin", "user"):
            raise ValueError("role must be 'admin' or 'user'")
        if username in self._users:
            raise ValueError(f"Portal user '{username}' already exists")
        if not username.isascii() or not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
            raise ValueError("Username must be alphanumeric (plus _ - .)")
        self._check_password(password)
        self._users[username] = {
            "password_hash": self._hasher.hash_password(password),
            "role": role,
            "enabled": True,
            "totp_secret": "",
            "totp_enrolled_at": "",
            "assigned_domains": list(assigned_domains or []),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "last_login": "",
            "failed_attempts": 0,
            "lockout_until": 0,
        }
        self._save()

    def update_user(
        self,
        username: str,
        *,
        role: str | None = None,
        enabled: bool | None = None,
        assigned_domains: list[str] | None = None,
    ) -> None:
        u = self._users.get(username)
        if not u:
            raise ValueError(f"Portal user '{username}' not found")
        if role is not None:
            if role not in ("admin", "user"):
                raise ValueError("role must be 'admin' or 'user'")
            u["role"] = role
        if enabled is not None:
            u["enabled"] = bool(enabled)
        if assigned_domains is not None:
            u["assigned_domains"] = list(assigned_domains)
        self._save()

    def delete_user(self, username: str) -> None:
        if username not in self._users:
            raise ValueError(f"Portal user '{username}' not found")
        del self._users[username]
        self._save()

    def set_password(self, username: str, password: str) -> None:
        u = self._users.get(username)
        if not u:
            raise ValueError(f"Portal user '{username}' not found")
        self._check_password(password)
        u["password_hash"] = self._hasher.hash_password(password)
        u["failed_attempts"] = 0
        u["lockout_until"] = 0
        self._save()

    # ── TOTP ─────────────────────────────────────────────────────────────

    def begin_totp_enrollment(self, username: str) -> str:
        """Return the pending TOTP secret for ``username``, creating one if absent.

        Reusing any existing pending secret matters: if the operator scans the
        QR code, then reloads the page before confirming, regenerating the
        secret would silently invalidate the code from their authenticator.
        """
        import pyotp  # local import — only needed when TOTP used

        u = self._users.get(username)
        if not u:
            raise ValueError(f"Portal user '{username}' not found")
        existing = u.get("_pending_totp")
        if existing:
            return existing
        secret = pyotp.random_base32()
        u["_pending_totp"] = secret
        self._save()
        return secret

    def confirm_totp_enrollment(self, username: str, code: str) -> bool:
        import pyotp

        u = self._users.get(username)
        if not u or not u.get("_pending_totp"):
            return False
        if not pyotp.TOTP(u["_pending_totp"]).verify(code, valid_window=1):
            return False
        u["totp_secret"] = u.pop("_pending_totp")
        u["totp_enrolled_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save()
        return True

    def disable_totp(self, username: str) -> None:
        u = self._users.get(username)
        if not u:
            return
        u["totp_secret"] = ""
        u["totp_enrolled_at"] = ""
        u.pop("_pending_totp", None)
        self._save()

    # ── authentication ──────────────────────────────────────────────────

    def authenticate(
        self, username: str, password: str, totp_code: str, peer_ip: str
    ) -> PortalUser:
        """Verify credentials. Raises ``AuthError`` on any failure.

        Failure messages are intentionally generic — they don't reveal
        whether the username exists.
        """
        self._check_ip_lockout(peer_ip)
        u = self._users.get(username)

        # Always run the hash check (constant-time response timing).
        stored_hash = (u or {}).get("password_hash") or self._hasher.hash_password(
            secrets.token_urlsafe(8)
        )
        ok = self._hasher.verify_password(password, stored_hash)

        if not u or not u.get("enabled", True):
            self._record_ip_failure(peer_ip)
            raise AuthError("Invalid credentials")

        if self._is_locked(u):
            self._record_ip_failure(peer_ip)
            raise AuthError("Account is temporarily locked. Try again later.")

        if not ok:
            self._record_failure(username, peer_ip)
            raise AuthError("Invalid credentials")

        # Password OK — check TOTP.
        if u.get("role") == "admin" and not u.get("totp_secret"):
            # Admin without TOTP must enroll on first login.
            return PortalUser(
                username=username,
                role="admin",
                enabled=True,
                totp_enrolled=False,
                assigned_domains=[],
            )

        if u.get("totp_secret"):
            import pyotp
            if not totp_code or not pyotp.TOTP(u["totp_secret"]).verify(
                totp_code, valid_window=1
            ):
                self._record_failure(username, peer_ip)
                raise AuthError("Invalid TOTP code")

        # Success — clear failure counters.
        u["failed_attempts"] = 0
        u["lockout_until"] = 0
        u["last_login"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # Persistence failure here must NOT discard a valid authentication —
        # the user is who they say they are even if we can't update their
        # last_login field. The operator gets a warning to fix permissions.
        self._try_save()
        self._ip_failures.pop(peer_ip, None)
        return self.get(username)  # type: ignore[return-value]

    # ── lockout bookkeeping ──────────────────────────────────────────────

    def _is_locked(self, u: dict[str, Any]) -> bool:
        return float(u.get("lockout_until", 0) or 0) > time.time()

    def _record_failure(self, username: str, peer_ip: str) -> None:
        u = self._users.get(username)
        if u is not None:
            attempts = int(u.get("failed_attempts", 0)) + 1
            u["failed_attempts"] = attempts
            lock = self._lock_for(attempts)
            if lock:
                u["lockout_until"] = time.time() + lock
                logger.warning(
                    "Portal user '%s' locked for %ds after %d failed attempts (peer=%s)",
                    username, lock, attempts, peer_ip,
                )
            self._try_save()
        self._record_ip_failure(peer_ip)

    def _lock_for(self, attempts: int) -> int:
        for threshold, seconds in _LOCKOUT_SCHEDULE:
            if attempts == threshold:
                return seconds
        # Past the last threshold: re-apply the longest interval every time.
        if attempts > _LOCKOUT_SCHEDULE[-1][0]:
            return _LOCKOUT_SCHEDULE[-1][1]
        return 0

    # Per-IP: rolling 5-minute window; block beyond 30 failures.
    def _check_ip_lockout(self, peer_ip: str) -> None:
        cutoff = time.time() - 300
        attempts = [t for t in self._ip_failures.get(peer_ip, []) if t > cutoff]
        self._ip_failures[peer_ip] = attempts
        if len(attempts) >= 30:
            raise AuthError("Too many failed attempts from this address. Try again later.")

    def _record_ip_failure(self, peer_ip: str) -> None:
        self._ip_failures.setdefault(peer_ip, []).append(time.time())
