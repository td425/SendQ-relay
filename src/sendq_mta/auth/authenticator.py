"""User authentication and management for SendQ-MTA."""

import hashlib
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

import yaml

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

try:
    import bcrypt as _bcrypt

    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

from sendq_mta.core.config import Config

logger = logging.getLogger("sendq-mta.auth")


def _hash_sha512(password: str, salt: str | None = None) -> str:
    """SHA-512 with salt fallback."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha512((salt + password).encode()).hexdigest()
    return f"$sha512${salt}${hashed}"


def _verify_sha512(password: str, stored: str) -> bool:
    parts = stored.split("$")
    if len(parts) != 4 or parts[1] != "sha512":
        return False
    salt = parts[2]
    expected = parts[3]
    hashed = hashlib.sha512((salt + password).encode()).hexdigest()
    return secrets.compare_digest(hashed, expected)


class Authenticator:
    """Handles user authentication and user CRUD operations."""

    def __init__(self, config: Config):
        self.config = config
        self._backend = config.get("auth.backend", "internal")
        self._hash_algo = config.get("auth.password_hash", "argon2")
        self._users_file = config.get("auth.users_file", "/etc/sendq-mta/users.yml")
        self._min_password_length = config.get("auth.min_password_length", 12)
        self._users: dict[str, dict[str, Any]] = {}
        self._users_file_mtime: float = 0.0

        if self._backend == "internal":
            self._load_users()

        # Initialize argon2 hasher
        if self._hash_algo == "argon2" and ARGON2_AVAILABLE:
            self._argon2 = PasswordHasher()
        else:
            self._argon2 = None

    def _load_users(self) -> None:
        """Load users from the users YAML file."""
        if not os.path.isfile(self._users_file):
            logger.info("Users file not found at %s; starting empty", self._users_file)
            self._users = {}
            return

        with open(self._users_file, "r") as f:
            data = yaml.safe_load(f) or {}

        self._users = data.get("users", {})
        try:
            self._users_file_mtime = os.path.getmtime(self._users_file)
        except OSError:
            self._users_file_mtime = 0.0
        logger.info("Loaded %d users from %s", len(self._users), self._users_file)

    def _save_users(self) -> None:
        """Persist users to the YAML file."""
        Path(self._users_file).parent.mkdir(parents=True, exist_ok=True)
        data = {"users": self._users}
        with open(self._users_file, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        # Restrict permissions on users file
        os.chmod(self._users_file, 0o600)
        try:
            self._users_file_mtime = os.path.getmtime(self._users_file)
        except OSError:
            self._users_file_mtime = 0.0
        logger.info("Saved %d users to %s", len(self._users), self._users_file)

    def hash_password(self, password: str) -> str:
        """Hash a password using the configured algorithm."""
        if self._hash_algo == "argon2" and self._argon2:
            return self._argon2.hash(password)
        elif self._hash_algo == "bcrypt" and BCRYPT_AVAILABLE:
            salt = _bcrypt.gensalt(rounds=12)
            return _bcrypt.hashpw(password.encode(), salt).decode()
        else:
            return _hash_sha512(password)

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        try:
            if hashed.startswith("$argon2"):
                if self._argon2:
                    try:
                        return self._argon2.verify(hashed, password)
                    except VerifyMismatchError:
                        return False
                return False
            elif hashed.startswith("$2b$") or hashed.startswith("$2a$"):
                if BCRYPT_AVAILABLE:
                    return _bcrypt.checkpw(password.encode(), hashed.encode())
                return False
            elif hashed.startswith("$sha512$"):
                return _verify_sha512(password, hashed)
            else:
                return False
        except Exception:
            logger.exception("Password verification error")
            return False

    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate a user. Returns True on success."""
        if self._backend == "internal":
            return self._auth_internal(username, password)
        else:
            logger.error("Auth backend '%s' not yet implemented", self._backend)
            return False

    def _check_reload(self) -> None:
        """Reload users file if it has been modified on disk."""
        try:
            current_mtime = os.path.getmtime(self._users_file)
            if current_mtime != self._users_file_mtime:
                logger.info("Users file changed on disk, reloading")
                self._load_users()
        except OSError:
            pass

    def _auth_internal(self, username: str, password: str) -> bool:
        """Authenticate against the internal users file."""
        self._check_reload()
        user = self._users.get(username)
        if not user:
            return False
        if not user.get("enabled", True):
            logger.warning("Login attempt for disabled user: %s", username)
            return False
        stored_hash = user.get("password_hash", "")
        return self.verify_password(password, stored_hash)

    # --- User CRUD Operations ---

    def list_users(self) -> list[dict[str, Any]]:
        """List all users (without password hashes)."""
        result = []
        for username, data in self._users.items():
            result.append({
                "username": username,
                "email": data.get("email", ""),
                "display_name": data.get("display_name", ""),
                "enabled": data.get("enabled", True),
                "created_at": data.get("created_at", ""),
                "last_login": data.get("last_login", ""),
                "quota_mb": data.get("quota_mb", 0),
                "send_limit_per_hour": data.get("send_limit_per_hour", 0),
            })
        return result

    def get_user(self, username: str) -> dict[str, Any] | None:
        """Get a single user's details (without password hash)."""
        user = self._users.get(username)
        if not user:
            return None
        return {
            "username": username,
            "email": user.get("email", ""),
            "display_name": user.get("display_name", ""),
            "enabled": user.get("enabled", True),
            "created_at": user.get("created_at", ""),
            "last_login": user.get("last_login", ""),
            "quota_mb": user.get("quota_mb", 0),
            "send_limit_per_hour": user.get("send_limit_per_hour", 0),
        }

    def add_user(
        self,
        username: str,
        password: str,
        email: str = "",
        display_name: str = "",
        quota_mb: int = 0,
        send_limit_per_hour: int = 0,
    ) -> bool:
        """Add a new user. Returns False if user already exists."""
        if username in self._users:
            logger.warning("User '%s' already exists", username)
            return False

        if len(password) < self._min_password_length:
            raise ValueError(
                f"Password must be at least {self._min_password_length} characters"
            )

        self._users[username] = {
            "password_hash": self.hash_password(password),
            "email": email or f"{username}@{self.config.get('server.hostname', 'localhost')}",
            "display_name": display_name or username,
            "enabled": True,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "last_login": "",
            "quota_mb": quota_mb,
            "send_limit_per_hour": send_limit_per_hour,
        }
        self._save_users()
        logger.info("Added user '%s'", username)
        return True

    def edit_user(self, username: str, **kwargs: Any) -> bool:
        """Edit user attributes. Does not change password (use change_password)."""
        if username not in self._users:
            return False

        allowed_fields = {
            "email", "display_name", "enabled", "quota_mb", "send_limit_per_hour"
        }
        for key, value in kwargs.items():
            if key in allowed_fields:
                self._users[username][key] = value

        self._save_users()
        logger.info("Updated user '%s'", username)
        return True

    def delete_user(self, username: str) -> bool:
        """Delete a user."""
        if username not in self._users:
            return False
        del self._users[username]
        self._save_users()
        logger.info("Deleted user '%s'", username)
        return True

    def change_password(self, username: str, new_password: str) -> bool:
        """Change a user's password."""
        if username not in self._users:
            return False
        if len(new_password) < self._min_password_length:
            raise ValueError(
                f"Password must be at least {self._min_password_length} characters"
            )
        self._users[username]["password_hash"] = self.hash_password(new_password)
        self._save_users()
        logger.info("Password changed for user '%s'", username)
        return True

    def enable_user(self, username: str) -> bool:
        return self.edit_user(username, enabled=True)

    def disable_user(self, username: str) -> bool:
        return self.edit_user(username, enabled=False)

    def record_login(self, username: str) -> None:
        """Record last login timestamp."""
        if username in self._users:
            self._users[username]["last_login"] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            )
            self._save_users()

    def user_exists(self, username: str) -> bool:
        return username in self._users

    @property
    def user_count(self) -> int:
        return len(self._users)
