"""Tests for the authentication module."""

import os
import tempfile

import pytest
import yaml

from sendq_mta.core.config import Config
from sendq_mta.auth.authenticator import Authenticator


@pytest.fixture
def auth_setup():
    """Create a temporary config and users file for testing."""
    users_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    )
    yaml.dump({"users": {}}, users_file)
    users_file.flush()

    config_data = {
        "auth": {
            "backend": "internal",
            "password_hash": "sha512",  # Use sha512 to avoid argon2 dependency in tests
            "users_file": users_file.name,
            "min_password_length": 8,
        },
        "server": {"hostname": "test.local"},
    }
    config_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    )
    yaml.dump(config_data, config_file)
    config_file.flush()

    config = Config(config_file.name)
    auth = Authenticator(config)

    yield auth, config

    os.unlink(users_file.name)
    os.unlink(config_file.name)


class TestAuthenticator:
    def test_add_user(self, auth_setup):
        auth, config = auth_setup
        result = auth.add_user("testuser", "securepassword123")
        assert result is True
        assert auth.user_exists("testuser")

    def test_add_duplicate_user(self, auth_setup):
        auth, config = auth_setup
        auth.add_user("testuser", "securepassword123")
        result = auth.add_user("testuser", "anotherpassword1")
        assert result is False

    def test_short_password_rejected(self, auth_setup):
        auth, config = auth_setup
        with pytest.raises(ValueError, match="at least 8 characters"):
            auth.add_user("testuser", "short")

    def test_authenticate_success(self, auth_setup):
        auth, config = auth_setup
        auth.add_user("testuser", "securepassword123")
        assert auth.authenticate("testuser", "securepassword123") is True

    def test_authenticate_wrong_password(self, auth_setup):
        auth, config = auth_setup
        auth.add_user("testuser", "securepassword123")
        assert auth.authenticate("testuser", "wrongpassword!!") is False

    def test_authenticate_nonexistent_user(self, auth_setup):
        auth, config = auth_setup
        assert auth.authenticate("ghost", "password1234") is False

    def test_change_password(self, auth_setup):
        auth, config = auth_setup
        auth.add_user("testuser", "oldpassword1234")
        auth.change_password("testuser", "newpassword1234")
        assert auth.authenticate("testuser", "newpassword1234") is True
        assert auth.authenticate("testuser", "oldpassword1234") is False

    def test_delete_user(self, auth_setup):
        auth, config = auth_setup
        auth.add_user("testuser", "securepassword123")
        assert auth.delete_user("testuser") is True
        assert not auth.user_exists("testuser")

    def test_delete_nonexistent_user(self, auth_setup):
        auth, config = auth_setup
        assert auth.delete_user("ghost") is False

    def test_edit_user(self, auth_setup):
        auth, config = auth_setup
        auth.add_user("testuser", "securepassword123")
        auth.edit_user("testuser", email="new@test.local", display_name="Test User")
        user = auth.get_user("testuser")
        assert user["email"] == "new@test.local"
        assert user["display_name"] == "Test User"

    def test_disable_enable_user(self, auth_setup):
        auth, config = auth_setup
        auth.add_user("testuser", "securepassword123")
        auth.disable_user("testuser")
        assert auth.authenticate("testuser", "securepassword123") is False
        auth.enable_user("testuser")
        assert auth.authenticate("testuser", "securepassword123") is True

    def test_list_users(self, auth_setup):
        auth, config = auth_setup
        auth.add_user("user1", "password1234aaa")
        auth.add_user("user2", "password5678bbb")
        users = auth.list_users()
        usernames = [u["username"] for u in users]
        assert "user1" in usernames
        assert "user2" in usernames
        # Ensure password hash is not exposed
        for u in users:
            assert "password_hash" not in u

    def test_user_count(self, auth_setup):
        auth, config = auth_setup
        assert auth.user_count == 0
        auth.add_user("user1", "password1234aaa")
        assert auth.user_count == 1
        auth.add_user("user2", "password5678bbb")
        assert auth.user_count == 2
