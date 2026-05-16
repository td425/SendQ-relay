"""Tests for the portal user store (dashboard login accounts)."""

import os
import tempfile

import pytest
import yaml

from sendq_mta.core.config import Config


@pytest.fixture
def portal_setup():
    users_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
    yaml.dump({"users": {}}, users_file)
    users_file.flush()

    config_data = {
        "auth": {
            "backend": "internal",
            "password_hash": "argon2",
            "min_password_length": 8,
        },
        "portal": {"users_file": users_file.name},
        "server": {"hostname": "test.local"},
    }
    config_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
    yaml.dump(config_data, config_file)
    config_file.flush()

    config = Config(config_file.name)

    from sendq_dashboard.portal_auth import PortalAuth
    pa = PortalAuth(config)
    yield pa
    for p in (users_file.name, config_file.name):
        try:
            os.unlink(p)
        except OSError:
            pass


def test_add_and_list(portal_setup):
    pa = portal_setup
    pa.add_user("alice", "secret-pw-1234", role="user", assigned_domains=["example.com"])
    users = pa.list_users()
    assert len(users) == 1
    assert users[0]["username"] == "alice"
    assert users[0]["role"] == "user"
    assert users[0]["assigned_domains"] == ["example.com"]
    assert users[0]["totp_enrolled"] is False


def test_no_admin_initially(portal_setup):
    assert portal_setup.has_admin() is False
    portal_setup.add_user("root", "secret-pw-1234", role="admin")
    assert portal_setup.has_admin() is True


def test_wrong_password_raises(portal_setup):
    from sendq_dashboard.portal_auth import AuthError

    portal_setup.add_user("bob", "right-pw-1234", role="user")
    with pytest.raises(AuthError):
        portal_setup.authenticate("bob", "wrong", "", "127.0.0.1")


def test_admin_without_totp_returns_enrollment_user(portal_setup):
    """Admin login is allowed once with a valid password to trigger TOTP enrollment."""
    portal_setup.add_user("root", "right-pw-1234", role="admin")
    user = portal_setup.authenticate("root", "right-pw-1234", "", "127.0.0.1")
    assert user.role == "admin"
    assert user.totp_enrolled is False


def test_user_role_logs_in_without_totp(portal_setup):
    portal_setup.add_user("u1", "right-pw-1234", role="user")
    user = portal_setup.authenticate("u1", "right-pw-1234", "", "127.0.0.1")
    assert user.username == "u1"


def test_account_lockout_after_threshold(portal_setup):
    from sendq_dashboard.portal_auth import AuthError

    portal_setup.add_user("victim", "right-pw-1234", role="user")
    # First 4 failures don't lock — only the 5th triggers a lock window.
    for _ in range(5):
        with pytest.raises(AuthError):
            portal_setup.authenticate("victim", "wrong", "", "10.0.0.1")
    with pytest.raises(AuthError, match="locked"):
        portal_setup.authenticate("victim", "right-pw-1234", "", "10.0.0.1")


def test_assigned_domains_update(portal_setup):
    portal_setup.add_user("u", "right-pw-1234", role="user")
    portal_setup.update_user("u", assigned_domains=["a.com", "b.com"])
    u = portal_setup.get("u")
    assert sorted(u.assigned_domains) == ["a.com", "b.com"]


def test_short_password_rejected(portal_setup):
    with pytest.raises(ValueError, match="at least"):
        portal_setup.add_user("x", "short", role="user")


def test_empty_password_rejected(portal_setup):
    with pytest.raises(ValueError):
        portal_setup.add_user("x", "", role="user")


def test_set_password_rejects_short(portal_setup):
    portal_setup.add_user("p", "right-pw-1234", role="user")
    with pytest.raises(ValueError):
        portal_setup.set_password("p", "abc")


def test_totp_pending_secret_is_stable_across_calls(portal_setup):
    """Reloading the enrollment page must NOT regenerate the secret.

    Otherwise the user's authenticator app stops matching the moment they
    refresh, with no visible explanation.
    """
    portal_setup.add_user("admin", "right-pw-1234", role="admin")
    s1 = portal_setup.begin_totp_enrollment("admin")
    s2 = portal_setup.begin_totp_enrollment("admin")
    assert s1 == s2
