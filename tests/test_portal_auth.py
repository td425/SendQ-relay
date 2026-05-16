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


def test_admin_without_totp_logs_in_by_default(portal_setup):
    """TOTP is optional by default — admin logs in normally with just a password."""
    portal_setup.add_user("root", "right-pw-1234", role="admin")
    user = portal_setup.authenticate("root", "right-pw-1234", "", "127.0.0.1")
    assert user.role == "admin"
    assert user.totp_enrolled is False
    # last_login should have been recorded — i.e. it's a real login, not a stub.
    assert portal_setup._users["root"]["last_login"]


def test_admin_without_totp_blocked_when_required(portal_setup):
    """Flipping require_totp_for_admin gates the admin until they enroll."""
    portal_setup._require_totp_for_admin = True
    portal_setup.add_user("root2", "right-pw-1234", role="admin")
    user = portal_setup.authenticate("root2", "right-pw-1234", "", "127.0.0.1")
    # Stub user signalling the caller should drive enrollment.
    assert user.totp_enrolled is False
    # No last_login recorded — it isn't a real authenticated session yet.
    assert not portal_setup._users["root2"]["last_login"]


def test_enrolled_user_must_provide_totp_code(portal_setup):
    """If TOTP is enrolled, the code is always required (regardless of config)."""
    from sendq_dashboard.portal_auth import AuthError
    import pyotp

    portal_setup.add_user("e", "right-pw-1234", role="user")
    secret = portal_setup.begin_totp_enrollment("e")
    portal_setup.confirm_totp_enrollment("e", pyotp.TOTP(secret).now())

    # Right password, missing code → reject.
    with pytest.raises(AuthError, match="TOTP"):
        portal_setup.authenticate("e", "right-pw-1234", "", "127.0.0.1")
    # Right password + right code → success.
    user = portal_setup.authenticate(
        "e", "right-pw-1234", pyotp.TOTP(secret).now(), "127.0.0.1"
    )
    assert user.totp_enrolled is True


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


def test_login_succeeds_when_users_file_is_readonly(portal_setup):
    """A read-only users.yml must not break authentication.

    Regression: this used to raise IOError out of _save() inside
    authenticate(), bubbling up as an HTTP 500 from the dashboard login
    endpoint.
    """
    portal_setup.add_user("u", "right-pw-1234", role="user")
    # Make the underlying file read-only.
    os.chmod(portal_setup._path, 0o400)
    try:
        # Authentication must still succeed and return the user.
        user = portal_setup.authenticate("u", "right-pw-1234", "", "127.0.0.1")
        assert user.username == "u"
        # A failed attempt must also not crash, even though the lockout
        # bookkeeping won't persist.
        from sendq_dashboard.portal_auth import AuthError
        with pytest.raises(AuthError):
            portal_setup.authenticate("u", "wrong", "", "127.0.0.1")
    finally:
        os.chmod(portal_setup._path, 0o600)


def test_totp_pending_secret_is_stable_across_calls(portal_setup):
    """Reloading the enrollment page must NOT regenerate the secret.

    Otherwise the user's authenticator app stops matching the moment they
    refresh, with no visible explanation.
    """
    portal_setup.add_user("admin", "right-pw-1234", role="admin")
    s1 = portal_setup.begin_totp_enrollment("admin")
    s2 = portal_setup.begin_totp_enrollment("admin")
    assert s1 == s2
