"""Smoke tests for the dashboard Flask app — auth, CSRF, role gating."""

import os
import tempfile

import pytest
import yaml


@pytest.fixture
def app_client():
    sqlite_f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    sqlite_f.close()
    os.unlink(sqlite_f.name)
    users_f = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
    yaml.dump({"users": {}}, users_f)
    users_f.flush()
    config_f = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
    yaml.dump({
        "auth": {"backend": "internal", "password_hash": "argon2",
                 "min_password_length": 8},
        "portal": {"users_file": users_f.name},
        "server": {"hostname": "test.local"},
        "dashboard": {
            "bind_address": "127.0.0.1",
            "port": 0,
            "sqlite_path": sqlite_f.name,
            "session_secret": "x" * 64,
            "trusted_proxies": [],
            "admin_ip_allowlist": [],
        },
    }, config_f)
    config_f.flush()

    from sendq_mta.core.config import Config

    # Reset shared module state between tests.
    from sendq_dashboard import db
    db._TLS = type(db._TLS)()
    db._INITIALISED = False
    db._DB_PATH = None

    config = Config(config_f.name)

    from sendq_dashboard import app as app_module
    flask_app = app_module.init_app(config)
    flask_app.config.update(
        TESTING=True,
        SESSION_COOKIE_SECURE=False,  # allow the test client to send cookies
    )

    # Seed an admin so login routes work.
    app_module._portal.add_user("rootadmin", "very-long-test-pw", role="admin")
    # Bypass TOTP enrollment by pre-setting a totp_secret.
    app_module._portal._users["rootadmin"]["totp_secret"] = "JBSWY3DPEHPK3PXP"
    app_module._portal._users["rootadmin"]["totp_enrolled_at"] = "2026-01-01T00:00:00Z"
    app_module._portal._save()

    # Seed a non-admin too.
    app_module._portal.add_user("regular", "very-long-test-pw", role="user",
                                 assigned_domains=["example.com"])

    client = flask_app.test_client()

    yield client, app_module, config

    for p in (sqlite_f.name, users_f.name, config_f.name):
        try:
            os.unlink(p)
        except OSError:
            pass


def _login(client, username, password, totp=""):
    return client.post("/login", data={
        "username": username, "password": password, "totp": totp,
    }, follow_redirects=False)


def test_unauthenticated_api_returns_401(app_client):
    client, *_ = app_client
    r = client.get("/api/me")
    assert r.status_code == 401


def test_login_redirects_for_root(app_client):
    client, *_ = app_client
    r = client.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_missing_csrf_token_blocks_mutation(app_client):
    client, app_module, _ = app_client
    import pyotp
    code = pyotp.TOTP(app_module._portal._users["rootadmin"]["totp_secret"]).now()
    _login(client, "rootadmin", "very-long-test-pw", totp=code)
    r = client.post(
        "/api/portal-users",
        json={"username": "x", "password": "very-long-pw-1234"},
        # No X-CSRF-Token header.
    )
    assert r.status_code == 403


def test_admin_can_mutate_with_csrf(app_client):
    client, app_module, _ = app_client
    import pyotp
    code = pyotp.TOTP(app_module._portal._users["rootadmin"]["totp_secret"]).now()
    _login(client, "rootadmin", "very-long-test-pw", totp=code)
    me = client.get("/api/me").get_json()
    assert me["data"]["role"] == "admin"
    tok = client.get("/api/csrf-token").get_json()["token"]
    r = client.post(
        "/api/portal-users",
        json={"username": "new1", "password": "another-long-pw-1234", "role": "user"},
        headers={"X-CSRF-Token": tok},
    )
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_user_role_cannot_hit_admin_routes(app_client):
    client, _, _ = app_client
    _login(client, "regular", "very-long-test-pw")
    r = client.get("/api/portal-users")
    assert r.status_code == 403
    # but the user-allowed read works
    r2 = client.get("/api/me")
    assert r2.status_code == 200
    assert r2.get_json()["data"]["role"] == "user"


def test_cache_headers_on_api(app_client):
    client, _, _ = app_client
    _login(client, "regular", "very-long-test-pw")
    r = client.get("/api/me")
    assert "no-store" in r.headers.get("Cache-Control", "")


def test_login_form_round_trip_persists_session(app_client):
    """Posting valid credentials lands the user logged-in on the next request.

    Regression guard against the Secure-cookie-over-HTTP loop bug.
    """
    client, app_module, _ = app_client
    import pyotp
    code = pyotp.TOTP(app_module._portal._users["rootadmin"]["totp_secret"]).now()
    r = client.post("/login", data={
        "username": "rootadmin",
        "password": "very-long-test-pw",
        "totp": code,
    }, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].rstrip("/") in ("", "/", "http://localhost/")
    # Following the redirect should now show the dashboard (200), not bounce to /login.
    r2 = client.get("/", follow_redirects=False)
    assert r2.status_code == 200
    # And /api/me should return the logged-in admin.
    me = client.get("/api/me").get_json()
    assert me["status"] == "ok"
    assert me["data"]["username"] == "rootadmin"


def test_wrong_credentials_do_not_create_session(app_client):
    client, _, _ = app_client
    r = client.post("/login", data={
        "username": "rootadmin", "password": "wrong", "totp": "",
    }, follow_redirects=False)
    assert r.status_code == 401
    # Subsequent request is still unauthenticated.
    assert client.get("/api/me").status_code == 401


def test_short_password_rejected_on_portal_user_add(app_client):
    client, app_module, _ = app_client
    import pyotp
    code = pyotp.TOTP(app_module._portal._users["rootadmin"]["totp_secret"]).now()
    _login(client, "rootadmin", "very-long-test-pw", totp=code)
    tok = client.get("/api/csrf-token").get_json()["token"]
    r = client.post(
        "/api/portal-users",
        json={"username": "shortpw", "password": "abc", "role": "user"},
        headers={"X-CSRF-Token": tok},
    )
    assert r.status_code == 400


def test_message_scoped_to_assigned_domains(app_client):
    client, app_module, _ = app_client
    from sendq_dashboard import db

    # Insert two messages: one to example.com (allowed), one to other.com.
    db.execute(
        "INSERT INTO message_history "
        "(msg_id, sender, sender_domain, peer_ip, size_bytes, status, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("ok-msg", "a@example.com", "example.com", "1.2.3.4", 100,
         "delivered", "2026-05-16T10:00:00"),
    )
    db.execute(
        "INSERT INTO message_recipients VALUES (?, ?, ?)",
        ("ok-msg", "b@example.com", "example.com"),
    )
    db.execute(
        "INSERT INTO message_history "
        "(msg_id, sender, sender_domain, peer_ip, size_bytes, status, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("forbidden", "a@other.com", "other.com", "1.2.3.4", 100,
         "delivered", "2026-05-16T10:00:00"),
    )
    db.execute(
        "INSERT INTO message_recipients VALUES (?, ?, ?)",
        ("forbidden", "b@other.com", "other.com"),
    )

    _login(client, "regular", "very-long-test-pw")
    r = client.get("/api/messages")
    data = r.get_json()["data"]
    ids = {m["msg_id"] for m in data}
    assert "ok-msg" in ids
    assert "forbidden" not in ids

    # Direct access to forbidden message is 403.
    r2 = client.get("/api/messages/forbidden")
    assert r2.status_code == 403
