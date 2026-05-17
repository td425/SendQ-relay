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


def test_totp_enroll_renders_without_pillow(app_client, monkeypatch):
    """Regression: TOTP enrollment 500'd when Pillow wasn't installed.

    Simulate Pillow's absence by forcing the PNG path to fail; the page
    must still render via the SVG fallback (or text-only fallback).
    """
    client, app_module, _ = app_client

    # Flip the config so admin login forces enrollment for this test.
    app_module._portal._require_totp_for_admin = True
    app_module._config.set("dashboard.require_totp_for_admin", True)

    # Create a fresh admin with NO TOTP enrolled, so login redirects to enroll.
    app_module._portal.add_user("freshadmin", "very-long-test-pw", role="admin")

    # Force qrcode.make() to fail like a missing-Pillow install would, so
    # the route exercises the fallback path.
    import qrcode
    real_make = qrcode.make

    def fake_make(uri, **kw):
        if "image_factory" in kw:
            return real_make(uri, **kw)  # let SVG path succeed
        raise ImportError("simulated: PIL not installed")

    monkeypatch.setattr(qrcode, "make", fake_make)

    r = client.post("/login", data={
        "username": "freshadmin", "password": "very-long-test-pw", "totp": "",
    }, follow_redirects=False)
    assert r.status_code == 302
    assert "/login/totp-enroll" in r.headers["Location"]

    r2 = client.get("/login/totp-enroll")
    assert r2.status_code == 200
    # Page must still show the manual secret so the operator can complete
    # enrollment manually.
    assert b"Manual secret" in r2.data


def test_totp_enroll_renders_with_no_qr_when_all_backends_fail(app_client, monkeypatch):
    """If both PNG and SVG rendering die, the page must still render."""
    client, app_module, _ = app_client
    app_module._portal._require_totp_for_admin = True
    app_module._config.set("dashboard.require_totp_for_admin", True)
    app_module._portal.add_user("freshadmin2", "very-long-test-pw", role="admin")

    import qrcode
    monkeypatch.setattr(
        qrcode, "make",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("forced")),
    )

    r = client.post("/login", data={
        "username": "freshadmin2", "password": "very-long-test-pw", "totp": "",
    }, follow_redirects=False)
    assert r.status_code == 302

    r2 = client.get("/login/totp-enroll")
    assert r2.status_code == 200
    assert b"Manual secret" in r2.data
    # No <img> tag for the QR (the template hides it when totp_qr is empty).
    assert b'alt="TOTP QR"' not in r2.data


def test_mta_history_visible_to_dashboard_api(app_client):
    """End-to-end of the cross-process write/read pipeline.

    The MTA process writes through ``sendq_mta.core.history``; the
    dashboard reads through its own connection on the same file. This
    test simulates the MTA side by calling history.record_* directly,
    then hits the dashboard's /api/messages and confirms the row
    appears. Regression for the bug where 50 sent messages produced
    zero rows in the dashboard.
    """
    client, app_module, config = app_client
    import pyotp
    code = pyotp.TOTP(app_module._portal._users["rootadmin"]["totp_secret"]).now()
    _login(client, "rootadmin", "very-long-test-pw", totp=code)

    # Point the MTA-side history module at the SAME sqlite file the
    # dashboard opened. Reset state first so init() actually runs.
    from sendq_mta.core import history
    history._conn = None
    history._path = None
    sqlite_path = config.get("dashboard.sqlite_path")
    history.init(sqlite_path)

    history.record_enqueue("mta-roundtrip-1", "alice@example.com",
                           ["bob@gmail.com"], "10.0.0.1", 2048)
    history.record_attempt("mta-roundtrip-1", "gmail-smtp-in.l.google.com",
                           250, "OK", "success")
    history.record_terminal("mta-roundtrip-1", "delivered", None)

    r = client.get("/api/messages")
    assert r.status_code == 200
    msgs = r.get_json()["data"]
    found = [m for m in msgs if m["msg_id"] == "mta-roundtrip-1"]
    assert found, f"MTA-written message not visible to dashboard: got {msgs}"
    assert found[0]["status"] == "delivered"
    assert found[0]["sender"] == "alice@example.com"
    assert "bob@gmail.com" in found[0]["recipients"]

    # Drill into the per-message timeline.
    r2 = client.get("/api/messages/mta-roundtrip-1")
    assert r2.status_code == 200
    detail = r2.get_json()["data"]
    assert len(detail["attempts"]) == 1
    assert detail["attempts"][0]["outcome"] == "success"

    history._conn = None
    history._path = None


def test_api_status_includes_status_ok_wrapper(app_client):
    """The SPA's Dashboard tile checks ``r.status === 'ok'`` before rendering.

    Regression: the route once returned the data dict directly without the
    wrapper, so the Dashboard tile showed "Status unavailable" forever.
    """
    client, _, _ = app_client
    _login(client, "regular", "very-long-test-pw")
    payload = client.get("/api/status").get_json()
    assert payload["status"] == "ok"
    assert "queue" in payload and "server" in payload


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
