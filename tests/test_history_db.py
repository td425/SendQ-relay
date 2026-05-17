"""Tests for the dashboard SQLite history layer."""

import os
import tempfile

import pytest


@pytest.fixture
def fresh_db():
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    os.unlink(f.name)

    from sendq_dashboard import db
    # Reset the module-level globals from a previous test.
    db._TLS = type(db._TLS)()
    db._INITIALISED = False
    db._DB_PATH = None
    db.init(f.name)

    yield db, f.name

    try:
        os.unlink(f.name)
    except OSError:
        pass
    for sidecar in (f.name + "-wal", f.name + "-shm"):
        try:
            os.unlink(sidecar)
        except OSError:
            pass


def test_migrations_applied(fresh_db):
    db, _ = fresh_db
    rows = db.fetch("SELECT version FROM schema_migrations ORDER BY version")
    assert [r["version"] for r in rows] == [1]
    tables = {r["name"] for r in db.fetch(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    assert {"message_history", "message_recipients",
            "delivery_attempts", "audit_log"} <= tables


def test_migration_not_reapplied(fresh_db):
    db, path = fresh_db
    # Re-init should be a no-op for migrations.
    db._INITIALISED = False
    db.init(path)
    rows = db.fetch("SELECT version FROM schema_migrations")
    assert len(rows) == 1


def test_wal_mode_enabled(fresh_db):
    db, _ = fresh_db
    row = db.fetch_one("PRAGMA journal_mode")
    assert row[0] == "wal"


def test_insert_and_query_message(fresh_db):
    db, _ = fresh_db
    with db.with_tx() as conn:
        conn.execute(
            "INSERT INTO message_history "
            "(msg_id, sender, sender_domain, peer_ip, size_bytes, status, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("m1", "a@x.com", "x.com", "1.2.3.4", 100, "queued", "2026-05-16T10:00:00"),
        )
        conn.execute(
            "INSERT INTO message_recipients VALUES (?, ?, ?)",
            ("m1", "b@y.com", "y.com"),
        )
    row = db.fetch_one("SELECT * FROM message_history WHERE msg_id = ?", ("m1",))
    assert row["sender_domain"] == "x.com"
    assert row["status"] == "queued"
    rcpt = db.fetch("SELECT * FROM message_recipients WHERE msg_id = ?", ("m1",))
    assert rcpt[0]["recipient_domain"] == "y.com"


def test_cascade_delete(fresh_db):
    db, _ = fresh_db
    with db.with_tx() as conn:
        conn.execute(
            "INSERT INTO message_history "
            "(msg_id, sender, sender_domain, peer_ip, size_bytes, status, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("m2", "a@x.com", "x.com", "1.2.3.4", 100, "delivered", "2026-05-16T10:00:00"),
        )
        conn.execute(
            "INSERT INTO message_recipients VALUES (?, ?, ?)",
            ("m2", "b@y.com", "y.com"),
        )
        conn.execute(
            "INSERT INTO delivery_attempts (msg_id, attempt_at, outcome) VALUES (?, ?, ?)",
            ("m2", "2026-05-16T10:00:05", "success"),
        )
    with db.with_tx() as conn:
        conn.execute("DELETE FROM message_history WHERE msg_id = ?", ("m2",))
    assert db.fetch_one("SELECT 1 FROM message_recipients WHERE msg_id = ?", ("m2",)) is None
    assert db.fetch_one("SELECT 1 FROM delivery_attempts WHERE msg_id = ?", ("m2",)) is None


def test_audit_log_insert(fresh_db):
    db, _ = fresh_db
    db.execute(
        "INSERT INTO audit_log(ts, actor, actor_ip, action, target) "
        "VALUES (?, ?, ?, ?, ?)",
        ("2026-05-16T11:00:00.000", "alice", "10.0.0.1", "login", ""),
    )
    row = db.fetch_one("SELECT * FROM audit_log WHERE actor = ?", ("alice",))
    assert row["action"] == "login"
