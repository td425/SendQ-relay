"""The MTA writes message events into the same SQLite file the dashboard reads.

This is the contract that was broken before: cross-process event hooks
silently swallowed every message because the MTA process never imported
the dashboard's hook installer. Now the MTA writes SQLite directly; the
dashboard reads the same file.
"""

import os
import sqlite3
import tempfile

import pytest


@pytest.fixture
def history_path():
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    os.unlink(f.name)

    from sendq_mta.core import history
    # Reset module state between tests.
    history._conn = None
    history._path = None
    history._init_attempted = False
    history.init(f.name)

    yield f.name, history

    if history._conn is not None:
        history._conn.close()
        history._conn = None
    for sidecar in (f.name, f.name + "-wal", f.name + "-shm"):
        try:
            os.unlink(sidecar)
        except OSError:
            pass


def test_enqueue_writes_row_visible_to_independent_reader(history_path):
    """A second sqlite3 connection (i.e. a different process) sees the
    row immediately — WAL + CREATE-IF-NOT-EXISTS handles cross-process."""
    path, history = history_path
    history.record_enqueue("m1", "a@x.com", ["b@y.com", "c@z.com"], "1.2.3.4", 1500)

    # Open a NEW connection — simulating the dashboard reading the file.
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM message_history WHERE msg_id = ?", ("m1",)
    ).fetchone()
    assert row is not None
    assert row["sender"] == "a@x.com"
    assert row["sender_domain"] == "x.com"
    assert row["status"] == "queued"
    assert row["size_bytes"] == 1500
    rcpts = {r["recipient"] for r in conn.execute(
        "SELECT recipient FROM message_recipients WHERE msg_id = ?", ("m1",)
    )}
    assert rcpts == {"b@y.com", "c@z.com"}


def test_attempt_then_terminal_transitions_status(history_path):
    path, history = history_path
    history.record_enqueue("m2", "a@x.com", ["b@y.com"], "1.2.3.4", 500)
    history.record_attempt("m2", "mx.y.com", 250, "OK", "success")
    history.record_terminal("m2", "delivered", None)

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT status, finalized_at FROM message_history WHERE msg_id = ?", ("m2",)
    ).fetchone()
    assert row["status"] == "delivered"
    assert row["finalized_at"] is not None

    attempts = list(conn.execute(
        "SELECT * FROM delivery_attempts WHERE msg_id = ? ORDER BY id", ("m2",)
    ))
    assert len(attempts) == 1
    assert attempts[0]["outcome"] == "success"
    assert attempts[0]["smtp_code"] == 250


def test_init_silent_when_path_unset():
    """Empty path is a deliberate disable — no exception, no DB file."""
    from sendq_mta.core import history
    history._conn = None
    history._path = None
    history.init("")
    history.init(None)
    # All record_* are no-ops.
    history.record_enqueue("x", "a@b", [], "", 0)
    history.record_attempt("x", None, None, None, "failed")
    history.record_terminal("x", "failed", None)


def test_init_silent_when_directory_unwritable(tmp_path):
    """Wrong path / bad permissions: silent no-op, MTA delivery keeps working."""
    from sendq_mta.core import history
    history._conn = None
    history._path = None
    # /proc is always read-only.
    history.init("/proc/nonexistent/dashboard.db")
    assert history._conn is None
    # Still no exceptions on writes.
    history.record_enqueue("x", "a@b", [], "", 0)
