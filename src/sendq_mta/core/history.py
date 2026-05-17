"""Message history writer — invoked from the MTA daemon's queue path.

Writes to the dashboard's SQLite file directly (no IPC, no event-bus, no
cross-process hooks) so messages flow to the dashboard regardless of
which process started first or whether the dashboard is running at all.

Both this module and ``sendq_dashboard.db`` use ``CREATE TABLE IF NOT
EXISTS`` for the shared tables, so whichever process touches the file
first wins and the other no-ops.

Failures here are logged but never raise — the SMTP delivery path must
not stall on bookkeeping.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("sendq-mta.history")

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None
_path: str | None = None
_init_attempted = False

_SCHEMA = """
CREATE TABLE IF NOT EXISTS message_history (
  msg_id          TEXT PRIMARY KEY,
  sender          TEXT NOT NULL,
  sender_domain   TEXT NOT NULL,
  peer_ip         TEXT NOT NULL,
  size_bytes      INTEGER NOT NULL,
  status          TEXT NOT NULL,
  received_at     TEXT NOT NULL,
  last_attempt_at TEXT,
  finalized_at    TEXT,
  last_error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_msg_sender_domain ON message_history(sender_domain, received_at);
CREATE INDEX IF NOT EXISTS idx_msg_status        ON message_history(status, received_at);
CREATE INDEX IF NOT EXISTS idx_msg_received      ON message_history(received_at);

CREATE TABLE IF NOT EXISTS message_recipients (
  msg_id           TEXT NOT NULL REFERENCES message_history(msg_id) ON DELETE CASCADE,
  recipient        TEXT NOT NULL,
  recipient_domain TEXT NOT NULL,
  PRIMARY KEY (msg_id, recipient)
);
CREATE INDEX IF NOT EXISTS idx_rcpt_domain ON message_recipients(recipient_domain);

CREATE TABLE IF NOT EXISTS delivery_attempts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  msg_id      TEXT NOT NULL REFERENCES message_history(msg_id) ON DELETE CASCADE,
  attempt_at  TEXT NOT NULL,
  remote_host TEXT,
  smtp_code   INTEGER,
  smtp_resp   TEXT,
  outcome     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_att_msg ON delivery_attempts(msg_id, attempt_at);
"""


def init(path: str | None) -> None:
    """Open (or create) the SQLite history DB. Safe to call repeatedly.

    Silently no-ops on any error — message delivery must keep working
    even if we can't open the file (permissions, missing parent dir, etc.).
    """
    global _conn, _path, _init_attempted
    if not path:
        return
    with _lock:
        if _conn is not None and _path == path:
            return
        _init_attempted = True
        try:
            Path(os.path.dirname(path) or ".").mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                path, timeout=30.0, isolation_level=None, check_same_thread=False
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript(_SCHEMA)
            _conn = conn
            _path = path
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            logger.info("Message history DB ready at %s", path)
        except Exception:
            logger.warning(
                "Could not initialise history DB at %s — messages won't "
                "appear on the dashboard. Check that the directory is "
                "writable by this process.",
                path, exc_info=True,
            )


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def record_enqueue(
    msg_id: str,
    sender: str,
    recipients: list[str],
    peer_ip: str,
    size_bytes: int,
) -> None:
    if _conn is None:
        return
    sender_domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    ts = _iso_now()
    try:
        with _lock:
            _conn.execute("BEGIN IMMEDIATE")
            _conn.execute(
                "INSERT OR REPLACE INTO message_history "
                "(msg_id, sender, sender_domain, peer_ip, size_bytes, status, received_at) "
                "VALUES (?, ?, ?, ?, ?, 'queued', ?)",
                (msg_id, sender, sender_domain, peer_ip, size_bytes, ts),
            )
            _conn.execute(
                "DELETE FROM message_recipients WHERE msg_id = ?", (msg_id,)
            )
            for rcpt in recipients:
                rcpt_domain = rcpt.rsplit("@", 1)[-1].lower() if "@" in rcpt else ""
                _conn.execute(
                    "INSERT OR IGNORE INTO message_recipients "
                    "(msg_id, recipient, recipient_domain) VALUES (?, ?, ?)",
                    (msg_id, rcpt, rcpt_domain),
                )
            _conn.execute("COMMIT")
    except sqlite3.Error:
        _safe_rollback()
        logger.warning("history record_enqueue failed for %s", msg_id, exc_info=True)


def record_attempt(
    msg_id: str,
    remote_host: str | None,
    smtp_code: int | None,
    smtp_resp: str | None,
    outcome: str,
) -> None:
    if _conn is None:
        return
    ts = _iso_now()
    new_status = (
        "delivered" if outcome == "success"
        else "deferred" if outcome == "deferred"
        else "failed"
    )
    try:
        with _lock:
            _conn.execute("BEGIN IMMEDIATE")
            _conn.execute(
                "INSERT INTO delivery_attempts "
                "(msg_id, attempt_at, remote_host, smtp_code, smtp_resp, outcome) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (msg_id, ts, remote_host, smtp_code, smtp_resp, outcome),
            )
            _conn.execute(
                "UPDATE message_history "
                "SET last_attempt_at = ?, status = ?, "
                "    last_error = COALESCE(?, last_error) "
                "WHERE msg_id = ?",
                (ts, new_status,
                 smtp_resp if outcome != "success" else None, msg_id),
            )
            _conn.execute("COMMIT")
    except sqlite3.Error:
        _safe_rollback()
        logger.warning("history record_attempt failed for %s", msg_id, exc_info=True)


def record_terminal(msg_id: str, status: str, last_error: str | None = None) -> None:
    if _conn is None:
        return
    ts = _iso_now()
    try:
        with _lock:
            _conn.execute("BEGIN IMMEDIATE")
            _conn.execute(
                "UPDATE message_history "
                "SET status = ?, finalized_at = ?, "
                "    last_error = COALESCE(?, last_error) "
                "WHERE msg_id = ?",
                (status, ts, last_error, msg_id),
            )
            _conn.execute("COMMIT")
    except sqlite3.Error:
        _safe_rollback()
        logger.warning("history record_terminal failed for %s", msg_id, exc_info=True)


def _safe_rollback() -> None:
    if _conn is None:
        return
    try:
        _conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass
