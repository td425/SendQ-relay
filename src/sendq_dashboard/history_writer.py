"""Background writer that mirrors queue events into the SQLite history DB.

Installed as event observers on ``sendq_mta.core.events`` at dashboard
startup. All writes are best-effort — failures log a warning but never
raise (the MTA delivery path must not block on the dashboard DB).
"""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sendq_mta.core import events as mta_events

from sendq_dashboard import db

logger = logging.getLogger("sendq-dashboard.history")

# Background writer: callers enqueue (callable, args, kwargs); the worker
# thread drains them so SMTP code paths never wait on SQLite.
_write_queue: queue.Queue[tuple] = queue.Queue(maxsize=10_000)
_worker_started = False
_worker_lock = threading.Lock()
_retention_days = 30
_audit_retention_days = 365


def _ensure_worker() -> None:
    global _worker_started
    if _worker_started:
        return
    with _worker_lock:
        if _worker_started:
            return
        t = threading.Thread(target=_worker, name="dashboard-history-writer", daemon=True)
        t.start()
        sweeper = threading.Thread(target=_sweeper, name="dashboard-history-sweeper", daemon=True)
        sweeper.start()
        _worker_started = True


def _worker() -> None:
    while True:
        try:
            fn, args, kwargs = _write_queue.get()
        except Exception:
            continue
        try:
            fn(*args, **kwargs)
        except sqlite3.Error:
            logger.warning("history writer: SQL error", exc_info=True)
        except Exception:
            logger.warning("history writer: unexpected error", exc_info=True)


def _enqueue_write(fn: Any, *args: Any, **kwargs: Any) -> None:
    try:
        _write_queue.put_nowait((fn, args, kwargs))
    except queue.Full:
        logger.warning("history writer queue full; dropping event")


# ── event handlers ────────────────────────────────────────────────────


def _record_enqueue_sync(
    msg_id: str,
    sender: str,
    recipients: list[str],
    peer_ip: str,
    size_bytes: int,
    received_at_iso: str,
) -> None:
    sender_domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    with db.with_tx() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO message_history "
            "(msg_id, sender, sender_domain, peer_ip, size_bytes, status, received_at) "
            "VALUES (?, ?, ?, ?, ?, 'queued', ?)",
            (msg_id, sender, sender_domain, peer_ip, size_bytes, received_at_iso),
        )
        conn.execute(
            "DELETE FROM message_recipients WHERE msg_id = ?", (msg_id,)
        )
        for rcpt in recipients:
            rcpt_domain = rcpt.rsplit("@", 1)[-1].lower() if "@" in rcpt else ""
            conn.execute(
                "INSERT OR IGNORE INTO message_recipients "
                "(msg_id, recipient, recipient_domain) VALUES (?, ?, ?)",
                (msg_id, rcpt, rcpt_domain),
            )


def _record_attempt_sync(
    msg_id: str,
    attempt_at_iso: str,
    remote_host: str | None,
    smtp_code: int | None,
    smtp_resp: str | None,
    outcome: str,
) -> None:
    with db.with_tx() as conn:
        conn.execute(
            "INSERT INTO delivery_attempts "
            "(msg_id, attempt_at, remote_host, smtp_code, smtp_resp, outcome) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (msg_id, attempt_at_iso, remote_host, smtp_code, smtp_resp, outcome),
        )
        new_status = "delivering" if outcome == "success" else (
            "deferred" if outcome == "deferred" else "failed"
        )
        conn.execute(
            "UPDATE message_history "
            "SET last_attempt_at = ?, status = ?, last_error = COALESCE(?, last_error) "
            "WHERE msg_id = ?",
            (
                attempt_at_iso,
                new_status,
                smtp_resp if outcome != "success" else None,
                msg_id,
            ),
        )


def _record_terminal_sync(
    msg_id: str,
    status: str,
    finalized_at_iso: str,
    last_error: str | None,
) -> None:
    with db.with_tx() as conn:
        conn.execute(
            "UPDATE message_history "
            "SET status = ?, finalized_at = ?, last_error = COALESCE(?, last_error) "
            "WHERE msg_id = ?",
            (status, finalized_at_iso, last_error, msg_id),
        )


def on_message_enqueued(
    msg_id: str,
    sender: str,
    recipients: list[str],
    peer_ip: str,
    size_bytes: int,
    received_at_iso: str,
) -> None:
    _enqueue_write(
        _record_enqueue_sync,
        msg_id, sender, recipients, peer_ip, size_bytes, received_at_iso,
    )


def on_delivery_attempt(
    msg_id: str,
    attempt_at_iso: str,
    remote_host: str | None,
    smtp_code: int | None,
    smtp_resp: str | None,
    outcome: str,
) -> None:
    _enqueue_write(
        _record_attempt_sync,
        msg_id, attempt_at_iso, remote_host, smtp_code, smtp_resp, outcome,
    )


def on_message_terminal(
    msg_id: str,
    status: str,
    finalized_at_iso: str,
    last_error: str | None = None,
) -> None:
    _enqueue_write(
        _record_terminal_sync,
        msg_id, status, finalized_at_iso, last_error,
    )


# ── audit log (used by the dashboard's own routes) ───────────────────


def record_audit(actor: str, actor_ip: str, action: str, target: str = "",
                 detail: str | None = None) -> None:
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    try:
        db.execute(
            "INSERT INTO audit_log(ts, actor, actor_ip, action, target, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, actor, actor_ip, action, target, detail),
        )
    except sqlite3.Error:
        logger.warning("audit_log insert failed", exc_info=True)


# ── retention sweeper ────────────────────────────────────────────────


def _sweeper() -> None:
    while True:
        time.sleep(3600)
        try:
            history_cutoff = (
                datetime.now(timezone.utc) - timedelta(days=_retention_days)
            ).isoformat(timespec="seconds")
            audit_cutoff = (
                datetime.now(timezone.utc) - timedelta(days=_audit_retention_days)
            ).isoformat(timespec="seconds")
            with db.with_tx() as conn:
                conn.execute(
                    "DELETE FROM message_history WHERE received_at < ?",
                    (history_cutoff,),
                )
                conn.execute(
                    "DELETE FROM audit_log WHERE ts < ?", (audit_cutoff,)
                )
        except sqlite3.Error:
            logger.warning("retention sweep failed", exc_info=True)


# ── install hooks ────────────────────────────────────────────────────


def install(history_retention_days: int = 30, audit_retention_days: int = 365) -> None:
    """Register handlers with ``sendq_mta.core.events`` and start the worker.

    Idempotent — calling twice has no extra effect.
    """
    global _retention_days, _audit_retention_days
    _retention_days = max(1, int(history_retention_days))
    _audit_retention_days = max(1, int(audit_retention_days))

    mta_events.on_message_enqueued = on_message_enqueued
    mta_events.on_delivery_attempt = on_delivery_attempt
    mta_events.on_message_terminal = on_message_terminal
    _ensure_worker()
    logger.info(
        "History writer installed (retention: messages=%dd, audit=%dd)",
        _retention_days, _audit_retention_days,
    )
