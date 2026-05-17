"""Audit-log writer for the dashboard process.

Message history (enqueue / attempt / terminal) is written by the MTA
daemon directly into the shared SQLite file — see
``sendq_mta.core.history``. This module only handles ``audit_log``
entries, which are dashboard-process actions.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

from sendq_dashboard import db

logger = logging.getLogger("sendq-dashboard.history")

_sweeper_started = False
_sweeper_lock = threading.Lock()
_history_retention_days = 30
_audit_retention_days = 365


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


def install(history_retention_days: int = 30, audit_retention_days: int = 365) -> None:
    """Start the background retention sweeper. Idempotent."""
    global _sweeper_started, _history_retention_days, _audit_retention_days
    _history_retention_days = max(1, int(history_retention_days))
    _audit_retention_days = max(1, int(audit_retention_days))
    with _sweeper_lock:
        if _sweeper_started:
            return
        t = threading.Thread(target=_sweeper, name="dashboard-retention-sweeper", daemon=True)
        t.start()
        _sweeper_started = True
    logger.info(
        "Retention sweeper running (messages=%dd, audit=%dd)",
        _history_retention_days, _audit_retention_days,
    )


def _sweeper() -> None:
    while True:
        time.sleep(3600)
        try:
            history_cutoff = (
                datetime.now(timezone.utc) - timedelta(days=_history_retention_days)
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
