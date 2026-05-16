"""SQLite helpers, WAL setup, and a tiny migration runner.

A single SQLite file (default ``/var/lib/sendq-mta/dashboard.db``) holds
queryable dashboard data (message history, delivery attempts, audit log).
WAL mode lets the queue manager write while the Flask threads read without
blocking each other.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("sendq-dashboard.db")

_DB_PATH: str | None = None
_TLS = threading.local()
_INIT_LOCK = threading.Lock()
_INITIALISED = False


def init(db_path: str) -> None:
    """Open/create the DB, enable WAL, apply pending migrations.

    Idempotent. Safe to call from multiple threads but the actual
    migration only runs once per process.
    """
    global _DB_PATH, _INITIALISED
    with _INIT_LOCK:
        _DB_PATH = db_path
        Path(os.path.dirname(db_path) or ".").mkdir(parents=True, exist_ok=True)

        conn = _open_connection(db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            _apply_migrations(conn)
        finally:
            conn.close()

        try:
            os.chmod(db_path, 0o600)
        except OSError:
            pass

        _INITIALISED = True
        logger.info("Dashboard DB ready at %s (WAL mode)", db_path)


def _open_connection(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(
        path,
        timeout=30.0,
        isolation_level=None,  # manual transactions via BEGIN/COMMIT
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    return conn


def get_connection() -> sqlite3.Connection:
    """Return a thread-local connection. Lazily created per-thread.

    SQLite connections aren't shareable across threads with
    ``check_same_thread=True``; we pin one per Flask worker thread.
    """
    if _DB_PATH is None:
        raise RuntimeError("Dashboard DB not initialised — call db.init() first")
    conn = getattr(_TLS, "conn", None)
    if conn is None:
        conn = _open_connection(_DB_PATH)
        conn.execute("PRAGMA foreign_keys=ON")
        _TLS.conn = conn
    return conn


@contextmanager
def with_tx() -> Iterator[sqlite3.Connection]:
    """Context manager wrapping BEGIN IMMEDIATE / COMMIT (or ROLLBACK)."""
    conn = get_connection()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise


def fetch(query: str, params: tuple = ()) -> list[sqlite3.Row]:
    return get_connection().execute(query, params).fetchall()


def fetch_one(query: str, params: tuple = ()) -> sqlite3.Row | None:
    return get_connection().execute(query, params).fetchone()


def execute(query: str, params: tuple = ()) -> int:
    """Run an INSERT/UPDATE/DELETE outside an explicit transaction.

    Returns the cursor lastrowid (useful for INSERTs).
    """
    cur = get_connection().execute(query, params)
    return cur.lastrowid or 0


def _apply_migrations(conn: sqlite3.Connection) -> None:
    """Run any unapplied .sql migration files in numeric order."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version INTEGER PRIMARY KEY, "
        "applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    applied = {row[0] for row in conn.execute(
        "SELECT version FROM schema_migrations"
    ).fetchall()}

    migrations_dir = resources.files("sendq_dashboard") / "migrations"
    candidates: list[tuple[int, Any]] = []
    for entry in migrations_dir.iterdir():
        name = entry.name
        if not name.endswith(".sql"):
            continue
        try:
            version = int(name.split("_", 1)[0])
        except ValueError:
            logger.warning("Skipping migration with unparseable version: %s", name)
            continue
        candidates.append((version, entry))

    for version, entry in sorted(candidates, key=lambda x: x[0]):
        if version in applied:
            continue
        sql = entry.read_text(encoding="utf-8")
        logger.info("Applying migration %d (%s)", version, entry.name)
        # ``executescript`` issues its own COMMIT before running, so wrapping
        # it in an explicit BEGIN/COMMIT is unsafe — instead, run the script
        # and then record the version in a separate statement.
        try:
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations(version) VALUES (?)", (version,)
            )
        except Exception:
            logger.exception("Migration %d failed", version)
            raise
