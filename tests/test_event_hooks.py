"""Enforce the one-way dependency rule: sendq_mta must not import sendq_dashboard."""

from pathlib import Path

import sendq_mta.core.events as events


def test_default_hooks_are_noop():
    # Calling the defaults must not raise.
    events.on_message_enqueued("id", "a@b", ["c@d"], "1.2.3.4", 0, "2026-01-01T00:00:00")
    events.on_delivery_attempt("id", "2026-01-01T00:00:00", None, None, None, "deferred")
    events.on_message_terminal("id", "delivered", "2026-01-01T00:00:00", None)


def test_no_module_level_dashboard_imports_in_mta_package():
    """The MTA package must not import sendq_dashboard at module load time.

    Lazy imports inside function bodies (e.g. CLI subcommands that optionally
    launch the dashboard) are allowed — those only fire when the operator
    invokes that command.
    """
    root = Path(__file__).resolve().parent.parent / "src" / "sendq_mta"
    offenders = []
    for py in root.rglob("*.py"):
        for line in py.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):
                continue
            if "sendq_dashboard" not in line:
                continue
            # Module-level import = starts at column 0 with import/from.
            if line.startswith("import ") or line.startswith("from "):
                offenders.append(f"{py.relative_to(root)}: {line.strip()}")
    assert not offenders, (
        "sendq_mta must not import sendq_dashboard at module level. Offenders:\n  "
        + "\n  ".join(offenders)
    )


def test_hooks_can_be_overridden():
    calls = []

    def cb(msg_id, *args, **kwargs):
        calls.append(msg_id)

    original = events.on_message_enqueued
    events.on_message_enqueued = cb
    try:
        events.on_message_enqueued("xyz", "a@b", [], "", 0, "")
        assert calls == ["xyz"]
    finally:
        events.on_message_enqueued = original
