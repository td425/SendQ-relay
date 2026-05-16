"""Pub/sub hooks for cross-package observers (e.g. the dashboard).

The MTA daemon must remain runnable without the dashboard package installed,
so it never imports ``sendq_dashboard`` directly. Instead it calls the no-op
hooks below at the relevant lifecycle points. If the dashboard is installed,
it replaces these module-level callables on startup to receive events.

Callbacks must be cheap and non-raising — they run on the SMTP / delivery
critical path. The dashboard's implementations dispatch into a background
task so DB writes never block mail flow.
"""

from typing import Any, Callable


def _noop(*_args: Any, **_kwargs: Any) -> None:
    return None


# Signature: (msg_id, sender, recipients, peer_ip, size_bytes, received_at_iso)
on_message_enqueued: Callable[..., None] = _noop

# Signature: (msg_id, attempt_at_iso, remote_host, smtp_code, smtp_resp, outcome)
# outcome ∈ {"success", "deferred", "failed"}
on_delivery_attempt: Callable[..., None] = _noop

# Signature: (msg_id, status, finalized_at_iso, last_error)
# status ∈ {"delivered", "deferred", "failed"}
on_message_terminal: Callable[..., None] = _noop
