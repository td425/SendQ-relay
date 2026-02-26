"""SPF (Sender Policy Framework) checking for SendQ-MTA."""

import logging
from typing import Any

from sendq_mta.core.config import Config

logger = logging.getLogger("sendq-mta.spf")

try:
    import spf as _spf

    SPF_AVAILABLE = True
except ImportError:
    SPF_AVAILABLE = False


class SPFChecker:
    """Checks SPF records for inbound mail."""

    def __init__(self, config: Config):
        self.config = config
        self._enabled = config.get("spf.enabled", True)
        self._hard_fail_action = config.get("spf.hard_fail_action", "reject")
        self._soft_fail_action = config.get("spf.soft_fail_action", "tag")
        self._neutral_action = config.get("spf.neutral_action", "accept")

    def check(self, ip: str, sender: str, helo: str = "") -> dict[str, Any]:
        """Check SPF for a given sender IP and envelope sender.

        Returns:
            dict with 'result' (pass|fail|softfail|neutral|none|temperror|permerror)
            and 'action' (accept|reject|quarantine|tag).
        """
        if not self._enabled:
            return {"result": "skipped", "action": "accept"}

        if not SPF_AVAILABLE:
            logger.debug("SPF check skipped — pyspf not installed")
            return {"result": "skipped", "action": "accept", "reason": "pyspf not installed"}

        try:
            result, explanation, _ = _spf.check2(i=ip, s=sender, h=helo)

            action = "accept"
            if result == "fail":
                action = self._hard_fail_action
            elif result == "softfail":
                action = self._soft_fail_action
            elif result == "neutral":
                action = self._neutral_action

            return {
                "result": result,
                "action": action,
                "explanation": explanation,
            }
        except Exception as exc:
            logger.warning("SPF check error for ip=%s sender=%s: %s", ip, sender, exc)
            return {"result": "temperror", "action": "accept", "reason": str(exc)}
