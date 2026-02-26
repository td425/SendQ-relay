"""DMARC (Domain-based Message Authentication) checking for SendQ-MTA."""

import logging
from typing import Any

import dns.resolver

from sendq_mta.core.config import Config

logger = logging.getLogger("sendq-mta.dmarc")


class DMARCChecker:
    """Checks DMARC policies for inbound mail."""

    def __init__(self, config: Config):
        self.config = config
        self._enabled = config.get("dmarc.enabled", True)
        self._reject_action = config.get("dmarc.reject_action", "reject")
        self._quarantine_action = config.get("dmarc.quarantine_action", "quarantine")

    def check(
        self,
        sender_domain: str,
        spf_result: str,
        spf_domain: str,
        dkim_result: str,
        dkim_domain: str,
    ) -> dict[str, Any]:
        """Evaluate DMARC policy for a message.

        Args:
            sender_domain: The From: header domain.
            spf_result: SPF check result (pass/fail/etc).
            spf_domain: Domain used in SPF check.
            dkim_result: DKIM verification result (pass/fail).
            dkim_domain: Domain from DKIM signature.

        Returns:
            dict with 'policy', 'result', 'action'.
        """
        if not self._enabled:
            return {"result": "skipped", "action": "accept"}

        # Fetch DMARC record
        record = self._fetch_dmarc_record(sender_domain)
        if not record:
            return {
                "result": "none",
                "action": "accept",
                "reason": "No DMARC record found",
            }

        policy = self._parse_policy(record)

        # DMARC alignment check
        spf_aligned = (
            spf_result == "pass"
            and self._domains_align(spf_domain, sender_domain, policy.get("aspf", "r"))
        )
        dkim_aligned = (
            dkim_result == "pass"
            and self._domains_align(dkim_domain, sender_domain, policy.get("adkim", "r"))
        )

        if spf_aligned or dkim_aligned:
            return {
                "result": "pass",
                "action": "accept",
                "policy": policy,
                "spf_aligned": spf_aligned,
                "dkim_aligned": dkim_aligned,
            }

        # Determine action based on policy
        p = policy.get("p", "none")
        if p == "reject":
            action = self._reject_action
        elif p == "quarantine":
            action = self._quarantine_action
        else:
            action = "accept"

        return {
            "result": "fail",
            "action": action,
            "policy": policy,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
        }

    def _fetch_dmarc_record(self, domain: str) -> str | None:
        """Fetch DMARC DNS TXT record for a domain."""
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = "".join(
                    s.decode() if isinstance(s, bytes) else s for s in rdata.strings
                )
                if txt.startswith("v=DMARC1"):
                    return txt
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as exc:
            logger.debug("DMARC DNS lookup error for %s: %s", domain, exc)

        # Try organizational domain (one level up)
        parts = domain.split(".")
        if len(parts) > 2:
            org_domain = ".".join(parts[-2:])
            try:
                answers = dns.resolver.resolve(f"_dmarc.{org_domain}", "TXT")
                for rdata in answers:
                    txt = "".join(
                        s.decode() if isinstance(s, bytes) else s for s in rdata.strings
                    )
                    if txt.startswith("v=DMARC1"):
                        return txt
            except Exception:
                pass

        return None

    @staticmethod
    def _parse_policy(record: str) -> dict[str, str]:
        """Parse a DMARC TXT record into a dict."""
        policy = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                policy[key.strip()] = value.strip()
        return policy

    @staticmethod
    def _domains_align(
        check_domain: str, from_domain: str, alignment: str
    ) -> bool:
        """Check domain alignment (strict or relaxed)."""
        check_domain = check_domain.lower()
        from_domain = from_domain.lower()

        if alignment == "s":
            # Strict — exact match
            return check_domain == from_domain
        else:
            # Relaxed — organizational domain match
            return (
                check_domain == from_domain
                or check_domain.endswith(f".{from_domain}")
                or from_domain.endswith(f".{check_domain}")
            )
