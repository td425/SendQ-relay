"""Outbound delivery engine — relay and direct MX delivery."""

import asyncio
import ipaddress
import logging
import socket as _socket
import ssl
import time
from typing import Any

import aiosmtplib
import dns.resolver

from sendq_mta.core.config import Config
from sendq_mta.transport.connection_pool import ConnectionPool

logger = logging.getLogger("sendq-mta.delivery")

# Private / loopback networks that must never be used as relay targets.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _check_addr_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, host: str) -> None:
    """Raise ``ValueError`` if *addr* is private/loopback.

    Handles IPv6-mapped IPv4 addresses (e.g. ``::ffff:127.0.0.1``) by
    extracting the underlying IPv4 address before checking.
    """
    # Unwrap IPv6-mapped IPv4 (e.g. ::ffff:127.0.0.1 → 127.0.0.1)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped

    for net in _BLOCKED_NETWORKS:
        if addr in net:
            raise ValueError(
                f"Relay host {host} resolves to private/loopback address {addr}"
            )


def _validate_relay_host(host: str) -> None:
    """Reject relay hosts that resolve to private or loopback addresses.

    Raises ``ValueError`` if the host is unsafe.
    """
    # First check if host is already a literal IP
    try:
        addr = ipaddress.ip_address(host)
        _check_addr_blocked(addr, host)
        return
    except ValueError as exc:
        if "private/loopback" in str(exc):
            raise
        # Not a literal IP — resolve it below

    try:
        results = _socket.getaddrinfo(host, None, _socket.AF_UNSPEC, _socket.SOCK_STREAM)
        for family, _type, _proto, _canonname, sockaddr in results:
            addr = ipaddress.ip_address(sockaddr[0])
            _check_addr_blocked(addr, host)
    except _socket.gaierror:
        pass  # DNS resolution failed — let the connection attempt handle it


class DeliveryEngine:
    """Delivers messages via relay or direct MX lookup."""

    # Fallback nameservers when the system has none configured
    _FALLBACK_DNS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    def __init__(self, config: Config):
        self.config = config
        self._pool = ConnectionPool(config) if config.get("delivery.connection_pool.enabled", True) else None

        try:
            self._dns_resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            logger.warning("No system DNS configured; falling back to public resolvers")
            self._dns_resolver = dns.resolver.Resolver(configure=False)
            self._dns_resolver.nameservers = list(self._FALLBACK_DNS)

        self._dns_resolver.lifetime = config.get("delivery.dns_timeout", 10)

        custom_dns = config.get("delivery.dns_servers", [])
        if custom_dns:
            self._dns_resolver.nameservers = custom_dns

    async def deliver(self, msg: Any) -> bool:
        """Deliver a message. Returns True on success."""
        relay_cfg = self.config.get("relay", {})

        if relay_cfg.get("enabled"):
            return await self._deliver_via_relay(msg, relay_cfg)
        else:
            return await self._deliver_direct(msg)

    async def _deliver_via_relay(self, msg: Any, relay_cfg: dict) -> bool:
        """Deliver through configured SMTP relay / smarthost."""
        host = relay_cfg.get("host", "")
        port = relay_cfg.get("port", 587)

        # SSRF protection: reject relay hosts that resolve to private IPs
        try:
            _validate_relay_host(host)
        except ValueError as exc:
            logger.error("Relay host rejected: %s", exc)
            return False
        username = relay_cfg.get("username", "")
        password = relay_cfg.get("password", "")
        tls_mode = relay_cfg.get("tls_mode", "starttls")
        tls_verify = relay_cfg.get("tls_verify", True)

        try:
            success = await self._send_smtp(
                host=host,
                port=port,
                username=username,
                password=password,
                tls_mode=tls_mode,
                tls_verify=tls_verify,
                sender=msg.sender,
                recipients=msg.recipients,
                data=msg.data,
            )
            if success:
                return True
        except Exception as exc:
            logger.warning("Primary relay failed: %s — trying failover", exc)

        # Try failover relays
        for failover in relay_cfg.get("failover", []):
            if not failover.get("host"):
                continue
            try:
                _validate_relay_host(failover["host"])
            except ValueError as exc:
                logger.warning("Failover relay rejected: %s", exc)
                continue
            try:
                success = await self._send_smtp(
                    host=failover["host"],
                    port=failover.get("port", 587),
                    username=failover.get("username", ""),
                    password=failover.get("password", ""),
                    tls_mode=failover.get("tls_mode", "starttls"),
                    tls_verify=tls_verify,
                    sender=msg.sender,
                    recipients=msg.recipients,
                    data=msg.data,
                )
                if success:
                    return True
            except Exception as exc:
                logger.warning("Failover relay %s failed: %s", failover["host"], exc)

        return False

    async def _deliver_direct(self, msg: Any) -> bool:
        """Deliver directly to recipient MX servers."""
        # Group recipients by domain
        domain_rcpts: dict[str, list[str]] = {}
        for rcpt in msg.recipients:
            domain = rcpt.rsplit("@", 1)[-1].lower() if "@" in rcpt else ""
            if domain:
                domain_rcpts.setdefault(domain, []).append(rcpt)

        all_success = True
        for domain, recipients in domain_rcpts.items():
            try:
                mx_hosts = await self._resolve_mx(domain)
                delivered = False

                for mx_host, _priority in mx_hosts:
                    try:
                        _validate_relay_host(mx_host)
                    except ValueError:
                        logger.warning(
                            "Skipping MX %s for %s — resolves to private/loopback",
                            mx_host, domain,
                        )
                        continue
                    try:
                        success = await self._send_smtp(
                            host=mx_host,
                            port=25,
                            username="",
                            password="",
                            tls_mode="starttls",  # opportunistic
                            tls_verify=False,
                            sender=msg.sender,
                            recipients=recipients,
                            data=msg.data,
                        )
                        if success:
                            delivered = True
                            break
                    except Exception as exc:
                        logger.warning(
                            "MX %s for %s failed: %s — trying next", mx_host, domain, exc
                        )

                if not delivered:
                    all_success = False
                    logger.error("All MX hosts failed for domain %s", domain)

            except Exception as exc:
                logger.error("DNS MX lookup failed for %s: %s", domain, exc)
                all_success = False

        return all_success

    async def _resolve_mx(self, domain: str) -> list[tuple[str, int]]:
        """Resolve MX records for a domain, sorted by priority."""
        loop = asyncio.get_event_loop()

        def _lookup():
            try:
                answers = self._dns_resolver.resolve(domain, "MX")
                results = []
                for rdata in answers:
                    host = str(rdata.exchange).rstrip(".")
                    results.append((host, rdata.preference))
                results.sort(key=lambda x: x[1])
                return results
            except dns.resolver.NoAnswer:
                # Fall back to A record
                return [(domain, 0)]
            except dns.resolver.NXDOMAIN:
                raise ValueError(f"Domain {domain} does not exist")

        return await loop.run_in_executor(None, _lookup)

    async def _send_smtp(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        tls_mode: str,
        tls_verify: bool,
        sender: str,
        recipients: list[str],
        data: bytes | str,
    ) -> bool:
        """Send mail via SMTP to a specific host."""
        connect_timeout = self.config.get("delivery.connect_timeout", 30)
        read_timeout = self.config.get("delivery.read_timeout", 120)

        kwargs: dict[str, Any] = {
            "hostname": host,
            "port": port,
            "timeout": connect_timeout,
        }

        if tls_mode == "implicit":
            tls_context = self._make_tls_context(tls_verify)
            kwargs["use_tls"] = True
            kwargs["tls_context"] = tls_context
        else:
            kwargs["use_tls"] = False

        try:
            smtp = aiosmtplib.SMTP(**kwargs)
            await smtp.connect()

            if tls_mode == "starttls":
                tls_context = self._make_tls_context(tls_verify)
                try:
                    await smtp.starttls(tls_context=tls_context)
                except aiosmtplib.SMTPException:
                    # Opportunistic — continue without TLS if server doesn't support
                    if tls_verify:
                        raise
                    logger.debug("STARTTLS not supported by %s, continuing plain", host)

            if username and password:
                await smtp.login(username, password)

            message_data = data if isinstance(data, (str, bytes)) else str(data)

            await smtp.sendmail(sender, recipients, message_data)
            await smtp.quit()

            logger.debug(
                "Sent to %s:%d sender=%s rcpts=%d",
                host, port, sender, len(recipients),
            )
            return True

        except aiosmtplib.SMTPResponseException as exc:
            logger.warning(
                "SMTP error from %s:%d — %d %s",
                host, port, exc.code, exc.message,
            )
            if 500 <= exc.code < 600:
                raise  # Permanent failure — don't retry
            return False
        except Exception as exc:
            logger.warning("Connection error to %s:%d — %s", host, port, exc)
            return False

    @staticmethod
    def _make_tls_context(verify: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx
