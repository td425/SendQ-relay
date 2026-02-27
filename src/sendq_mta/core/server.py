"""Async SMTP server — the inbound listener engine for SendQ-MTA."""

import asyncio
import logging
import os
import signal
import ssl
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer, Envelope, Session

from sendq_mta.core.config import Config, SNAKEOIL_CERT, SNAKEOIL_KEY, _generate_snakeoil
from sendq_mta.auth.authenticator import Authenticator
from sendq_mta.queue.manager import QueueManager
from sendq_mta.core.rate_limiter import RateLimiter

logger = logging.getLogger("sendq-mta.server")


class SendQHandler:
    """SMTP protocol handler — receives inbound mail and enqueues it."""

    def __init__(
        self,
        config: Config,
        queue_manager: QueueManager,
        authenticator: Authenticator,
        rate_limiter: RateLimiter,
    ):
        self.config = config
        self.queue = queue_manager
        self.auth = authenticator
        self.rate_limiter = rate_limiter

    async def handle_EHLO(
        self, server: SMTPServer, session: Session, envelope: Envelope, hostname: str, responses: list[str]
    ) -> list[str]:
        session.host_name = hostname
        return responses

    async def handle_MAIL(
        self,
        server: SMTPServer,
        session: Session,
        envelope: Envelope,
        address: str,
        mail_options: list[str],
    ) -> str:
        peer_ip = session.peer[0] if session.peer else "unknown"

        # Rate limit check
        if self.rate_limiter.is_banned(peer_ip):
            logger.warning("Rejected MAIL FROM from banned IP %s", peer_ip)
            return "550 Too many errors, you are temporarily banned"

        if not self.rate_limiter.check_inbound_rate(peer_ip):
            logger.warning("Rate limit exceeded for IP %s", peer_ip)
            return "451 Rate limit exceeded, try again later"

        # Check blocked domains
        sender_domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
        blocked = self.config.get("domains.blocked_domains", [])
        if sender_domain in blocked:
            return f"550 Domain {sender_domain} is blocked"

        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(
        self,
        server: SMTPServer,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        max_rcpt = self.config.get(
            "rate_limiting.inbound.max_recipients_per_message", 500
        )
        if len(envelope.rcpt_tos) >= max_rcpt:
            return f"452 Too many recipients (max {max_rcpt})"

        rcpt_domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
        blocked = self.config.get("domains.blocked_domains", [])
        if rcpt_domain in blocked:
            return f"550 Domain {rcpt_domain} is blocked"

        # Check if we handle this domain
        local_domains = self.config.get("domains.local_domains", [])
        relay_domains = self.config.get("domains.relay_domains", [])

        listener_requires_auth = getattr(session, "_listener_require_auth", False)
        is_authenticated = getattr(session, "authenticated", False)

        # If domain is local or relay domain, accept
        if rcpt_domain in local_domains or rcpt_domain in relay_domains:
            envelope.rcpt_tos.append(address)
            return "250 OK"

        # For external domains, require authentication
        if is_authenticated:
            envelope.rcpt_tos.append(address)
            return "250 OK"

        if listener_requires_auth:
            return "550 Authentication required for relay"

        # Open relay protection — reject by default
        return "550 Relay access denied"

    async def handle_DATA(
        self, server: SMTPServer, session: Session, envelope: Envelope
    ) -> str:
        peer_ip = session.peer[0] if session.peer else "unknown"
        max_size = self.config.get("server.max_message_size", 52428800)

        if len(envelope.content) > max_size:
            return f"552 Message too large (max {max_size} bytes)"

        # Enqueue message for delivery
        try:
            msg_id = await self.queue.enqueue(
                sender=envelope.mail_from,
                recipients=list(envelope.rcpt_tos),
                data=envelope.content,
                peer_ip=peer_ip,
                authenticated_user=getattr(session, "authenticated_user", None),
            )
            logger.info(
                "Accepted message %s from=%s rcpts=%d size=%d peer=%s",
                msg_id,
                envelope.mail_from,
                len(envelope.rcpt_tos),
                len(envelope.content),
                peer_ip,
            )
            return f"250 OK queued as {msg_id}"
        except Exception:
            logger.exception("Failed to enqueue message")
            return "451 Temporary failure, please retry"

class SendQAuthenticator:
    """aiosmtpd-compatible authenticator bridge (synchronous)."""

    def __init__(self, auth: Authenticator):
        self._auth = auth

    def __call__(
        self, server: SMTPServer, session: Session, envelope: Envelope, mechanism: str, auth_data: Any
    ) -> Any:
        try:
            if mechanism.upper() in ("PLAIN", "LOGIN"):
                username = auth_data.login.decode() if isinstance(auth_data.login, bytes) else auth_data.login
                password = auth_data.password.decode() if isinstance(auth_data.password, bytes) else auth_data.password
                if self._auth.authenticate(username, password):
                    session.authenticated = True
                    session.authenticated_user = username
                    logger.info("AUTH success for user=%s", username)
                    return True
                else:
                    logger.warning("AUTH failed for user=%s", username)
                    return False
            return False
        except Exception:
            logger.exception("AUTH error")
            return False


def _build_ssl_context(config: Config) -> ssl.SSLContext | None:
    """Build SSL context from config."""
    tls_cfg = config.get("tls", {})
    cert = tls_cfg.get("cert_file", "")
    key = tls_cfg.get("key_file", "")

    if not cert or not key:
        return None

    # Auto-generate snakeoil if using the default paths and files are missing
    if (
        cert == SNAKEOIL_CERT
        and key == SNAKEOIL_KEY
        and (not os.path.isfile(cert) or not os.path.isfile(key))
    ):
        _generate_snakeoil(cert, key)

    if not os.path.isfile(cert) or not os.path.isfile(key):
        logger.warning("TLS cert/key files not found; TLS disabled")
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    min_ver = tls_cfg.get("min_version", "TLSv1.2")
    if min_ver == "TLSv1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx.load_cert_chain(cert, key)

    ca_file = tls_cfg.get("ca_file", "")
    if ca_file and os.path.isfile(ca_file):
        ctx.load_verify_locations(ca_file)

    ciphers = tls_cfg.get("ciphers")
    if ciphers:
        ctx.set_ciphers(ciphers)

    if tls_cfg.get("prefer_server_ciphers", True):
        ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    return ctx


class MTAServer:
    """Top-level MTA server — manages listeners, queue, delivery."""

    def __init__(self, config: Config):
        self.config = config
        self.controllers: list[Controller] = []
        self.queue_manager = QueueManager(config)
        self.authenticator = Authenticator(config)
        self.rate_limiter = RateLimiter(config)
        self._running = False

    def _create_handler(self) -> SendQHandler:
        return SendQHandler(
            config=self.config,
            queue_manager=self.queue_manager,
            authenticator=self.authenticator,
            rate_limiter=self.rate_limiter,
        )

    def _setup_listeners(self) -> None:
        """Create aiosmtpd controllers for each configured listener."""
        listeners = self.config.get("listeners", [])
        ssl_context = _build_ssl_context(self.config)
        auth_bridge = SendQAuthenticator(self.authenticator)
        handler = self._create_handler()
        hostname = self.config.get("server.hostname", "localhost")

        for listener in listeners:
            name = listener.get("name", "unnamed")
            address = listener.get("address", "0.0.0.0")
            port = listener.get("port", 25)
            tls_mode = listener.get("tls_mode", "none")
            require_auth = listener.get("require_auth", False)

            kwargs: dict[str, Any] = {
                "handler": handler,
                "hostname": address,
                "port": port,
                "ident": self.config.get("server.banner", "SendQ-MTA"),
                "data_size_limit": self.config.get("server.max_message_size", 52428800),
                "enable_SMTPUTF8": True,
            }

            if require_auth:
                kwargs["authenticator"] = auth_bridge
                kwargs["auth_required"] = True
                # For implicit TLS the connection is already encrypted,
                # so we don't need the additional "require TLS before AUTH"
                # gate (which may not detect implicit-TLS sessions).
                kwargs["auth_require_tls"] = tls_mode == "starttls"

            if tls_mode == "implicit" and ssl_context:
                kwargs["ssl_context"] = ssl_context
            elif tls_mode == "starttls" and ssl_context:
                kwargs["tls_context"] = ssl_context

            controller = Controller(**kwargs)
            self.controllers.append(controller)
            logger.info(
                "Configured listener '%s' on %s:%d (tls=%s, auth=%s)",
                name, address, port, tls_mode, require_auth,
            )

    async def start(self) -> None:
        """Start all listeners and the delivery engine."""
        logger.info("Starting SendQ-MTA server")
        self._running = True
        self._setup_listeners()

        for controller in self.controllers:
            controller.start()
            logger.info("Listener started on %s:%s", controller.hostname, controller.port)

        # Start queue delivery workers
        await self.queue_manager.start_workers()

        logger.info(
            "SendQ-MTA is running — %d listeners active, %d queue workers",
            len(self.controllers),
            self.config.get("queue.workers", 16),
        )

    async def stop(self) -> None:
        """Gracefully shut down the server."""
        logger.info("Shutting down SendQ-MTA")
        self._running = False

        await self.queue_manager.stop_workers()

        for controller in self.controllers:
            controller.stop()

        self.rate_limiter.shutdown()
        logger.info("SendQ-MTA stopped")

    async def run_forever(self) -> None:
        """Start and run until interrupted."""
        await self.start()

        loop = asyncio.get_event_loop()
        stop_event = asyncio.Event()

        def _signal_handler():
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)

        # SIGHUP = reload config
        def _reload_handler():
            logger.info("SIGHUP received — reloading configuration")
            self.config.reload()

        loop.add_signal_handler(signal.SIGHUP, _reload_handler)

        await stop_event.wait()
        await self.stop()
