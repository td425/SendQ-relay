"""Connection pool for outbound SMTP connections."""

import asyncio
import logging
import ssl
import time
from collections import defaultdict
from typing import Any

import aiosmtplib

from sendq_mta.core.config import Config

logger = logging.getLogger("sendq-mta.pool")


class PooledConnection:
    """Wrapper around an SMTP connection with metadata."""

    def __init__(self, smtp: aiosmtplib.SMTP, host: str, port: int):
        self.smtp = smtp
        self.host = host
        self.port = port
        self.created_at = time.monotonic()
        self.last_used = time.monotonic()
        self.in_use = False

    @property
    def age(self) -> float:
        return time.monotonic() - self.created_at

    @property
    def idle_time(self) -> float:
        return time.monotonic() - self.last_used

    def mark_used(self) -> None:
        self.last_used = time.monotonic()
        self.in_use = True

    def release(self) -> None:
        self.last_used = time.monotonic()
        self.in_use = False

    async def is_alive(self) -> bool:
        try:
            await self.smtp.noop()
            return True
        except Exception:
            return False

    async def close(self) -> None:
        try:
            await self.smtp.quit()
        except Exception:
            pass


class ConnectionPool:
    """Manages a pool of reusable outbound SMTP connections."""

    def __init__(self, config: Config):
        self.config = config
        self._pools: dict[str, list[PooledConnection]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._total_connections = 0

        pool_cfg = config.get("delivery.connection_pool", {})
        self._size_per_domain = pool_cfg.get("size_per_domain", 10)
        self._max_total = pool_cfg.get("max_total", 500)
        self._idle_timeout = pool_cfg.get("idle_timeout", 300)
        self._max_lifetime = pool_cfg.get("max_lifetime", 1800)

        # Start cleanup task
        self._cleanup_running = True
        self._cleanup_task: asyncio.Task | None = None

    async def start(self) -> None:
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self) -> None:
        self._cleanup_running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
        await self.close_all()

    def _pool_key(self, host: str, port: int, username: str = "") -> str:
        return f"{host}:{port}:{username}"

    async def acquire(
        self,
        host: str,
        port: int,
        tls_mode: str = "starttls",
        tls_verify: bool = True,
        username: str = "",
        password: str = "",
    ) -> PooledConnection | None:
        """Acquire a connection from the pool, or create a new one."""
        key = self._pool_key(host, port, username)

        async with self._lock:
            # Try to find an idle connection
            pool = self._pools[key]
            for conn in pool:
                if not conn.in_use:
                    if conn.age > self._max_lifetime:
                        await conn.close()
                        pool.remove(conn)
                        self._total_connections -= 1
                        continue
                    if await conn.is_alive():
                        conn.mark_used()
                        return conn
                    else:
                        await conn.close()
                        pool.remove(conn)
                        self._total_connections -= 1

            # Create new connection if under limits
            if (
                len(pool) < self._size_per_domain
                and self._total_connections < self._max_total
            ):
                conn = await self._create_connection(
                    host, port, tls_mode, tls_verify, username, password
                )
                if conn:
                    conn.mark_used()
                    pool.append(conn)
                    self._total_connections += 1
                    return conn

        return None

    async def release(self, conn: PooledConnection) -> None:
        """Return a connection to the pool."""
        conn.release()

    async def _create_connection(
        self,
        host: str,
        port: int,
        tls_mode: str,
        tls_verify: bool,
        username: str,
        password: str,
    ) -> PooledConnection | None:
        """Create a new SMTP connection."""
        connect_timeout = self.config.get("delivery.connect_timeout", 30)

        kwargs: dict[str, Any] = {
            "hostname": host,
            "port": port,
            "timeout": connect_timeout,
        }

        if tls_mode == "implicit":
            ctx = ssl.create_default_context()
            if not tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            kwargs["use_tls"] = True
            kwargs["tls_context"] = ctx

        try:
            smtp = aiosmtplib.SMTP(**kwargs)
            await smtp.connect()

            if tls_mode == "starttls":
                ctx = ssl.create_default_context()
                if not tls_verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                try:
                    await smtp.starttls(tls_context=ctx)
                except aiosmtplib.SMTPException:
                    if tls_verify:
                        raise

            if username and password:
                await smtp.login(username, password)

            return PooledConnection(smtp, host, port)

        except Exception as exc:
            logger.warning("Failed to create connection to %s:%d — %s", host, port, exc)
            return None

    async def _cleanup_loop(self) -> None:
        """Periodically clean up idle/expired connections."""
        while self._cleanup_running:
            await asyncio.sleep(60)
            async with self._lock:
                for key, pool in list(self._pools.items()):
                    to_remove = []
                    for conn in pool:
                        if conn.in_use:
                            continue
                        if (
                            conn.idle_time > self._idle_timeout
                            or conn.age > self._max_lifetime
                        ):
                            await conn.close()
                            to_remove.append(conn)
                    for conn in to_remove:
                        pool.remove(conn)
                        self._total_connections -= 1
                    if not pool:
                        del self._pools[key]

    async def close_all(self) -> None:
        """Close all pooled connections."""
        async with self._lock:
            for pool in self._pools.values():
                for conn in pool:
                    await conn.close()
            self._pools.clear()
            self._total_connections = 0

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_connections": self._total_connections,
            "domains": len(self._pools),
            "per_domain": {
                key: {"total": len(pool), "idle": sum(1 for c in pool if not c.in_use)}
                for key, pool in self._pools.items()
            },
        }
