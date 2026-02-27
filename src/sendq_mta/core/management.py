"""Management API — UNIX socket + optional HTTP for CLI communication."""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from sendq_mta.core.config import Config
from sendq_mta.queue.manager import QueueManager
from sendq_mta.auth.authenticator import Authenticator
from sendq_mta.core.rate_limiter import RateLimiter

logger = logging.getLogger("sendq-mta.mgmt")


class ManagementAPI:
    """Internal management API exposed over a UNIX socket for CLI control."""

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
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        """Start the management socket listener."""
        if not self.config.get("management_api.enabled", True):
            return

        socket_path = self.config.get(
            "management_api.socket", "/var/run/sendq-mta/mgmt.sock"
        )
        Path(socket_path).parent.mkdir(parents=True, exist_ok=True)

        # Remove stale socket
        if os.path.exists(socket_path):
            os.unlink(socket_path)

        # Set restrictive umask so the socket is created with tight permissions
        old_umask = os.umask(0o117)
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_connection, path=socket_path
            )
        finally:
            os.umask(old_umask)
        os.chmod(socket_path, 0o660)
        logger.info("Management API listening on %s", socket_path)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single management API request."""
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=30)
            if not data:
                return

            request = json.loads(data.decode())
            command = request.get("command", "")
            params = request.get("params", {})

            response = await self._dispatch(command, params)
            writer.write(json.dumps(response).encode())
            await writer.drain()
        except Exception as exc:
            try:
                error_resp = {"status": "error", "message": str(exc)}
                writer.write(json.dumps(error_resp).encode())
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()

    async def _dispatch(self, command: str, params: dict) -> dict[str, Any]:
        """Dispatch a management command and return result."""
        handlers = {
            "status": self._cmd_status,
            "queue_status": self._cmd_queue_status,
            "queue_list": self._cmd_queue_list,
            "queue_flush": self._cmd_queue_flush,
            "queue_delete": self._cmd_queue_delete,
            "queue_purge_failed": self._cmd_queue_purge_failed,
            "list_users": self._cmd_list_users,
            "rate_limiter_stats": self._cmd_rate_stats,
            "reload_config": self._cmd_reload,
        }

        handler = handlers.get(command)
        if not handler:
            return {"status": "error", "message": f"Unknown command: {command}"}

        return await handler(params)

    async def _cmd_status(self, params: dict) -> dict:
        return {
            "status": "ok",
            "data": {
                "running": True,
                "pid": os.getpid(),
                "queue": self.queue.get_stats(),
                "rate_limiter": self.rate_limiter.get_stats(),
            },
        }

    async def _cmd_queue_status(self, params: dict) -> dict:
        return {"status": "ok", "data": self.queue.get_stats()}

    async def _cmd_queue_list(self, params: dict) -> dict:
        queue_type = params.get("type", "all")
        messages = []

        if queue_type in ("active", "all"):
            active = await self.queue.get_queue_list()
            for m in active:
                m["queue"] = "active"
            messages.extend(active)

        if queue_type in ("deferred", "all"):
            deferred_dir = self.config.get(
                "queue.deferred_directory", "/var/spool/sendq-mta/deferred"
            )
            deferred = await self.queue.get_queue_list(deferred_dir)
            for m in deferred:
                m["queue"] = "deferred"
            messages.extend(deferred)

        if queue_type in ("failed", "all"):
            failed_dir = self.config.get(
                "queue.failed_directory", "/var/spool/sendq-mta/failed"
            )
            failed = await self.queue.get_queue_list(failed_dir)
            for m in failed:
                m["queue"] = "failed"
            messages.extend(failed)

        return {"status": "ok", "data": messages}

    async def _cmd_queue_flush(self, params: dict) -> dict:
        count = await self.queue.flush_queue()
        return {"status": "ok", "data": {"flushed": count}}

    async def _cmd_queue_delete(self, params: dict) -> dict:
        msg_id = params.get("msg_id", "")
        if not msg_id:
            return {"status": "error", "message": "msg_id required"}
        result = await self.queue.delete_message(msg_id)
        return {"status": "ok" if result else "error", "data": {"deleted": result}}

    async def _cmd_queue_purge_failed(self, params: dict) -> dict:
        count = await self.queue.purge_failed()
        return {"status": "ok", "data": {"purged": count}}

    async def _cmd_list_users(self, params: dict) -> dict:
        users = self.auth.list_users()
        return {"status": "ok", "data": users}

    async def _cmd_rate_stats(self, params: dict) -> dict:
        return {"status": "ok", "data": self.rate_limiter.get_stats()}

    async def _cmd_reload(self, params: dict) -> dict:
        self.config.reload()
        errors = self.config.validate()
        if errors:
            return {"status": "error", "message": "Validation failed", "errors": errors}
        return {"status": "ok", "message": "Configuration reloaded"}
