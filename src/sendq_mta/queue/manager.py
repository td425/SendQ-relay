"""Persistent disk-backed message queue with async delivery workers."""

import asyncio
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

from sendq_mta.core.config import Config

logger = logging.getLogger("sendq-mta.queue")


class QueueMessage:
    """Represents a queued email message."""

    def __init__(
        self,
        msg_id: str,
        sender: str,
        recipients: list[str],
        data: bytes | str,
        peer_ip: str = "",
        authenticated_user: str | None = None,
        created_at: float | None = None,
        retry_count: int = 0,
        next_retry: float | None = None,
        last_error: str = "",
        status: str = "queued",
    ):
        self.msg_id = msg_id
        self.sender = sender
        self.recipients = recipients
        self.data = data if isinstance(data, bytes) else data.encode("utf-8")
        self.peer_ip = peer_ip
        self.authenticated_user = authenticated_user
        self.created_at = created_at or time.time()
        self.retry_count = retry_count
        self.next_retry = next_retry or time.time()
        self.last_error = last_error
        self.status = status  # queued | delivering | deferred | failed | delivered

    def to_meta(self) -> dict[str, Any]:
        """Serialize metadata (without body) to dict."""
        return {
            "msg_id": self.msg_id,
            "sender": self.sender,
            "recipients": self.recipients,
            "peer_ip": self.peer_ip,
            "authenticated_user": self.authenticated_user,
            "created_at": self.created_at,
            "retry_count": self.retry_count,
            "next_retry": self.next_retry,
            "last_error": self.last_error,
            "status": self.status,
        }

    @classmethod
    def from_disk(cls, meta_path: str, data_path: str) -> "QueueMessage":
        """Load a queued message from disk."""
        with open(meta_path, "r") as f:
            meta = json.load(f)
        with open(data_path, "rb") as f:
            data = f.read()
        return cls(data=data, **meta)


class QueueManager:
    """Manages the persistent mail queue and delivery workers."""

    def __init__(self, config: Config):
        self.config = config
        self._queue_dir = config.get("queue.directory", "/var/spool/sendq-mta/queue")
        self._deferred_dir = config.get(
            "queue.deferred_directory", "/var/spool/sendq-mta/deferred"
        )
        self._failed_dir = config.get(
            "queue.failed_directory", "/var/spool/sendq-mta/failed"
        )
        self._workers: list[asyncio.Task] = []
        self._delivery_queue: asyncio.Queue[QueueMessage] = asyncio.Queue()
        self._running = False
        self._stats = {
            "enqueued": 0,
            "delivered": 0,
            "deferred": 0,
            "failed": 0,
            "active": 0,
        }

        # Ensure directories exist
        for d in (self._queue_dir, self._deferred_dir, self._failed_dir):
            Path(d).mkdir(parents=True, exist_ok=True)

    async def enqueue(
        self,
        sender: str,
        recipients: list[str],
        data: bytes | str,
        peer_ip: str = "",
        authenticated_user: str | None = None,
    ) -> str:
        """Add a message to the queue. Returns message ID."""
        msg_id = f"sendq-{uuid.uuid4().hex[:16]}-{int(time.time())}"

        msg = QueueMessage(
            msg_id=msg_id,
            sender=sender,
            recipients=recipients,
            data=data,
            peer_ip=peer_ip,
            authenticated_user=authenticated_user,
        )

        # Write to disk
        await self._write_to_disk(msg, self._queue_dir)
        self._stats["enqueued"] += 1

        # Push to in-memory delivery queue
        await self._delivery_queue.put(msg)

        logger.info("Enqueued %s from=%s rcpts=%d", msg_id, sender, len(recipients))
        return msg_id

    async def _write_to_disk(self, msg: QueueMessage, directory: str) -> None:
        """Persist message to disk (metadata + body as separate files)."""
        meta_path = os.path.join(directory, f"{msg.msg_id}.meta.json")
        data_path = os.path.join(directory, f"{msg.msg_id}.eml")

        loop = asyncio.get_event_loop()

        def _write():
            with open(meta_path, "w") as f:
                json.dump(msg.to_meta(), f, indent=2)
            with open(data_path, "wb") as f:
                f.write(msg.data if isinstance(msg.data, bytes) else msg.data.encode())

        await loop.run_in_executor(None, _write)

    async def _remove_from_disk(self, msg_id: str, directory: str) -> None:
        """Remove a message from disk."""
        loop = asyncio.get_event_loop()

        def _remove():
            for ext in (".meta.json", ".eml"):
                path = os.path.join(directory, f"{msg_id}{ext}")
                if os.path.exists(path):
                    os.unlink(path)

        await loop.run_in_executor(None, _remove)

    async def _move_to_deferred(self, msg: QueueMessage, error: str) -> None:
        """Move message to deferred queue with updated retry info."""
        retry_intervals = self.config.get(
            "queue.retry_intervals", [60, 300, 900, 1800, 3600]
        )
        max_retries = self.config.get("queue.max_retries", 30)
        max_age = self.config.get("queue.max_age", 432000)

        msg.retry_count += 1
        msg.last_error = error
        msg.status = "deferred"

        # Check if we've exceeded limits
        age = time.time() - msg.created_at
        if msg.retry_count >= max_retries or age >= max_age:
            await self._move_to_failed(msg, error)
            return

        # Calculate next retry time
        idx = min(msg.retry_count - 1, len(retry_intervals) - 1)
        msg.next_retry = time.time() + retry_intervals[idx]

        await self._remove_from_disk(msg.msg_id, self._queue_dir)
        await self._write_to_disk(msg, self._deferred_dir)
        self._stats["deferred"] += 1

        logger.info(
            "Deferred %s retry=%d next_in=%ds error=%s",
            msg.msg_id,
            msg.retry_count,
            retry_intervals[idx],
            error[:100],
        )

    async def _move_to_failed(self, msg: QueueMessage, error: str) -> None:
        """Move message to failed queue (permanent failure)."""
        msg.status = "failed"
        msg.last_error = error

        await self._remove_from_disk(msg.msg_id, self._queue_dir)
        await self._remove_from_disk(msg.msg_id, self._deferred_dir)
        await self._write_to_disk(msg, self._failed_dir)
        self._stats["failed"] += 1

        logger.warning("Failed permanently %s error=%s", msg.msg_id, error[:200])

    async def _delivery_worker(self, worker_id: int) -> None:
        """Worker coroutine that pulls messages from the queue and delivers."""
        # Import here to avoid circular imports
        from sendq_mta.transport.delivery import DeliveryEngine

        engine = DeliveryEngine(self.config)

        logger.info("Delivery worker %d started", worker_id)
        while self._running:
            try:
                msg = await asyncio.wait_for(self._delivery_queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            self._stats["active"] += 1
            msg.status = "delivering"

            try:
                success = await engine.deliver(msg)
                if success:
                    await self._remove_from_disk(msg.msg_id, self._queue_dir)
                    self._stats["delivered"] += 1
                    logger.info("Delivered %s", msg.msg_id)
                else:
                    await self._move_to_deferred(msg, "Delivery returned failure")
            except Exception as exc:
                logger.exception("Delivery error for %s", msg.msg_id)
                await self._move_to_deferred(msg, str(exc))
            finally:
                self._stats["active"] -= 1
                self._delivery_queue.task_done()

        logger.info("Delivery worker %d stopped", worker_id)

    async def _deferred_scanner(self) -> None:
        """Periodically scan deferred directory and re-enqueue ready messages."""
        flush_interval = self.config.get("queue.flush_interval", 30)

        while self._running:
            await asyncio.sleep(flush_interval)
            try:
                await self._scan_deferred()
            except Exception:
                logger.exception("Error scanning deferred queue")

    async def _scan_deferred(self) -> None:
        """Scan deferred directory for messages ready for retry."""
        loop = asyncio.get_event_loop()
        now = time.time()

        def _list_meta():
            files = []
            if os.path.isdir(self._deferred_dir):
                for f in os.listdir(self._deferred_dir):
                    if f.endswith(".meta.json"):
                        files.append(os.path.join(self._deferred_dir, f))
            return files

        meta_files = await loop.run_in_executor(None, _list_meta)

        for meta_path in meta_files:
            try:
                msg_id = os.path.basename(meta_path).replace(".meta.json", "")
                data_path = os.path.join(self._deferred_dir, f"{msg_id}.eml")
                if not os.path.exists(data_path):
                    continue

                msg = await loop.run_in_executor(
                    None, QueueMessage.from_disk, meta_path, data_path
                )

                if msg.next_retry <= now:
                    msg.status = "queued"
                    # Move back to active queue
                    await self._remove_from_disk(msg.msg_id, self._deferred_dir)
                    await self._write_to_disk(msg, self._queue_dir)
                    await self._delivery_queue.put(msg)
                    logger.info("Re-queued deferred message %s", msg.msg_id)
            except Exception:
                logger.exception("Error processing deferred message %s", meta_path)

    async def _load_existing_queue(self) -> None:
        """On startup, load any existing queued messages."""
        loop = asyncio.get_event_loop()

        def _list_queue():
            files = []
            if os.path.isdir(self._queue_dir):
                for f in os.listdir(self._queue_dir):
                    if f.endswith(".meta.json"):
                        files.append(f.replace(".meta.json", ""))
            return files

        msg_ids = await loop.run_in_executor(None, _list_queue)

        for msg_id in msg_ids:
            try:
                meta_path = os.path.join(self._queue_dir, f"{msg_id}.meta.json")
                data_path = os.path.join(self._queue_dir, f"{msg_id}.eml")
                if os.path.exists(meta_path) and os.path.exists(data_path):
                    msg = await loop.run_in_executor(
                        None, QueueMessage.from_disk, meta_path, data_path
                    )
                    await self._delivery_queue.put(msg)
            except Exception:
                logger.exception("Error loading queued message %s", msg_id)

        if msg_ids:
            logger.info("Loaded %d messages from queue on startup", len(msg_ids))

    async def start_workers(self) -> None:
        """Start delivery workers and deferred scanner."""
        self._running = True
        num_workers = self.config.get("queue.workers", 16)

        # Load existing queued messages
        await self._load_existing_queue()

        # Start workers
        for i in range(num_workers):
            task = asyncio.create_task(self._delivery_worker(i))
            self._workers.append(task)

        # Start deferred scanner
        scanner = asyncio.create_task(self._deferred_scanner())
        self._workers.append(scanner)

        logger.info("Started %d delivery workers + deferred scanner", num_workers)

    async def stop_workers(self) -> None:
        """Stop all delivery workers gracefully."""
        self._running = False
        for task in self._workers:
            task.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        logger.info("All delivery workers stopped")

    def get_stats(self) -> dict[str, Any]:
        return dict(self._stats)

    async def get_queue_list(self, directory: str | None = None) -> list[dict]:
        """List all messages in a queue directory."""
        target = directory or self._queue_dir
        loop = asyncio.get_event_loop()

        def _scan():
            messages = []
            if not os.path.isdir(target):
                return messages
            for f in sorted(os.listdir(target)):
                if f.endswith(".meta.json"):
                    path = os.path.join(target, f)
                    try:
                        with open(path, "r") as fh:
                            meta = json.load(fh)
                            messages.append(meta)
                    except Exception:
                        pass
            return messages

        return await loop.run_in_executor(None, _scan)

    async def flush_queue(self) -> int:
        """Force retry all deferred messages immediately."""
        count = 0
        loop = asyncio.get_event_loop()

        def _list_deferred():
            ids = []
            if os.path.isdir(self._deferred_dir):
                for f in os.listdir(self._deferred_dir):
                    if f.endswith(".meta.json"):
                        ids.append(f.replace(".meta.json", ""))
            return ids

        msg_ids = await loop.run_in_executor(None, _list_deferred)

        for msg_id in msg_ids:
            try:
                meta_path = os.path.join(self._deferred_dir, f"{msg_id}.meta.json")
                data_path = os.path.join(self._deferred_dir, f"{msg_id}.eml")
                if os.path.exists(meta_path) and os.path.exists(data_path):
                    msg = await loop.run_in_executor(
                        None, QueueMessage.from_disk, meta_path, data_path
                    )
                    msg.next_retry = 0
                    msg.status = "queued"
                    await self._remove_from_disk(msg.msg_id, self._deferred_dir)
                    await self._write_to_disk(msg, self._queue_dir)
                    await self._delivery_queue.put(msg)
                    count += 1
            except Exception:
                logger.exception("Error flushing message %s", msg_id)

        logger.info("Flushed %d deferred messages", count)
        return count

    async def delete_message(self, msg_id: str) -> bool:
        """Delete a message from any queue."""
        for directory in (self._queue_dir, self._deferred_dir, self._failed_dir):
            meta = os.path.join(directory, f"{msg_id}.meta.json")
            if os.path.exists(meta):
                await self._remove_from_disk(msg_id, directory)
                logger.info("Deleted message %s from %s", msg_id, directory)
                return True
        return False

    async def purge_failed(self) -> int:
        """Delete all failed messages."""
        loop = asyncio.get_event_loop()

        def _purge():
            count = 0
            if os.path.isdir(self._failed_dir):
                for f in os.listdir(self._failed_dir):
                    os.unlink(os.path.join(self._failed_dir, f))
                    count += 1
            return count // 2  # meta + eml per message

        return await loop.run_in_executor(None, _purge)
