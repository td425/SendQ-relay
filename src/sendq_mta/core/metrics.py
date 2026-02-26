"""Prometheus metrics exporter for SendQ-MTA."""

import asyncio
import logging
import time
from typing import Any

from sendq_mta.core.config import Config

logger = logging.getLogger("sendq-mta.metrics")


class MetricsCollector:
    """Collects and exposes MTA metrics."""

    def __init__(self, config: Config):
        self.config = config
        self._counters: dict[str, int] = {
            "messages_received": 0,
            "messages_delivered": 0,
            "messages_deferred": 0,
            "messages_failed": 0,
            "messages_bounced": 0,
            "connections_inbound": 0,
            "connections_outbound": 0,
            "auth_success": 0,
            "auth_failure": 0,
            "tls_connections": 0,
            "rate_limited": 0,
            "spf_pass": 0,
            "spf_fail": 0,
            "dkim_signed": 0,
        }
        self._gauges: dict[str, float] = {
            "queue_active": 0,
            "queue_deferred": 0,
            "queue_failed": 0,
            "active_connections": 0,
            "delivery_workers_busy": 0,
        }
        self._start_time = time.time()

    def increment(self, counter: str, value: int = 1) -> None:
        if counter in self._counters:
            self._counters[counter] += value

    def set_gauge(self, gauge: str, value: float) -> None:
        if gauge in self._gauges:
            self._gauges[gauge] = value

    def get_all(self) -> dict[str, Any]:
        return {
            "uptime_seconds": int(time.time() - self._start_time),
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
        }

    def to_prometheus(self) -> str:
        """Format metrics in Prometheus exposition format."""
        lines = []
        lines.append(f"# HELP sendq_uptime_seconds Uptime in seconds")
        lines.append(f"# TYPE sendq_uptime_seconds gauge")
        lines.append(f"sendq_uptime_seconds {int(time.time() - self._start_time)}")

        for name, value in self._counters.items():
            prom_name = f"sendq_{name}_total"
            lines.append(f"# TYPE {prom_name} counter")
            lines.append(f"{prom_name} {value}")

        for name, value in self._gauges.items():
            prom_name = f"sendq_{name}"
            lines.append(f"# TYPE {prom_name} gauge")
            lines.append(f"{prom_name} {value}")

        return "\n".join(lines) + "\n"


class PrometheusExporter:
    """Simple HTTP server for Prometheus scraping."""

    def __init__(self, config: Config, metrics: MetricsCollector):
        self.config = config
        self.metrics = metrics
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        if not self.config.get("metrics.prometheus.enabled", True):
            return

        address = self.config.get("metrics.prometheus.address", "127.0.0.1")
        port = self.config.get("metrics.prometheus.port", 9225)

        self._server = await asyncio.start_server(
            self._handle_request, address, port
        )
        logger.info("Prometheus metrics at http://%s:%d/metrics", address, port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await reader.read(4096)
            body = self.metrics.to_prometheus()
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
                f"{body}"
            )
            writer.write(response.encode())
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
