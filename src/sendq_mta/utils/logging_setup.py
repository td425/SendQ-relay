"""Logging configuration for SendQ-MTA."""

import logging
import logging.handlers
import os
import sys
import json
import time
from typing import Any

from sendq_mta.core.config import Config


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            )
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        for key in ("msg_id", "peer_ip", "mail_from", "rcpt_to", "queue_id"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)

        return json.dumps(log_entry)


class TextFormatter(logging.Formatter):
    """Human-readable text log formatter."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def _parse_size(size_str: str) -> int:
    """Parse size string like '100M' to bytes."""
    size_str = size_str.strip().upper()
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3}
    if size_str[-1] in multipliers:
        return int(size_str[:-1]) * multipliers[size_str[-1]]
    return int(size_str)


def setup_logging(config: Config) -> None:
    """Configure logging based on config file settings."""
    log_cfg = config.get("logging", {})
    level_str = log_cfg.get("level", "info").upper()
    log_file = log_cfg.get("file", "/var/log/sendq-mta/sendq-mta.log")
    max_size = _parse_size(log_cfg.get("max_size", "100M"))
    max_files = log_cfg.get("max_files", 30)
    fmt = log_cfg.get("format", "json")

    level = getattr(logging, level_str, logging.INFO)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Choose formatter
    if fmt == "json":
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()

    # Console handler (for foreground mode)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(TextFormatter())
    root_logger.addHandler(console_handler)

    # File handler
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=max_files,
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except (PermissionError, OSError) as e:
        logging.warning("Cannot write to log file %s: %s", log_file, e)

    # Syslog handler
    syslog_cfg = log_cfg.get("syslog", {})
    if syslog_cfg.get("enabled"):
        facility_name = syslog_cfg.get("facility", "mail").upper()
        facility = getattr(
            logging.handlers.SysLogHandler,
            f"LOG_{facility_name}",
            logging.handlers.SysLogHandler.LOG_MAIL,
        )
        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address="/dev/log", facility=facility
            )
            syslog_handler.setLevel(level)
            syslog_handler.setFormatter(
                logging.Formatter("sendq-mta[%(process)d]: %(message)s")
            )
            root_logger.addHandler(syslog_handler)
        except Exception as e:
            logging.warning("Cannot setup syslog: %s", e)

    # Suppress noisy libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("aiosmtpd").setLevel(logging.WARNING)

    logging.info(
        "Logging initialized: level=%s file=%s format=%s",
        level_str, log_file, fmt,
    )
