"""
Structured logging.

* Console output: one JSON object per line (easy to grep / ship to a log stack)
  or a readable single-line format in development.
* ``RingBufferHandler`` keeps the last N records in memory so the dashboard's
  Logs page can show real backend logs without a log database.
"""
from __future__ import annotations

import collections
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional

_STD_ATTRS = set(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime"}


def _extras(record: logging.LogRecord) -> Dict[str, object]:
    return {k: v for k, v in record.__dict__.items() if k not in _STD_ATTRS and not k.startswith("_")}


def record_to_dict(record: logging.LogRecord) -> Dict[str, object]:
    data: Dict[str, object] = {
        "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
        "level": record.levelname,
        "logger": record.name,
        "message": record.getMessage(),
    }
    extra = _extras(record)
    if extra:
        data["context"] = {k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
                           for k, v in extra.items()}
    if record.exc_info:
        data["exception"] = logging.Formatter().formatException(record.exc_info).splitlines()[-1]
    return data


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(record_to_dict(record), ensure_ascii=False, default=str)


class ReadableFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<7} {record.name}: {record.getMessage()}"
        extra = _extras(record)
        if extra:
            base += "  " + " ".join(f"{k}={v}" for k, v in extra.items())
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


class RingBufferHandler(logging.Handler):
    def __init__(self, capacity: int = 1000):
        super().__init__()
        self.buffer: Deque[Dict[str, object]] = collections.deque(maxlen=capacity)
        self._lock_rb = threading.Lock()
        self._seq = 0

    def emit(self, record: logging.LogRecord) -> None:
        try:
            item = record_to_dict(record)
            with self._lock_rb:
                self._seq += 1
                item["id"] = self._seq
                self.buffer.append(item)
        except Exception:  # never let logging break the app
            pass

    def records(self, level: Optional[str] = None, logger_prefix: Optional[str] = None,
                after_id: int = 0, limit: int = 200) -> List[Dict[str, object]]:
        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        min_idx = levels.index(level.upper()) if level and level.upper() in levels else 0
        with self._lock_rb:
            items = list(self.buffer)
        out = [r for r in items
               if levels.index(str(r["level"])) >= min_idx
               and (not logger_prefix or str(r["logger"]).startswith(logger_prefix))
               and int(r["id"]) > after_id]
        return out[-limit:]


ring_buffer = RingBufferHandler()


def build_logging_config(json_output: bool, level: str = "INFO") -> dict:
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {"()": "core.logs.JSONFormatter"},
            "readable": {"()": "core.logs.ReadableFormatter"},
        },
        "handlers": {
            "console": {"class": "logging.StreamHandler", "formatter": "json" if json_output else "readable"},
            "ring": {"()": "core.logs.get_ring_buffer"},
        },
        "root": {"handlers": ["console", "ring"], "level": level},
        "loggers": {
            "django": {"level": "INFO"},
            "django.server": {"level": "WARNING"},
            "httpx": {"level": "WARNING"},
            "httpcore": {"level": "WARNING"},
            "mcp": {"level": "WARNING"},
        },
    }


def get_ring_buffer() -> RingBufferHandler:
    return ring_buffer
