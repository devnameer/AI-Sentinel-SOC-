"""
Live stream worker — a single background thread that ingests a small batch every
N seconds while "streaming" is switched on from the dashboard. Good enough for a
demo; a production system would use a task queue (Celery/RQ) instead.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("soc.stream")


class StreamWorker:
    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.source = "replay"
        self.interval = 5.0
        self.batch_size = 3
        self.started_at: Optional[str] = None
        self.batches = 0
        self.last_error = ""

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, source: str, interval: float, batch_size: int) -> None:
        if self.running:
            self.stop()
        self.source, self.interval, self.batch_size = source, interval, batch_size
        self._stop.clear()
        self.batches, self.last_error = 0, ""
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._thread = threading.Thread(target=self._loop, name="soc-stream", daemon=True)
        self._thread.start()
        logger.info("Stream started", extra={"source": source, "interval": interval, "batch": batch_size})

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 60)
        self._thread = None
        logger.info("Stream stopped", extra={"batches": self.batches})

    def _loop(self) -> None:
        from django.db import close_old_connections

        from api.services import ingest

        while not self._stop.is_set():
            try:
                close_old_connections()
                ingest(self.source, count=self.batch_size)
                self.batches += 1
            except Exception as exc:  # keep streaming; surface the error in /system/health
                self.last_error = f"{type(exc).__name__}: {exc}"
                logger.warning("Stream batch failed", extra={"error": self.last_error})
            self._stop.wait(self.interval)

    def status(self) -> dict:
        return {"status": "running" if self.running else "stopped", "source": self.source,
                "interval_seconds": self.interval, "batch_size": self.batch_size, "batches": self.batches,
                "started_at": self.started_at if self.running else None, "last_error": self.last_error}


stream_worker = StreamWorker()
