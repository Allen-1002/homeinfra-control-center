"""Background collection scheduler.

Periodically collects device metrics on the backend, independent of whether a
frontend page is open. Each enabled device is collected no more often than its
own ``collection_interval``; the global ``default_collection_interval`` is the
fallback for devices without an explicit interval.

This runs in a single daemon thread started by ``create_server``. It is NOT
started in tests (which construct ``HomeInfraApp`` directly), so it cannot
interfere with the test suite.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

logger = logging.getLogger("homeinfra.scheduler")


class CollectionScheduler:
    def __init__(self, app, *, tick_interval: int = 10, timeout: int = 10) -> None:
        self.app = app
        self.tick_interval = max(1, tick_interval)
        self.timeout = max(3, timeout)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="hinfra-collector"
        )
        self._thread.start()
        logger.info("collection scheduler started (tick=%ss)", self.tick_interval)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        # Don't collect immediately on boot — give the server a tick to settle
        # and avoid a thundering herd against all devices at startup.
        if self._stop.wait(self.tick_interval):
            return
        while not self._stop.is_set():
            try:
                self.app.service.monitoring.run_scheduled_collection(timeout=self.timeout)
            except Exception as exc:  # never let the loop die
                logger.warning("scheduled collection error: %s", exc)
            if self._stop.wait(self.tick_interval):
                break


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
