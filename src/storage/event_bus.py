import asyncio
import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Set


class EventBus:
    def __init__(self) -> None:
        self._subscribers: Set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def publish(self, event_type: str, payload: Dict[str, Any] | None = None) -> None:
        message = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload or {},
        }
        encoded = json.dumps(message, default=str)
        loop = self._loop
        if loop and loop.is_running():
            loop.call_soon_threadsafe(self._publish_now, encoded)
        else:
            self._publish_now(encoded)

    def _publish_now(self, encoded: str) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(encoded)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                    queue.put_nowait(encoded)
                except asyncio.QueueEmpty:
                    pass


event_bus = EventBus()
