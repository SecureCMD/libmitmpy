import logging
from threading import RLock

logger = logging.getLogger(__name__)


class EventMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._events = {}
        self._events_lock = RLock()

    def on(self, event, callback):
        with self._events_lock:
            self._events.setdefault(event, []).append(callback)

    def off(self, event, callback):
        with self._events_lock:
            self._events.get(event, []).remove(callback)

    def emit(self, event, *args, **kwargs):
        # Lock, copy callbacks and unlock so that we don't block the entire
        # world while iterating over the callbacks...
        with self._events_lock:
            callbacks = list(self._events.get(event, []))

        for cb in callbacks:
            try:
                cb(*args, **kwargs)
            except Exception:
                logger.exception(f"Callback '{cb}' of '{event}' crashed")
