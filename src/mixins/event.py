import logging
from threading import RLock

logger = logging.getLogger(__name__)


class EventMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._events = {}
        self._events_lock = RLock()

    def on(self, event, callback):
        logger.debug(f"Subscribing to {event=}")
        with self._events_lock:
            self._events.setdefault(event, []).append(callback)

    def off(self, event, callback=None):
        logger.debug(f"Unsubscribing from {event=}")
        with self._events_lock:
            if callback:
                self._events.get(event, []).remove(callback)
            else:
                self._events.pop(event)

    def emit(self, event, *args, **kwargs):
        logger.debug(f"emitting {event=}")
        # Lock, copy callbacks and unlock so that we don't block the entire
        # world while iterating over the callbacks...
        with self._events_lock:
            callbacks = list(self._events.get(event, []))

        for cb in callbacks:
            try:
                cb(*args, **kwargs)
            except Exception as ex:
                logger.error(f"Callback '{cb}' of '{event}' crashed: {ex}")
