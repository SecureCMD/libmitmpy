class EventMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._events = {}

    def on(self, event, callback):
        self._events.setdefault(event, []).append(callback)

    def off(self, event, callback=None):
        if callback is None:
            self._events.pop(event, None)
        else:
            self._events.get(event, []).remove(callback)

    def emit(self, event, *args, **kwargs):
        for cb in self._events.get(event, []):
            cb(*args, **kwargs)