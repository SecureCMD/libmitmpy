import logging
from queue import Empty, Queue
from typing import List

from core import AutoThread
from net.socks import Pipe
from parsers.dummy import DummyParser
from parsers.http import HTTPParser
from transformers.dummy import DummyTransformer
from transformers.http import HTTPTransformer

logger = logging.getLogger(__name__)


class PipeManager:
    def __init__(self):
        self.pipes: List[Pipe] = []
        self._event_queue = Queue()
        self._halt = False

        self.parser = HTTPParser()
        self.transformer = HTTPTransformer()

        self.parser = DummyParser()
        self.transformer = DummyTransformer()

        # Start event dispatcher thread
        self._dispatcher = AutoThread(target=self._dispatch_events, name="EventDispatcher")

    def _dispatch_events(self):
        while not self._halt:
            try:
                event_type, pipe, kwargs = self._event_queue.get(timeout=0.5)
                logger.debug(f"Dispatching {event_type} for pipe {pipe}")

                match event_type:
                    case "pipe_finished":
                        self.remove(pipe)
                    case "outgoing_data_available":
                        self.flush_outgoing_data(pipe, **kwargs)
                    case "incoming_data_available":
                        self.flush_incoming_data(pipe, **kwargs)
                    case _:
                        logger.warning(f"Unknown event type: {event_type}")

                self._event_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                if not isinstance(e, TimeoutError):
                    logger.exception("Error dispatching event")

    def _enqueue_event(self, event_type: str, pipe: Pipe, **kwargs):
        logger.debug(f"Enqueuing {event_type} for pipe {pipe}")
        self._event_queue.put((event_type, pipe, kwargs))

    def add(self, pipe):
        self.pipes.append(pipe)
        pipe.on("pipe_finished", lambda p: self._enqueue_event("pipe_finished", p))
        pipe.on("outgoing_data_available", lambda p, **kw: self._enqueue_event("outgoing_data_available", p, **kw))
        pipe.on("incoming_data_available", lambda p, **kw: self._enqueue_event("incoming_data_available", p, **kw))

        logger.info(f"Starting pipe {pipe}")
        pipe.start()

    def stop_all(self):
        self._halt = True
        for pipe in self.pipes:
            logger.info(f"Stopping pipe {pipe}")
            pipe.stop()

        # Wait for event queue to drain
        self._event_queue.join()
        self._dispatcher.join()

    def remove(self, pipe):
        if pipe in self.pipes:
            logger.info(f"Stopping pipe {pipe}")
            pipe.stop()

            logger.info(f"Removing pipe {pipe}")
            self.pipes.remove(pipe)

    def flush_outgoing_data(self, pipe, eof=False):
        buf = pipe.get_outgoing_buffer()

        # Try to parse and forward as much as possible from buf
        while True:
            parsed, consumed = self.parser.parse(buf, eof=eof)

            if not parsed:
                break

            transformed = self.transformer.transform(parsed)

            pipe.write_to_upstream(transformed)
            del buf[:consumed]

        # Fallback: pass-through any leftover bytes so target isn’t starved
        if eof and buf:
            logger.debug(f"{len(buf)} bytes left in the buffer, sending to target socket...")
            pipe.write_to_upstream(buf)
            buf.clear()

    def flush_incoming_data(self, pipe, eof=False):
        buf = pipe.get_incoming_buffer()

        # Try to parse and forward as much as possible from buf
        while True:
            parsed, consumed = self.parser.parse(buf, eof=eof)

            if not parsed:
                break

            transformed = self.transformer.transform(parsed)

            pipe.write_to_downstream(transformed)
            del buf[:consumed]

        # Fallback: pass-through any leftover bytes so client isn’t starved
        if eof and buf:
            logger.debug(f"{len(buf)} bytes left in the buffer, sending to local socket...")
            pipe.write_to_downstream(buf)
            buf.clear()
