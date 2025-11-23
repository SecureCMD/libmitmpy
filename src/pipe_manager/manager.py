import logging
from collections import defaultdict
from queue import Empty, Queue
from typing import Any

from core import AutoThread
from net.socks import Pipe
from parsers.dummy import DummyParser
from parsers.http import HTTPParser
from transformers.dummy import DummyTransformer
from transformers.http import HTTPTransformer

logger = logging.getLogger(__name__)


class PipeManager:
    def __init__(self):
        self.pipes: dict[Pipe, dict] = defaultdict(
            lambda: {
                "pending_outgoing": 0,
                "pending_incoming": 0,
            }
        )
        self._event_queue: Queue[tuple[str, Pipe, dict[str, Any]]] = Queue()
        self._halt = False

        self.parser = DummyParser()
        self.transformer = DummyTransformer()

        self.parser = HTTPParser()
        self.transformer = HTTPTransformer()

        # Start event dispatcher thread
        self._dispatcher = AutoThread(target=self._dispatch_events, name="EventDispatcher")

    def _dispatch_events(self):
        while not self._halt:
            try:
                event_type, pipe, kwargs = self._event_queue.get(timeout=0.5)
                logger.debug(f"Dispatching {event_type} for pipe {pipe}")

                match event_type:
                    case "pipe_finished":
                        logger.debug("Attempting to remove pipe...")
                        if self.pipes[pipe]["pending_outgoing"] + self.pipes[pipe]["pending_incoming"] == 0:
                            self.remove(pipe)
                        else:
                            logger.debug("Pipe hasn't been drained yet, rescheduling removal...")
                            self._enqueue_event(event_type, pipe)

                    case "outgoing_data_available":
                        with pipe.outgoing_locked():
                            # for parse, transformer in self.parsers_and_transformers:
                            self.process_outgoing_data(pipe, **kwargs)
                            self.pipes[pipe]["pending_outgoing"] -= 1

                    case "incoming_data_available":
                        with pipe.incoming_locked():
                            self.process_incoming_data(pipe, **kwargs)
                            self.pipes[pipe]["pending_incoming"] -= 1
                    case _:
                        logger.warning(f"Unknown event type: {event_type}")

                self._event_queue.task_done()

                pipe = None  # this will force the GC to collect the pipe object
            except Empty:
                continue
            except Exception as e:
                if not isinstance(e, TimeoutError):
                    logger.exception("Error dispatching event")

    def _enqueue_event(self, event_type: str, pipe: Pipe, **kwargs):
        logger.debug(f"Enqueuing {event_type} for pipe {pipe}")

        match event_type:
            case "outgoing_data_available":
                self.pipes[pipe]["pending_outgoing"] += 1
            case "incoming_data_available":
                self.pipes[pipe]["pending_incoming"] += 1

        self._event_queue.put((event_type, pipe, kwargs))

    def add(self, pipe):
        logger.debug(f"Adding pipe {pipe} to pipe manager")

        logger.debug(f"Subscribing to events of pipe {pipe}")
        pipe.on("pipe_finished", lambda p: self._enqueue_event("pipe_finished", p))
        pipe.on("outgoing_data_available", lambda p, **kw: self._enqueue_event("outgoing_data_available", p, **kw))
        pipe.on("incoming_data_available", lambda p, **kw: self._enqueue_event("incoming_data_available", p, **kw))

        logger.info(f"Starting pipe {pipe}")
        pipe.start()

    def stop_all(self):
        if self._halt:
            return

        self._halt = True

        for pipe in self.pipes.keys():
            logger.info(f"Stopping pipe {pipe}")
            pipe.stop()

        logger.debug("Draining all pipes...")
        self._event_queue.join()
        self._dispatcher.join()

    def remove(self, pipe):
        logger.info(f"Stopping pipe {pipe}")
        pipe.stop()

        logger.debug(f"Unsubscribing from events of pipe {pipe}")
        pipe.off("pipe_finished")
        pipe.off("outgoing_data_available")
        pipe.off("incoming_data_available")

        logger.debug(f"Removing pipe {pipe} from pipe manager")
        self.pipes.pop(pipe)

    def process_outgoing_data(self, pipe, eof=False):
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

    def process_incoming_data(self, pipe, eof=False):
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
