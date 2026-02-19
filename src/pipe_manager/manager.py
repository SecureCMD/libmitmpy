import logging
from collections import defaultdict
from queue import Empty, Queue
from threading import Lock
from typing import Any

from core import AutoThread
from interceptors import BaseInterceptor, DummyInterceptor, HTTPInterceptor
from net.socks import Pipe

logger = logging.getLogger(__name__)


class PipeManager:
    def __init__(self):
        self.pipes: dict[Pipe, dict] = defaultdict(
            lambda: {
                "pending_outgoing": 0,
                "pending_incoming": 0,
            }
        )
        self._pipes_lock = Lock()
        self._event_queue: Queue[tuple[str, Pipe, dict[str, Any]]] = Queue()
        self._halt = False

        self.interceptors: list[BaseInterceptor] = [
            DummyInterceptor(),
            HTTPInterceptor(),
        ]  # TODO: this should be per pipe

        # Start event dispatcher thread
        self._dispatcher = AutoThread(target=self._dispatch_events, name="EventDispatcher")

    def _pending_outgoing_tasks(self, pipe):
        with self._pipes_lock:
            return self.pipes[pipe]["pending_outgoing"] > 0

    def _pending_incoming_tasks(self, pipe):
        with self._pipes_lock:
            return self.pipes[pipe]["pending_incoming"] > 0

    def _pending_tasks(self, pipe):
        return self._pending_outgoing_tasks(pipe) or self._pending_incoming_tasks(pipe)

    def _dispatch_events(self):
        while not self._halt:
            try:
                event_type, pipe, kwargs = self._event_queue.get(timeout=0.5)
                logger.debug(f"Dispatching {event_type} for pipe {pipe}")

                match event_type:
                    case "pipe_finished":
                        logger.debug("Attempting to stop pipe...")
                        if not self._pending_tasks(pipe):
                            self.stop(pipe)
                            self.pipes.pop(pipe)
                        else:
                            logger.debug("Pipe hasn't been drained yet, rescheduling removal...")
                            self._enqueue_event(event_type, pipe)

                    case "no_more_outgoing_data_available":
                        logger.debug("Attempting to close upstream of pipe...")
                        if not self._pending_outgoing_tasks(pipe):
                            pipe.close_upstream()
                        else:
                            logger.debug("Pipe hasn't been drained yet, rescheduling closing upstream...")
                            self._enqueue_event(event_type, pipe)

                    case "no_more_incoming_data_available":
                        logger.debug("Attempting to close downstream of pipe...")
                        if not self._pending_incoming_tasks(pipe):
                            pipe.close_downstream()
                        else:
                            logger.debug("Pipe hasn't been drained yet, rescheduling closing downstream...")
                            self._enqueue_event(event_type, pipe)

                    case "outgoing_data_available":
                        with pipe.outgoing_locked():
                            for interceptor in self.interceptors:
                                try:
                                    interceptor.process_outgoing_data(pipe, **kwargs)
                                except Exception:
                                    logger.exception("Interceptor %s crashed on outgoing data", type(interceptor).__name__)
                            with self._pipes_lock:
                                self.pipes[pipe]["pending_outgoing"] -= 1

                    case "incoming_data_available":
                        with pipe.incoming_locked():
                            for interceptor in self.interceptors:
                                try:
                                    interceptor.process_incoming_data(pipe, **kwargs)
                                except Exception:
                                    logger.exception("Interceptor %s crashed on incoming data", type(interceptor).__name__)
                            with self._pipes_lock:
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

        # Drain remaining items so stop_all()'s queue.join() doesn't deadlock.
        while True:
            try:
                self._event_queue.get_nowait()
                self._event_queue.task_done()
            except Empty:
                break

    def _enqueue_event(self, event_type: str, pipe: Pipe, **kwargs):
        logger.debug(f"Enqueuing {event_type} for pipe {pipe}")

        match event_type:
            case "outgoing_data_available":
                with self._pipes_lock:
                    self.pipes[pipe]["pending_outgoing"] += 1
            case "incoming_data_available":
                with self._pipes_lock:
                    self.pipes[pipe]["pending_incoming"] += 1

        self._event_queue.put((event_type, pipe, kwargs))

    def add(self, pipe):
        logger.debug(f"Adding pipe {pipe} to pipe manager")

        logger.debug(f"Subscribing to events of pipe {pipe}")
        for event in [
            "pipe_finished",
            "no_more_outgoing_data_available",
            "no_more_incoming_data_available",
            "outgoing_data_available",
            "incoming_data_available",
        ]:
            pipe.on(event, lambda p, e=event, **kw: self._enqueue_event(e, p, **kw))

        logger.info(f"Starting pipe {pipe}")
        pipe.start()

    def stop(self, pipe):
        logger.info(f"Closing pipe {pipe}")
        pipe.stop()

        logger.debug(f"Unsubscribing from events of pipe {pipe}")
        pipe.off("pipe_finished")
        pipe.off("outgoing_data_available")
        pipe.off("incoming_data_available")

        logger.debug(f"Removing pipe {pipe} from pipe manager")

    def stop_all(self):
        if self._halt:
            return

        self._halt = True

        for pipe in list(self.pipes.keys()):
            self.stop(pipe)

        logger.debug("Draining all pipes...")
        self._event_queue.join()
        self._dispatcher.join()
