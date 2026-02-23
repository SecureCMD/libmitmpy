import logging
from collections import defaultdict
from queue import Empty, Queue
from threading import Lock
from typing import Any, Optional

from core import AutoThread
from handlers import ConnectionHandler
from net.socks import Pipe
from traffic_logger import TrafficLogger

logger = logging.getLogger(__name__)


class PipeManager:
    def __init__(self, traffic_logger: TrafficLogger):
        self._traffic_logger = traffic_logger
        self.pipes: dict[Pipe, dict] = defaultdict(
            lambda: {
                "pending_outgoing": 0,
                "pending_incoming": 0,
            }
        )
        self._pipes_lock = Lock()
        self._pipe_handlers: dict[Pipe, ConnectionHandler] = {}
        self._event_queue: Queue[tuple[str, Pipe, dict[str, Any]]] = Queue()
        self._halt = False

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
            except Empty:
                continue

            try:
                logger.debug(f"Dispatching {event_type} for pipe {pipe}")

                match event_type:
                    case "pipe_finished":
                        logger.debug("Attempting to stop pipe...")
                        if not self._pending_tasks(pipe):
                            handler = self._pipe_handlers.pop(pipe, None)
                            if handler is not None:
                                try:
                                    handler.on_disconnect()
                                except Exception as ex:
                                    logger.error(f"Handler crashed in on_disconnect for pipe {pipe}: {ex}")
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
                        try:
                            data_chunk = kwargs.pop("data", None)
                            if data_chunk is not None:
                                try:
                                    self._traffic_logger.log_outgoing(pipe, data_chunk)
                                except Exception as ex:
                                    logger.error(f"TrafficLogger failed on outgoing data for pipe {pipe}: {ex}")

                            eof = kwargs.get("eof", False)
                            data = data_chunk or b""
                            handler = self._pipe_handlers.get(pipe)

                            if handler is not None:
                                try:
                                    result = handler.on_outgoing(data, eof)
                                except Exception as ex:
                                    logger.error(f"Handler crashed in on_outgoing for pipe {pipe}: {ex}")
                                    result = None

                                # Clear the pipe buffer — the handler owns processing from here
                                with pipe.outgoing_locked() as buf:
                                    buf.clear()

                                if result is None:
                                    # Pass through: forward original data unchanged
                                    if data:
                                        pipe.write_to_upstream(data)
                                elif result:
                                    # Forward the handler's modified data
                                    pipe.write_to_upstream(result)
                                # b"" → swallow (handler buffering or intentional drop)
                            else:
                                # No handler: pass through directly
                                with pipe.outgoing_locked() as buf:
                                    if buf:
                                        pipe.write_to_upstream(bytes(buf))
                                        buf.clear()
                        except Exception as ex:
                            logger.error(f"Error processing outgoing_data_available for pipe {pipe}: {ex}")
                        finally:
                            with self._pipes_lock:
                                self.pipes[pipe]["pending_outgoing"] -= 1

                    case "incoming_data_available":
                        try:
                            data_chunk = kwargs.pop("data", None)
                            if data_chunk is not None:
                                try:
                                    self._traffic_logger.log_incoming(pipe, data_chunk)
                                except Exception as ex:
                                    logger.error(f"TrafficLogger failed on incoming data for pipe {pipe}: {ex}")

                            eof = kwargs.get("eof", False)
                            data = data_chunk or b""
                            handler = self._pipe_handlers.get(pipe)

                            if handler is not None:
                                try:
                                    result = handler.on_incoming(data, eof)
                                except Exception as ex:
                                    logger.error(f"Handler crashed in on_incoming for pipe {pipe}: {ex}")
                                    result = None

                                with pipe.incoming_locked() as buf:
                                    buf.clear()

                                if result is None:
                                    if data:
                                        pipe.write_to_downstream(data)
                                elif result:
                                    pipe.write_to_downstream(result)
                            else:
                                with pipe.incoming_locked() as buf:
                                    if buf:
                                        pipe.write_to_downstream(bytes(buf))
                                        buf.clear()
                        except Exception as ex:
                            logger.error(f"Error processing incoming_data_available for pipe {pipe}: {ex}")
                        finally:
                            with self._pipes_lock:
                                self.pipes[pipe]["pending_incoming"] -= 1

                    case _:
                        logger.warning(f"Unknown event type: {event_type}")

            except Exception as e:
                if not isinstance(e, TimeoutError):
                    logger.error("Error dispatching event")
            finally:
                self._event_queue.task_done()
                pipe = None  # this will force the GC to collect the pipe object

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

    def add(self, pipe: Pipe, handler: Optional[ConnectionHandler] = None):
        logger.debug(f"Adding pipe {pipe} to pipe manager")

        if handler is not None:
            self._pipe_handlers[pipe] = handler

        logger.debug(f"Subscribing to events of pipe {pipe}")
        for event in [
            "pipe_finished",
            "no_more_outgoing_data_available",
            "no_more_incoming_data_available",
            "outgoing_data_available",
            "incoming_data_available",
        ]:
            pipe.on(event, lambda p, e=event, **kw: self._enqueue_event(e, p, **kw))

        self._traffic_logger.register_pipe(pipe)

        if handler is not None:
            try:
                handler.on_connect()
            except Exception:
                logger.error("Handler crashed in on_connect for pipe {pipe}: {ex}")

        logger.info(f"Starting pipe {pipe}")
        pipe.start()

    def stop(self, pipe):
        logger.info(f"Closing pipe {pipe}")
        pipe.stop()

        logger.debug(f"Unsubscribing from events of pipe {pipe}")
        pipe.off("pipe_finished")
        pipe.off("outgoing_data_available")
        pipe.off("incoming_data_available")

        self._traffic_logger.unregister_pipe(pipe)

        logger.debug(f"Removing pipe {pipe} from pipe manager")

    def stop_all(self):
        if self._halt:
            return

        self._halt = True

        for pipe in list(self.pipes.keys()):
            self.stop(pipe)

        self._dispatcher.join()
