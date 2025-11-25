import logging
import socket
import ssl
from contextlib import contextmanager
from threading import Lock

from core import SafeConnection, SafeSocket, Thread
from mixins import EventMixin

BUFSIZE = 2048

logger = logging.getLogger(__name__)


class Pipe(EventMixin):
    def __init__(
        self,
        downstream: SafeSocket | SafeConnection,
        upstream: SafeSocket | SafeConnection,
    ):
        super().__init__()

        self._halt = False

        self._downstream = downstream
        self._upstream = upstream

        self._outgoing_buffer = bytearray()
        self._incoming_buffer = bytearray()

        self._outgoing_lock = Lock()
        self._incoming_lock = Lock()

        logger.info(f"Created pipe {self} for sockets [{downstream}, {upstream}]")

    def __del__(self):
        logger.debug(f"Closing up/downstream sockets of pipe {self}")
        self._downstream.shutdown(socket.SHUT_RDWR)
        self._upstream.shutdown(socket.SHUT_RDWR)

        self._downstream.close()
        self._upstream.close()

    def __str__(self):
        return f"{hex(id(self))}"

    def start(self):
        t1 = Thread(target=self._read_from_downstream, args=(), name="->")
        t2 = Thread(target=self._read_from_upstream, args=(), name="<-")

        logger.info(f"Created stream threads [{t1}, {t2}] for pipe {self}")

        t1.start()
        t2.start()

        t1.join()
        t2.join()

        self.emit("pipe_finished", self)

    def stop(self):
        self._halt = True

    def close_downstream(self):
        self._downstream.shutdown(socket.SHUT_WR)

    def close_upstream(self):
        self._upstream.shutdown(socket.SHUT_WR)

    def _read_from_downstream(self):
        try:
            while not self._halt:
                logger.debug("Reading data from local socket...")
                data = self._downstream.recv(BUFSIZE)
                logger.debug(f"Read {len(data)} bytes.")

                if not data:
                    logger.debug("No more data to read from downstream!")
                    self.emit("outgoing_data_available", self, eof=True)
                    self.emit("no_more_outgoing_data_available", self)
                    break

                with self.outgoing_locked() as buf:
                    buf.extend(data)
                self.emit("outgoing_data_available", self)

        except (OSError, ssl.SSLError):
            logger.error("Something failed, killing pipe...")
            self.emit("outgoing_data_available", self, eof=True)

    def _read_from_upstream(self):
        try:
            while not self._halt:
                logger.debug("Reading data from remote socket...")
                data = self._upstream.recv(BUFSIZE)
                logger.debug(f"Read {len(data)} bytes.")

                if not data:
                    logger.debug("No more data to read from upstream!")
                    self.emit("incoming_data_available", self, eof=True)
                    self.emit("no_more_incoming_data_available", self)
                    break

                with self.incoming_locked() as buf:
                    buf.extend(data)
                self.emit("incoming_data_available", self)

        except (OSError, ssl.SSLError):
            logger.error("Something failed, killing pipe...")
            self.emit("incoming_data_available", self, eof=True)

    def get_incoming_buffer(self) -> bytearray:
        return self._incoming_buffer

    def get_outgoing_buffer(self) -> bytearray:
        return self._outgoing_buffer

    def write_to_upstream(self, buf):
        logger.debug(f"Writing {len(buf)} bytes to remote socket...")
        self._upstream.sendall(buf)

    def write_to_downstream(self, buf):
        logger.debug(f"Writing {len(buf)} bytes to local socket...")
        self._downstream.sendall(buf)

    @contextmanager
    def outgoing_locked(self):
        self._outgoing_lock.acquire()
        try:
            yield self._outgoing_buffer
        finally:
            self._outgoing_lock.release()

    @contextmanager
    def incoming_locked(self):
        self._incoming_lock.acquire()
        try:
            yield self._incoming_buffer
        finally:
            self._incoming_lock.release()