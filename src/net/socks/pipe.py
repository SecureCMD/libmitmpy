import logging
import socket
import ssl

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

        logger.info(f"Created pipe {self} for sockets [{downstream}, {upstream}]")

    def __str__(self):
        return f"{hex(id(self))}"

    def start(self):
        self.t1 = Thread(target=self._read_from_downstream, args=(), name="->")
        self.t2 = Thread(target=self._read_from_upstream, args=(), name="<-")

        logger.info(f"Created stream threads [{self.t1}, {self.t2}] for pipe {self}")

        self.t1.start()
        self.t2.start()

        self.t1.join()
        self.t2.join()

        self.emit("pipe_finished", self)

    def stop(self):
        self._halt = True

        self._downstream.shutdown(socket.SHUT_RDWR)
        self._upstream.shutdown(socket.SHUT_RDWR)

        self._downstream.close()
        self._upstream.close()

    def _read_from_downstream(self):
        try:
            while not self._halt:
                logger.debug("Receiving data from local socket...")
                data = self._downstream.recv(BUFSIZE)
                logger.debug(f"Received {len(data)} bytes.")

                if not data:
                    logger.debug("No more data to receive, closing local socket!")
                    self.emit("outgoing_data_available", self, eof=True)
                    self._upstream.shutdown(socket.SHUT_WR)
                    break

                self.extend_outgoing_buffer(data)
                self.emit("outgoing_data_available", self)

        except (OSError, ssl.SSLError):
            logger.error("Something failed, killing pipe...")
            self.stop()

    def _read_from_upstream(self):
        try:
            while not self._halt:
                logger.debug("Receiving data from remote socket...")
                data = self._upstream.recv(BUFSIZE)
                logger.debug(f"Received {len(data)} bytes.")

                if not data:
                    logger.debug("No more data to receive, closing remote socket!")
                    self.emit("incoming_data_available", self, eof=True)
                    self._downstream.shutdown(socket.SHUT_WR)
                    break

                self.extend_incoming_buffer(data)
                self.emit("incoming_data_available", self)

        except (OSError, ssl.SSLError):
            logger.error("Something failed, killing pipe...")
            self.stop()

    def extend_incoming_buffer(self, data: bytearray) -> None:
        self._incoming_buffer.extend(data)

    def extend_outgoing_buffer(self, data: bytearray) -> None:
        self._outgoing_buffer.extend(data)

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
