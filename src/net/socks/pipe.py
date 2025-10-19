import logging
import socket
import ssl

from core import AutoThread, SafeSocket
from mixins import EventMixin

BUFSIZE = 2048

logger = logging.getLogger(__name__)

class Pipe(EventMixin):
    def __init__(self, client_socket: SafeSocket, target_socket: SafeSocket):
        super().__init__()

        self._halt = False

        self._downstream_socket = client_socket
        self._upstream_socket = target_socket

        self._outgoing_buffer = bytearray()
        self._incoming_buffer = bytearray()

    def start(self):
        logger.info(f"Creating MITM pipe: {hex(id(self))}")

        t1 = AutoThread(target=self._read_from_downstream, args=(), tname="->")
        t2 = AutoThread(target=self._read_from_upstream, args=(), tname="<-")
        t1.join()
        t2.join()

        self._downstream_socket.close()
        self._upstream_socket.close()

        self.emit("pipe_closed", self)
        logger.info(f"Removing MITM pipe: {hex(id(self))}")

    def stop(self):
        self._halt = True

        self._downstream_socket.shutdown(socket.SHUT_RDWR)
        self._upstream_socket.shutdown(socket.SHUT_RDWR)

    def _read_from_downstream(self):
        try:
            while not self._halt:
                logger.debug("Receiving data from local socket...")
                data = self._downstream_socket.recv(BUFSIZE)
                logger.debug(f"Received {len(data)} bytes.")

                if not data:
                    logger.debug("No more data to receive, closing local socket!")
                    self.emit("outgoing_data_available", self, eof=True)
                    self._upstream_socket.shutdown(socket.SHUT_WR)
                    break

                self._outgoing_buffer.extend(data)
                self.emit("outgoing_data_available", self)

        except (OSError, ssl.SSLError):
            logger.error("Something failed, killing MITM pipe...")
            self.stop()

    def _read_from_upstream(self):
        try:
            while not self._halt:
                logger.debug("Receiving data from remote socket...")
                data = self._upstream_socket.recv(BUFSIZE)
                logger.debug(f"Received {len(data)} bytes.")

                if not data:
                    logger.debug("No more data to receive, closing remote socket!")
                    self.emit("incoming_data_available", self, eof=True)
                    self._downstream_socket.shutdown(socket.SHUT_WR)
                    break

                self._incoming_buffer.extend(data)
                self.emit("incoming_data_available", self)

        except (OSError, ssl.SSLError):
            logger.error("Something failed, killing MITM pipe...")
            self.stop()

    def get_incoming_buffer(self) -> bytearray:
        return self._incoming_buffer

    def get_outgoing_buffer(self) -> bytearray:
        return self._outgoing_buffer

    def write_to_upstream(self, buf):
        logger.debug(f"Writing {len(buf)} bytes to remote socket...")
        self._upstream_socket.sendall(buf)

    def write_to_downstream(self, buf):
        logger.debug(f"Writing {len(buf)} bytes to local socket...")
        self._downstream_socket.sendall(buf)