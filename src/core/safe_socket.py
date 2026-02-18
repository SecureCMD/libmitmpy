from __future__ import annotations

import logging
import socket
import ssl
from typing import Tuple

logger = logging.getLogger(__name__)


class SafeSocket:
    def __init__(self, socket: socket.socket | ssl.SSLSocket):
        self._socket = socket
        self._closed = False

    def __str__(self):
        return f"{hex(id(self))}"

    @staticmethod
    def create():
        """Create an INET, STREAMing socket"""
        try:
            _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _socket = SafeSocket(_socket)
            _socket.setblocking(1)
            _socket.settimeout(None)
            _socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except socket.error:
            logger.exception("Failed to create socket")
            raise Exception
        return _socket

    def shutdown(self, *args, **kwargs):
        if not self._closed:
            try:
                self._socket.shutdown(*args, **kwargs)
            except OSError:
                pass
            self._closed = True

    def close(self):
        if not self._closed:
            self.shutdown(socket.SHUT_RDWR)
            try:
                self._socket.close()
            except OSError:
                pass
            self._closed = True

    def accept(self, *args, **kwargs) -> Tuple[SafeSocket, Tuple[bytes, int]]:
        conn_socket, addr = self._socket.accept(*args, **kwargs)
        return SafeSocket(conn_socket), addr

    def sendall(self, data: bytes, flags: int = 0):
        if flags:
            view = memoryview(data)
            total = 0
            while total < len(view):
                sent = self._socket.send(view[total:], flags)
                if sent == 0:
                    raise ConnectionResetError(f"Sent less bytes than expected ({total}/{len(data)}).")
                total += sent
        else:
            self._socket.sendall(data)

    def connect(self, *args, **kwargs):
        return self._socket.connect(*args, **kwargs)

    def listen(self, *args, **kwargs):
        return self._socket.listen(*args, **kwargs)

    def setsockopt(self, *args, **kwargs):
        return self._socket.setsockopt(*args, **kwargs)

    def bind(self, *args, **kwargs):
        return self._socket.bind(*args, **kwargs)

    def getsockname(self, *args, **kwargs):
        return self._socket.getsockname(*args, **kwargs)

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        return self._socket.recv(bufsize, flags)

    def recvall(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._socket.recv(n - len(buf))
            if not chunk:
                raise ConnectionResetError(f"Received less bytes than expected ({len(buf)}/{n}).")
            buf.extend(chunk)
        return bytes(buf)

    def peekall(self, n: int) -> bytes:
        # Note: this blocks until some data is available, or EOF.
        # If you need a bound, temporarily set a timeout around this call.
        # MSG_PEEK always returns data from the start of the socket buffer,
        # so we must always request the full n bytes and loop until we get them.
        while True:
            chunk = self._socket.recv(n, socket.MSG_PEEK)
            if not chunk:
                raise ConnectionResetError(f"Received less bytes than expected (0/{n}).")
            if len(chunk) >= n:
                return bytes(chunk[:n])
            # Kernel returned fewer bytes than requested; data is still arriving.
            # Loop and peek again until the full n bytes are available.

    # proxy to the real socket for everything else
    def __getattr__(self, name):
        return getattr(self._socket, name)
