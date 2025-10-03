from __future__ import annotations

import logging
import socket
import ssl
from typing import Tuple

logger = logging.getLogger(__name__)

TIMEOUT_SOCKET = 5

class SafeSocket:
    def __init__(self, socket: socket.socket | ssl.SSLSocket):
        self._socket = socket
        self._closed = False

    @staticmethod
    def create():
        """ Create an INET, STREAMing socket """
        try:
            _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _socket = SafeSocket(_socket)
            _socket.settimeout(TIMEOUT_SOCKET)
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

    def sendall(self, *args, **kwargs):
        # TODO: safe sendall?
        return self._socket.sendall(*args, *kwargs)

    def connect(self, *args, **kwargs):
        return self._socket.connect(*args, **kwargs)

    def listen(self, *args, **kwargs):
        return self._socket.listen(*args, **kwargs)

    def setsockopt(self, *args, **kwargs):
        return self._socket.setsockopt(*args, **kwargs)

    def bind(self, *args, **kwargs):
        return self._socket.bind(*args, **kwargs)

    def settimeout(self, *args, **kwargs):
        return self._socket.settimeout(*args, **kwargs)

    def getsockname(self, *args, **kwargs):
        return self._socket.getsockname(*args, **kwargs)

    def setblocking(self, *args, **kwargs):
        return self._socket.setblocking(*args, **kwargs)

    def recv(self, *args, **kwargs):
        return self._socket.recv(*args, **kwargs)

    def recvall(self, n: int) -> bytes:
        """
        Read exactly n bytes from the underlying socket.
        Returns the bytes read; if EOF is reached before `n` bytes, returns fewer bytes.
        Raises socket.timeout / OSError as propagated by the underlying socket.
        Handles SSLWantRead/Write by retrying.
        """
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self._socket.recv(n - len(buf))
            except Exception as exc:
                logger.exception()
                # handle non-blocking SSL intermediate exceptions by retrying
                try:
                    want_read = isinstance(exc, ssl.SSLWantReadError)
                    want_write = isinstance(exc, ssl.SSLWantWriteError)
                except Exception:
                    want_read = want_write = False

                if want_read or want_write:
                    continue
                # re-raise socket.timeout and other OSErrors
                raise
            if not chunk:
                # EOF
                break
            buf.extend(chunk)
        return bytes(buf)

    def peekall(self, n: int) -> bytes:
        """
        Peek exactly n bytes from the underlying socket.
        Returns the bytes read; if EOF is reached before `n` bytes, returns fewer bytes.
        Raises socket.timeout / OSError as propagated by the underlying socket.
        Handles SSLWantRead/Write by retrying.
        """
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self._socket.recv(n - len(buf), socket.MSG_PEEK)
            except Exception as exc:
                logger.exception()
                # handle non-blocking SSL intermediate exceptions by retrying
                try:
                    want_read = isinstance(exc, ssl.SSLWantReadError)
                    want_write = isinstance(exc, ssl.SSLWantWriteError)
                except Exception:
                    want_read = want_write = False

                if want_read or want_write:
                    continue
                # re-raise socket.timeout and other OSErrors
                raise
            if not chunk:
                # EOF
                break
            buf.extend(chunk)
        return bytes(buf)

    # proxy to the real socket for everything else
    def __getattr__(self, name):
        return getattr(self._socket, name)