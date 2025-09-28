import logging
import socket
import ssl

logger = logging.getLogger(__name__)


class SafeSocket:
    def __init__(self, sock: socket.socket | ssl.SSLSocket):
        self._sock = sock
        self._closed = False

    def shutdown(self, *args, **kwargs):
        if not self._closed:
            try:
                self._sock.shutdown(*args, **kwargs)
            except OSError:
                pass
            self._closed = True

    def close(self):
        if not self._closed:
            self.shutdown(socket.SHUT_RDWR)
            try:
                self._sock.close()
            except OSError:
                pass
            self._closed = True

    def accept(self, *args, **kwargs):
        return self._sock.accept(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        # TODO: safe sendall?
        return self._sock.sendall(*args, *kwargs)

    def connect(self, *args, **kwargs):
        return self._sock.connect(*args, **kwargs)

    def listen(self, *args, **kwargs):
        return self._sock.listen(*args, **kwargs)

    def setsockopt(self, *args, **kwargs):
        return self._sock.setsockopt(*args, **kwargs)

    def bind(self, *args, **kwargs):
        return self._sock.bind(*args, **kwargs)

    def settimeout(self, *args, **kwargs):
        return self._sock.settimeout(*args, **kwargs)

    def getsockname(self, *args, **kwargs):
        return self._sock.getsockname(*args, **kwargs)

    def setblocking(self, *args, **kwargs):
        return self._sock.setblocking(*args, **kwargs)

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
                chunk = self._sock.recv(n - len(buf))
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
        return getattr(self._sock, name)