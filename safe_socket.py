import socket


class SafeSocket:
    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._closed = False
        self._shutdown = False

    def shutdown(self, how=socket.SHUT_RDWR):
        if not self._shutdown:
            try:
                self._sock.shutdown(how)
            except OSError:
                pass
            self._shutdown = True

    def close(self):
        if not self._closed:
            self.shutdown()
            try:
                self._sock.close()
            except OSError:
                pass
            self._closed = True

    # TODO: safe sendall?

    # proxy to the real socket for everything else
    def __getattr__(self, name):
        return getattr(self._sock, name)