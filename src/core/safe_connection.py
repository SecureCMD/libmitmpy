from __future__ import annotations

import logging
import socket

from OpenSSL import SSL, crypto

logger = logging.getLogger(__name__)

class SafeConnection:
    def __init__(self, socket):
        self._socket = socket
        self._conn = None
        self._closed = False

    def __str__(self):
        return f"{hex(id(self))}"

    def shutdown(self, *args, **kwargs):
        if not self._closed:
            try:
                self._socket.shutdown(*args, **kwargs)
            except OSError:
                pass
            self._closed = True

    def close(self):
        if not self._closed:
            try:
                self.shutdown(socket.SHUT_RDWR)
                self._conn.close()
            except OSError:
                pass
            self._closed = True

    def sendall(self, data: bytes, flags: int = 0):
        if flags:
            view = memoryview(data)
            total = 0
            while total < len(view):
                sent = self._conn.send(view[total:], flags)
                if sent == 0:
                    raise ConnectionResetError(f"Sent less bytes than expected ({total}/{len(data)}).")
                total += sent
        else:
            self._conn.sendall(data)

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        try:
            return self._conn.recv(bufsize, flags)
        except SSL.SysCallError as e:
            if e.args == (-1, 'Unexpected EOF'):
                return b""  # treat as closed connection
            raise

    def wrap_local(self, cert_pem, key_pem):
        x509_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        pkey_obj = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)

        ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
        ctx.use_certificate(x509_obj)
        ctx.use_privatekey(pkey_obj)

        self._conn = SSL.Connection(ctx, self._socket._socket)
        self._conn.set_accept_state()
        self._conn.do_handshake()

    def wrap_target(self, domain: str):
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)

        self._conn = SSL.Connection(ctx, self._socket._socket)
        self._conn.set_tlsext_host_name(domain.encode())
        self._conn.set_connect_state()
        self._conn.do_handshake()