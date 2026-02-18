from __future__ import annotations

import logging
import socket

from OpenSSL import SSL, crypto

logger = logging.getLogger(__name__)


class SafeConnection:
    def __init__(self, socket):
        self._socket = socket
        self._conn = None
        self._shutdown = False
        self._closed = False

    def __str__(self):
        return f"{hex(id(self))}"

    def shutdown(self, *args, **kwargs):
        if not self._shutdown and not self._closed:
            try:
                self._socket.shutdown(*args, **kwargs)
            except OSError:
                pass
            self._shutdown = True

    def close(self):
        if not self._closed:
            self._closed = True
            if not self._shutdown:
                try:
                    self._socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            try:
                self._conn.close()
            except OSError:
                pass

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
        except SSL.ZeroReturnError:
            return b""  # clean TLS shutdown (close_notify received)
        except SSL.SysCallError as e:
            if e.args == (-1, "Unexpected EOF"):
                return b""  # treat as closed connection
            raise

    def wrap_local(self, cert_pem, key_pem, ca_cert_pem=None):
        x509_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        pkey_obj = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)

        ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
        ctx.use_certificate(x509_obj)
        ctx.use_privatekey(pkey_obj)
        if ca_cert_pem:
            # Include the CA cert in the TLS Certificate message so clients
            # that don't have it in their local trust store can build the chain.
            ca_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
            ctx.add_extra_chain_cert(ca_x509)

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
