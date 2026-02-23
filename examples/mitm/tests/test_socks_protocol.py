"""
Unit tests for the SOCKS5 client protocol handler (net.socks.client.Client).

These tests exercise protocol-level behaviour (handshake and request
parsing) without requiring a running proxy.  They feed bytes into one end
of a socket-pair and assert on what Client does with the other end.
"""

import socket
import struct
import threading
import time

import pytest

from core import SafeSocket
from net.socks.client import M_NOAUTH, VER, Client

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def socket_pair() -> tuple[SafeSocket, SafeSocket]:
    """Return two connected SafeSockets (server_side, client_side)."""
    a, b = socket.socketpair()
    return SafeSocket(a), SafeSocket(b)


# ---------------------------------------------------------------------------
# Handshake tests
# ---------------------------------------------------------------------------

class TestHandshake:
    def test_no_data_sent(self):
        """Client connects then immediately closes: handshake must return False."""
        server_sock, client_sock = socket_pair()
        client_sock.close()

        result = Client(server_sock).handshake()

        assert result is False

    def test_wrong_socks_version(self):
        """SOCKS4 greeting must be rejected (handshake returns False)."""
        server_sock, client_sock = socket_pair()

        def send():
            client_sock._socket.sendall(b"\x04\x01\x00")  # SOCKS4
            time.sleep(0.2)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        result = Client(server_sock).handshake()
        t.join(timeout=3)

        assert result is False

    def test_zero_methods(self):
        """NMETHODS=0 must be rejected."""
        server_sock, client_sock = socket_pair()

        def send():
            client_sock._socket.sendall(b"\x05\x00")  # VER=5, NMETHODS=0
            time.sleep(0.2)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        result = Client(server_sock).handshake()
        t.join(timeout=3)

        assert result is False

    def test_only_auth_method_offered(self):
        """Client offers only username/password auth; proxy requires no-auth."""
        server_sock, client_sock = socket_pair()

        def send():
            client_sock._socket.sendall(b"\x05\x01\x02")  # M_AUTH only
            time.sleep(0.2)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        result = Client(server_sock).handshake()
        t.join(timeout=3)

        assert result is False

    def test_partial_header_then_close(self):
        """Client sends only the VER byte before disconnecting."""
        server_sock, client_sock = socket_pair()

        def send():
            client_sock._socket.sendall(b"\x05")
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        result = Client(server_sock).handshake()
        t.join(timeout=3)

        assert result is False

    def test_valid_no_auth_handshake(self):
        """Well-formed SOCKS5 no-auth greeting succeeds and proxy replies correctly."""
        server_sock, client_sock = socket_pair()
        reply = []

        def send():
            client_sock._socket.sendall(b"\x05\x01\x00")  # VER=5, NMETHODS=1, M_NOAUTH
            resp = client_sock._socket.recv(2)
            reply.append(resp)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        result = Client(server_sock).handshake()
        t.join(timeout=3)

        assert result is True
        assert reply[0] == VER + M_NOAUTH

    def test_multiple_methods_includes_no_auth(self):
        """Client offers both no-auth and auth; proxy picks no-auth and succeeds."""
        server_sock, client_sock = socket_pair()
        reply = []

        def send():
            client_sock._socket.sendall(b"\x05\x02\x00\x02")  # no-auth + M_AUTH
            resp = client_sock._socket.recv(2)
            reply.append(resp)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        result = Client(server_sock).handshake()
        t.join(timeout=3)

        assert result is True
        assert reply[0] == VER + M_NOAUTH

    def test_server_closes_during_method_send(self):
        """If the server socket dies while sending the reply, handshake returns False."""
        server_sock, client_sock = socket_pair()

        def send():
            client_sock._socket.sendall(b"\x05\x01\x00")
            # Don't read the reply — close immediately to provoke a broken pipe
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()

        # The handshake may succeed or fail depending on timing (close vs. send race).
        # What matters is it must never raise an unhandled exception.
        try:
            Client(server_sock).handshake()
        except Exception as exc:
            pytest.fail(f"handshake raised an unexpected exception: {exc}")
        finally:
            t.join(timeout=3)


# ---------------------------------------------------------------------------
# Request-detail parsing tests
# ---------------------------------------------------------------------------

class TestGetRequestDetails:
    """Tests for Client.get_request_details()."""

    def _pair(self):
        return socket_pair()

    def test_ipv4_request(self):
        """CONNECT to an IPv4 address is parsed correctly."""
        server_sock, client_sock = self._pair()

        def send():
            header = b"\x05\x01\x00\x01"
            addr = socket.inet_aton("192.168.1.1")
            port = struct.pack(">H", 8080)
            client_sock._socket.sendall(header + addr + port)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == "192.168.1.1"
        assert dst_port == 8080

    def test_domain_request(self):
        """CONNECT to a domain name is parsed correctly."""
        server_sock, client_sock = self._pair()
        domain = b"example.com"

        def send():
            header = b"\x05\x01\x00\x03"
            client_sock._socket.sendall(
                header + bytes([len(domain)]) + domain + struct.pack(">H", 443)
            )
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == b"example.com"
        assert dst_port == 443

    def test_ipv6_request(self):
        """CONNECT to an IPv6 address is parsed correctly."""
        server_sock, client_sock = self._pair()

        def send():
            header = b"\x05\x01\x00\x04"
            addr = socket.inet_pton(socket.AF_INET6, "::1")
            port = struct.pack(">H", 8443)
            client_sock._socket.sendall(header + addr + port)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert "::1" in dst_addr
        assert dst_port == 8443

    def test_wrong_version_in_request(self):
        """SOCKS4 version byte in the request header returns empty address."""
        server_sock, client_sock = self._pair()

        def send():
            client_sock._socket.sendall(b"\x04\x01\x00\x01" + b"\x00" * 6)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == b""
        assert dst_port == 0

    def test_unsupported_command_bind(self):
        """BIND command (0x02) is rejected; returns empty address."""
        server_sock, client_sock = self._pair()

        def send():
            client_sock._socket.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == b""

    def test_unsupported_command_udp(self):
        """UDP ASSOCIATE command (0x03) is rejected; returns empty address."""
        server_sock, client_sock = self._pair()

        def send():
            client_sock._socket.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == b""

    def test_nonzero_reserved_byte(self):
        """Non-zero RSV byte must cause rejection."""
        server_sock, client_sock = self._pair()

        def send():
            client_sock._socket.sendall(b"\x05\x01\xff\x01" + b"\x00" * 6)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == b""

    def test_invalid_atyp(self):
        """Unknown ATYP value (e.g. 0x05) returns empty address."""
        server_sock, client_sock = self._pair()

        def send():
            client_sock._socket.sendall(b"\x05\x01\x00\x05" + b"\x00" * 6)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == b""

    def test_connection_reset_mid_header(self):
        """Client closes socket after sending only part of the 4-byte header."""
        server_sock, client_sock = self._pair()

        def send():
            client_sock._socket.sendall(b"\x05\x01")  # only 2 of 4 header bytes
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == b""

    def test_connection_reset_mid_address(self):
        """Client closes socket right after the 4-byte header (no address data)."""
        server_sock, client_sock = self._pair()

        def send():
            client_sock._socket.sendall(b"\x05\x01\x00\x01")  # header only, no addr
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == b""

    def test_garbage_bytes(self):
        """Completely random/garbage payload must not crash or hang."""
        server_sock, client_sock = self._pair()

        def send():
            client_sock._socket.sendall(b"\xff\xfe\xfd\xfc" + b"\xab" * 20)
            client_sock._socket.close()

        t = threading.Thread(target=send, daemon=True)
        t.start()
        dst_addr, dst_port = Client(server_sock).get_request_details()
        t.join(timeout=3)

        assert dst_addr == b""
