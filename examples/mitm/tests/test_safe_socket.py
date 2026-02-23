"""
Unit tests for core.safe_socket.SafeSocket.

SafeSocket wraps a raw socket and adds:
  * recvall(n)  – reads exactly n bytes, raises ConnectionResetError on early EOF
  * peekall(n)  – non-destructive peek at exactly n bytes
  * sendall     – thin wrapper around socket.sendall / chunked send with flags
  * close/shutdown idempotency guards

All tests use os-level socketpairs (no network required).
"""

import socket
import threading
import time

import pytest

from core import SafeSocket


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def socket_pair() -> tuple[SafeSocket, SafeSocket]:
    """Return two connected SafeSockets."""
    a, b = socket.socketpair()
    return SafeSocket(a), SafeSocket(b)


# ---------------------------------------------------------------------------
# recvall tests
# ---------------------------------------------------------------------------

class TestRecvAll:
    def test_receives_exact_bytes(self):
        """recvall returns exactly n bytes when the sender provides them."""
        reader, writer = socket_pair()
        writer._socket.sendall(b"hello world")
        data = reader.recvall(11)
        assert data == b"hello world"

    def test_receives_partial_sends_as_one(self):
        """recvall reassembles data that arrives in multiple small chunks."""
        reader, writer = socket_pair()

        def slow_sender():
            for byte in b"abcde":
                writer._socket.sendall(bytes([byte]))
                time.sleep(0.01)

        threading.Thread(target=slow_sender, daemon=True).start()
        data = reader.recvall(5)
        assert data == b"abcde"

    def test_raises_on_early_eof(self):
        """recvall must raise ConnectionResetError when the connection closes before n bytes arrive."""
        reader, writer = socket_pair()
        writer._socket.sendall(b"hi")  # only 2 bytes
        writer.close()

        with pytest.raises(ConnectionResetError):
            reader.recvall(10)  # requested 10

    def test_raises_on_immediate_eof(self):
        """recvall raises ConnectionResetError if the peer closes before sending anything."""
        reader, writer = socket_pair()
        writer.close()

        with pytest.raises(ConnectionResetError):
            reader.recvall(1)

    def test_returns_bytes_type(self):
        """recvall always returns a bytes object (not bytearray)."""
        reader, writer = socket_pair()
        writer._socket.sendall(b"\x00\x01\x02")
        result = reader.recvall(3)
        assert isinstance(result, bytes)

    def test_zero_bytes(self):
        """recvall(0) should return an empty bytes without blocking."""
        reader, writer = socket_pair()
        result = reader.recvall(0)
        assert result == b""


# ---------------------------------------------------------------------------
# peekall tests
# ---------------------------------------------------------------------------

class TestPeekAll:
    def test_peekall_returns_correct_bytes(self):
        """peekall returns exactly n bytes without removing them from the buffer."""
        reader, writer = socket_pair()
        writer._socket.sendall(b"peekme")
        peeked = reader.peekall(6)
        assert peeked == b"peekme"

    def test_peekall_does_not_consume_data(self):
        """After peekall the bytes remain readable by a normal recv."""
        reader, writer = socket_pair()
        writer._socket.sendall(b"12345")
        reader.peekall(5)
        still_there = reader._socket.recv(5)
        assert still_there == b"12345"

    def test_peekall_raises_on_eof(self):
        """peekall raises ConnectionResetError when the peer closes before n bytes."""
        reader, writer = socket_pair()
        writer.close()

        with pytest.raises(ConnectionResetError):
            reader.peekall(4)

    def test_peekall_waits_for_enough_bytes(self):
        """peekall blocks until the requested number of bytes is available."""
        reader, writer = socket_pair()

        def send_late():
            time.sleep(0.05)
            writer._socket.sendall(b"delayed")

        threading.Thread(target=send_late, daemon=True).start()
        peeked = reader.peekall(7)
        assert peeked == b"delayed"


# ---------------------------------------------------------------------------
# sendall tests
# ---------------------------------------------------------------------------

class TestSendAll:
    def test_sendall_delivers_data(self):
        """Data written with sendall must be readable from the other end."""
        reader, writer = socket_pair()
        writer.sendall(b"sent via sendall")
        received = reader._socket.recv(64)
        assert received == b"sent via sendall"

    def test_sendall_large_payload(self):
        """sendall copes with a 64 KB payload without truncation."""
        reader, writer = socket_pair()
        payload = b"Q" * 65536

        received = bytearray()

        def collect():
            while len(received) < len(payload):
                chunk = reader._socket.recv(4096)
                if not chunk:
                    break
                received.extend(chunk)

        t = threading.Thread(target=collect, daemon=True)
        t.start()
        writer.sendall(payload)
        t.join(timeout=5)

        assert bytes(received) == payload


# ---------------------------------------------------------------------------
# close / shutdown idempotency
# ---------------------------------------------------------------------------

class TestCloseAndShutdown:
    def test_close_is_idempotent(self):
        """Calling close() twice must not raise."""
        reader, writer = socket_pair()
        reader.close()
        reader.close()  # should be a no-op

    def test_shutdown_is_idempotent(self):
        """Calling shutdown() twice must not raise."""
        reader, writer = socket_pair()
        reader.shutdown(socket.SHUT_RDWR)
        reader.shutdown(socket.SHUT_RDWR)  # should be a no-op

    def test_close_after_shutdown(self):
        """close() after shutdown() must not raise."""
        reader, writer = socket_pair()
        reader.shutdown(socket.SHUT_RDWR)
        reader.close()

    def test_peer_gets_eof_after_close(self):
        """After close(), the peer's recv() must return b'' (EOF)."""
        reader, writer = socket_pair()
        reader.close()
        data = writer._socket.recv(16)
        assert data == b""

    def test_closed_socket_flags(self):
        """After close(), the _closed flag must be set."""
        reader, writer = socket_pair()
        assert reader._closed is False
        reader.close()
        assert reader._closed is True

    def test_shutdown_flag_set(self):
        """After shutdown(), the _shutdown flag must be set."""
        reader, writer = socket_pair()
        assert reader._shutdown is False
        reader.shutdown(socket.SHUT_RDWR)
        assert reader._shutdown is True
