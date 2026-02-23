"""
Unit tests for net.tls.get_sni_alpn.

get_sni_alpn() peeks at the raw bytes the client sends after the SOCKS
CONNECT handshake to decide whether this is a TLS connection and, if so,
what SNI hostname and ALPN protocols were requested.

All tests feed pre-built byte sequences into one end of a socketpair and
call get_sni_alpn() on the other end — no real TLS stack involved.
"""

import socket
import struct

import pytest

from core import SafeSocket
from net.tls import get_sni_alpn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def socket_pair() -> tuple[SafeSocket, SafeSocket]:
    a, b = socket.socketpair()
    return SafeSocket(a), SafeSocket(b)


def build_client_hello(sni: str = None, alpn: list[str] = None) -> bytes:
    """
    Construct a minimal but structurally valid TLS 1.3 ClientHello record.

    Layout
    ------
    TLS record header  (5 B)
      content_type   = 0x16 (handshake)
      legacy_version = 0x03 0x01 (TLS 1.0, as required by RFC 8446 §5.1)
      length         = len(handshake_msg)
    Handshake message
      msg_type = 0x01 (ClientHello)
      length   = 3 bytes big-endian
      body:
        legacy_version        = 0x03 0x03
        random                = 32 zero bytes
        session_id            = 0-length
        cipher_suites         = [TLS_AES_128_GCM_SHA256 (0x1301)]
        compression_methods   = [null (0x00)]
        extensions            = [SNI and/or ALPN if requested]
    """
    extensions = b""

    if sni:
        sni_bytes = sni.encode()
        # server_name_list entry: type=host_name(0), length, name
        sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
        # server_name_list with its own length prefix
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        extensions += struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    if alpn:
        proto_list = b""
        for proto in alpn:
            pb = proto.encode()
            proto_list += bytes([len(pb)]) + pb
        alpn_data = struct.pack("!H", len(proto_list)) + proto_list
        extensions += struct.pack("!HH", 0x0010, len(alpn_data)) + alpn_data

    body = (
        b"\x03\x03"                                    # legacy_version
        + b"\x00" * 32                                 # random
        + b"\x00"                                      # session_id length = 0
        + struct.pack("!H", 2) + b"\x13\x01"           # 1 cipher suite
        + b"\x01\x00"                                  # 1 compression method: null
        + struct.pack("!H", len(extensions))
        + extensions
    )

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body  # 3-byte length

    return (
        b"\x16"                              # content_type: handshake
        + b"\x03\x01"                        # record legacy_version: TLS 1.0
        + struct.pack("!H", len(handshake))
        + handshake
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGetSniAlpn:
    # --- Non-TLS / early-return cases ---

    def test_plain_http_returns_none(self):
        """Plain HTTP text (not a TLS handshake) → (None, [])."""
        reader, writer = socket_pair()
        writer._socket.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

        sni, alpn = get_sni_alpn(reader)

        assert sni is None
        assert alpn == []

    def test_random_garbage_returns_none(self):
        """Random bytes that don't look like TLS → (None, [])."""
        reader, writer = socket_pair()
        writer._socket.sendall(b"\xff\xfe\x00\x00" + b"\xab" * 64)

        sni, alpn = get_sni_alpn(reader)

        assert sni is None
        assert alpn == []

    def test_wrong_content_type_returns_none(self):
        """TLS application-data record (0x17) is not a handshake → (None, [])."""
        reader, writer = socket_pair()
        # 5-byte TLS record header: type=0x17, version=TLS1.2, length=4
        writer._socket.sendall(b"\x17\x03\x03\x00\x04" + b"\x00" * 4)

        sni, alpn = get_sni_alpn(reader)

        assert sni is None
        assert alpn == []

    def test_unsupported_tls_version_returns_none(self):
        """Handshake record with an unrecognised version tag → (None, [])."""
        reader, writer = socket_pair()
        # content_type=0x16 but version=0x04 0x00 (not TLS 1.0/1.2/1.3)
        writer._socket.sendall(b"\x16\x04\x00\x00\x04" + b"\x00" * 4)

        sni, alpn = get_sni_alpn(reader)

        assert sni is None
        assert alpn == []

    def test_server_hello_handshake_type_returns_none(self):
        """Handshake type ServerHello (0x02) instead of ClientHello (0x01) → (None, [])."""
        reader, writer = socket_pair()
        body = b"\x03\x03" + b"\x00" * 38  # version + random
        handshake = b"\x02" + struct.pack("!I", len(body))[1:] + body
        record = b"\x16" + b"\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        writer._socket.sendall(record)

        sni, alpn = get_sni_alpn(reader)

        assert sni is None
        assert alpn == []

    def test_connection_reset_before_data_raises(self):
        """Client closes connection without sending any bytes → ConnectionResetError."""
        reader, writer = socket_pair()
        writer.close()

        with pytest.raises(ConnectionResetError):
            get_sni_alpn(reader)

    # --- SNI extraction ---

    def test_sni_extracted_correctly(self):
        """Valid ClientHello with SNI → SNI is returned, ALPN is empty."""
        reader, writer = socket_pair()
        writer._socket.sendall(build_client_hello(sni="example.com"))

        sni, alpn = get_sni_alpn(reader)

        assert sni == "example.com"
        assert alpn == []

    def test_sni_with_subdomain(self):
        """SNI with a multi-label subdomain is extracted verbatim."""
        reader, writer = socket_pair()
        writer._socket.sendall(build_client_hello(sni="api.internal.example.com"))

        sni, alpn = get_sni_alpn(reader)

        assert sni == "api.internal.example.com"

    def test_no_extensions_returns_none_sni(self):
        """ClientHello with no extensions at all → (None, [])."""
        reader, writer = socket_pair()
        writer._socket.sendall(build_client_hello())  # neither sni nor alpn

        sni, alpn = get_sni_alpn(reader)

        assert sni is None
        assert alpn == []

    # --- ALPN extraction ---

    def test_sni_and_alpn_both_extracted(self):
        """ClientHello with both SNI and ALPN → both are returned correctly."""
        reader, writer = socket_pair()
        writer._socket.sendall(
            build_client_hello(sni="secure.example.com", alpn=["h2", "http/1.1"])
        )

        sni, alpn = get_sni_alpn(reader)

        assert sni == "secure.example.com"
        assert "h2" in alpn
        assert "http/1.1" in alpn

    def test_alpn_order_preserved(self):
        """ALPN protocols are returned in the same order they appear in the extension."""
        reader, writer = socket_pair()
        protos = ["h2", "http/1.1", "spdy/3.1"]
        writer._socket.sendall(build_client_hello(sni="x.example.com", alpn=protos))

        sni, alpn = get_sni_alpn(reader)

        assert alpn == protos

    def test_single_alpn_proto(self):
        """A single ALPN protocol is returned as a one-element list."""
        reader, writer = socket_pair()
        writer._socket.sendall(build_client_hello(sni="x.example.com", alpn=["h2"]))

        sni, alpn = get_sni_alpn(reader)

        assert alpn == ["h2"]

    # --- Data is only peeked, not consumed ---

    def test_data_remains_in_socket_after_peek(self):
        """
        get_sni_alpn uses MSG_PEEK so the bytes must still be readable
        from the socket afterwards (so the real TLS handshake can proceed).
        """
        reader, writer = socket_pair()
        hello = build_client_hello(sni="peek.example.com")
        writer._socket.sendall(hello)

        get_sni_alpn(reader)  # only peeks

        # The original bytes must still be available via a normal recv
        leftover = reader._socket.recv(len(hello))
        assert leftover == hello

    # --- TLS 1.0 / TLS 1.2 record versions ---

    def test_tls10_record_version_accepted(self):
        """Record version 0x03 0x01 (TLS 1.0) is accepted."""
        reader, writer = socket_pair()
        writer._socket.sendall(build_client_hello(sni="tls10.example.com"))
        # build_client_hello already uses TLS 1.0 record version (0x03 0x01)
        sni, _ = get_sni_alpn(reader)
        assert sni == "tls10.example.com"

    def test_tls12_record_version_accepted(self):
        """Record version 0x03 0x03 (TLS 1.2/1.3) is also accepted."""
        reader, writer = socket_pair()
        hello = build_client_hello(sni="tls12.example.com")
        # Patch the record version to 0x03 0x03
        hello = hello[:1] + b"\x03\x03" + hello[3:]
        writer._socket.sendall(hello)

        sni, _ = get_sni_alpn(reader)

        assert sni == "tls12.example.com"
