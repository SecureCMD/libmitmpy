import logging
from struct import unpack
from typing import Tuple

from core import SafeSocket

logger = logging.getLogger(__name__)


TLS_HANDSHAKE = b"\x16"
TLS_1_0 = b"\x03\x01"
TLS_1_2 = b"\x03\x03"
TLS_1_3 = b"\x03\x03"  # yeah, this is the same as TLS_1_2 because fuck everything
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = b"\x01"


def get_sni_alpn(sock: SafeSocket) -> Tuple[str, Tuple[str]]:
    """
    Incrementally parse TLS ClientHello to extract SNI and ALPN.
    Returns:
        (sni, alpn_list)
    """
    # --- Step 1: Read TLS record header (5 bytes) ---
    record_hdr = sock.peekall(5)
    content_type = record_hdr[0:1]
    version = record_hdr[1:3]
    total_len = unpack("!H", record_hdr[3:5])[0]

    if content_type != TLS_HANDSHAKE:
        return None, []

    if version not in [TLS_1_0, TLS_1_2, TLS_1_3]:
        return None, []

    # --- Step 2: Read full TLS record (exact length) ---
    full_record = sock.peekall(5 + total_len)
    data = full_record[5:]  # skip record header
    pos = 0

    # --- Step 3: Handshake type (ClientHello) ---
    if data[pos:pos+1] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
        return None, []
    pos += 1

    # Skip handshake length (3 bytes)
    pos += 3

    # Skip client_version (2) + random (32)
    pos += 2 + 32

    # Session ID
    session_id_len = data[pos]
    pos += 1 + session_id_len

    # Cipher Suites
    cipher_suites_len = unpack("!H", data[pos : pos + 2])[0]
    pos += 2 + cipher_suites_len

    # Compression Methods
    compression_methods_len = data[pos]
    pos += 1 + compression_methods_len

    # --- Step 4: Extensions ---
    if pos + 2 > len(data):
        return None, []
    extensions_len = unpack("!H", data[pos : pos + 2])[0]
    pos += 2

    sni = None
    alpn_list = []
    end = pos + extensions_len

    while pos + 4 <= end:
        ext_type = unpack("!H", data[pos : pos + 2])[0]
        ext_len = unpack("!H", data[pos + 2 : pos + 4])[0]
        pos += 4
        ext_data = data[pos : pos + ext_len]

        if ext_type == 0x00 and ext_len >= 5:  # SNI
            sni_len = unpack("!H", ext_data[3:5])[0]
            sni = ext_data[5 : 5 + sni_len].decode("utf-8", errors="ignore")

        elif ext_type == 0x10 and ext_len > 2:  # ALPN
            alpn_list_len = unpack("!H", ext_data[:2])[0]
            p = 2
            while p < 2 + alpn_list_len:
                proto_len = ext_data[p]
                p += 1
                alpn_list.append(ext_data[p : p + proto_len].decode("utf-8", errors="ignore"))
                p += proto_len

        pos += ext_len

    return sni, alpn_list
