import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

_CRLF = b"\r\n"
_HDR_END = b"\r\n\r\n"

@dataclass
class HTTPMessage:
    start_line: bytes
    headers: List[Tuple[bytes, bytes]]  # preserve order and original casing
    body: bytes
    is_response: bool
    was_chunked: bool
    trailers: Optional[bytes] = None  # raw trailers if present

    def get_header(self, name: bytes) -> Optional[bytes]:
        lname = name.lower()
        for k, v in self.headers:
            if k.lower() == lname:
                return v
        return None

    def set_header(self, name: bytes, value: bytes):
        lname = name.lower()
        for i, (k, v) in enumerate(self.headers):
            if k.lower() == lname:
                self.headers[i] = (k, value)
                return
        self.headers.append((name, value))

    def remove_header(self, name: bytes):
        lname = name.lower()
        self.headers = [(k, v) for (k, v) in self.headers if k.lower() != lname]

    def serialize(self) -> bytes:
        header_lines = [k + b": " + v for (k, v) in self.headers]
        headers_blob = _CRLF.join(header_lines)
        return self.start_line + headers_blob + _HDR_END + self.body

class HTTPParser:
    """
    Safer HTTP/1.x parser:
    - Waits for \r\n\r\n to end headers
    - If Content-Length is present: waits for full body
    - If Transfer-Encoding: chunked: waits for full chunked body (+trailers), de-chunks the body
    - Responses with no body (1xx, 101, 204, 304): emit immediately after headers
    - Requests without CL/TE: assume no body and emit (typical GET)
    - Otherwise: return (None, 0) and wait for more data (or connection close)
    """

    def parse(self, data: bytearray, eof: bool = False) -> Tuple[Optional[HTTPMessage], int]:
        # Work with immutable bytes to avoid bytearray edge cases
        db = bytes(data)

        sep = db.find(_HDR_END)
        if sep == -1:
            return None, 0

        head = db[:sep]
        body_start = sep + 4
        lines = head.split(_CRLF)
        if not lines:
            return None, 0

        start_line = lines[0] + _CRLF
        is_response = lines[0].startswith(b"HTTP/")

        # Parse headers preserving order as bytes
        headers: List[Tuple[bytes, bytes]] = []
        for raw in lines[1:]:
            if b":" not in raw:
                continue
            k, v = raw.split(b":", 1)
            headers.append((k.strip(), v.strip()))

        # Helpers
        def get_header(name: bytes) -> Optional[bytes]:
            lname = name.lower()
            for k, v in headers:
                if k.lower() == lname:
                    return v
            return None

        def has_chunked() -> bool:
            te = get_header(b"transfer-encoding")
            if not te:
                return False
            return any(token.strip().lower() == b"chunked" for token in te.split(b","))

        def get_content_length() -> Optional[int]:
            v = get_header(b"content-length")
            if v is None:
                return None
            try:
                return int(v)
            except ValueError:
                return None

        # Detect responses with no body by status code
        if is_response:
            status_code = None
            try:
                parts = lines[0].split(b" ")
                if len(parts) >= 2:
                    status_code = int(parts[1])
            except ValueError:
                pass
            if status_code is not None and (
                100 <= status_code < 200 or status_code in (101, 204, 304)
            ):
                msg = HTTPMessage(
                    start_line=start_line,
                    headers=headers,
                    body=b"",
                    is_response=True,
                    was_chunked=False,
                )
                return msg, body_start

        # For requests, assume no body if neither CL nor chunked
        if not is_response and get_content_length() is None and not has_chunked():
            msg = HTTPMessage(
                start_line=start_line,
                headers=headers,
                body=b"",
                is_response=False,
                was_chunked=False,
            )
            return msg, body_start

        body = db[body_start:]

        # 1) Content-Length
        cl = get_content_length()
        if cl is not None:
            if len(body) < cl:
                return None, 0
            full_body = body[:cl]
            consumed = body_start + cl
            msg = HTTPMessage(
                start_line=start_line,
                headers=headers,
                body=full_body,
                is_response=is_response,
                was_chunked=False,
            )
            return msg, consumed

        # 2) Transfer-Encoding: chunked
        if has_chunked():
            parsed = self._parse_chunked(body, eof=eof)
            if parsed is None:
                return None, 0
            dechunked_body, chunked_total_len, trailers = parsed
            consumed = body_start + chunked_total_len
            msg = HTTPMessage(
                start_line=start_line,
                headers=headers,
                body=dechunked_body,
                is_response=is_response,
                was_chunked=True,
                trailers=trailers,
            )
            return msg, consumed

        # 3) Indeterminate length
        return None, 0

    def _parse_chunked(self, buf: bytes, eof: bool = False) -> Optional[Tuple[bytes, int, Optional[bytes]]]:
        i = 0
        out = bytearray()
        while True:
            line_end = buf.find(_CRLF, i)
            if line_end == -1:
                return None

            size_line = buf[i:line_end]
            # strip chunk extensions
            if b";" in size_line:
                size_hex = size_line.split(b";", 1)[0]
            else:
                size_hex = size_line
            size_hex = size_hex.strip()

            try:
                size = int(size_hex, 16)
            except ValueError:
                return None

            # move past the size line CRLF
            i = line_end + 2

            if size == 0:
                # last-chunk: parse trailer-part (0+ lines) terminated by a single CRLF
                t_start = i
                while True:
                    t_end = buf.find(_CRLF, i)
                    if t_end == -1:
                        if eof:
                            trailers = None if i == t_start else buf[t_start:i]
                            return bytes(out), i, trailers
                        return None
                    if t_end == i:
                        # empty line ends trailers
                        i += 2
                        break
                    i = t_end + 2
                trailers = buf[t_start:i] if i > t_start + 2 else None
                return bytes(out), i, trailers

            # normal chunk: need data + trailing CRLF
            need = i + size + 2
            if len(buf) < need:
                return None

            out.extend(buf[i:i+size])
            i += size
            if buf[i:i+2] != _CRLF:
                return None
            i += 2