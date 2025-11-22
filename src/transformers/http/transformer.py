import logging
from typing import List, Tuple

from parsers.http.parser import HTTPMessage

logger = logging.getLogger(__name__)


class HTTPTransformer:
    def transform(self, msg: HTTPMessage) -> bytes:
        # Only attempt to modify HTTP responses with a concrete body length
        if not msg.is_response:
            # Pass-through requests unchanged
            return self._serialize(msg)

        # If the body is empty or there is no explicit length/chunking, pass-through
        body = msg.body

        # Example modification: naive HTML footer injection
        modified_body = body.replace(b"</html>", b"OLA K ASE MODIFICA TRAFICO ENCRIPTADO O K ASE?</html>")

        # Update headers:
        # - If original was chunked, remove Transfer-Encoding and set Content-Length
        # - Otherwise just update Content-Length
        self._remove_header(msg.headers, b"transfer-encoding")
        # Trailers are not preserved once we switch to Content-Length
        self._remove_header(msg.headers, b"trailer")

        content_length_value = str(len(modified_body)).encode("ascii")
        self._set_or_add_header(msg.headers, b"Content-Length", content_length_value)

        # Optional: ensure Content-Encoding not compressed (your client sets Accept-Encoding: identity)
        # If you later allow compression, you must decompress before modifying.
        # self._remove_header(msg.headers, b"content-encoding")

        # Rebuild message
        return self._serialize_with_body(msg, modified_body)

    def _serialize(self, msg: HTTPMessage) -> bytes:
        return self._serialize_with_body(msg, msg.body)

    def _serialize_with_body(self, msg: HTTPMessage, body: bytes) -> bytes:
        # Rebuild headers preserving original order/casing; replace values we changed
        lines: List[bytes] = []
        for k, v in msg.headers:
            lines.append(k + b": " + v)
        headers_blob = b"\r\n".join(lines)
        return msg.start_line + headers_blob + b"\r\n\r\n" + body

    def _set_or_add_header(self, headers: List[Tuple[bytes, bytes]], name: bytes, value: bytes):
        lname = name.lower()
        for i, (k, v) in enumerate(headers):
            if k.lower() == lname:
                headers[i] = (k, value)
                return
        headers.append((name, value))

    def _remove_header(self, headers: List[Tuple[bytes, bytes]], name: bytes):
        lname = name.lower()
        i = 0
        while i < len(headers):
            if headers[i][0].lower() == lname:
                headers.pop(i)
            else:
                i += 1
