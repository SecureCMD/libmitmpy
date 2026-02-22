import logging
from typing import Optional

from .connection_handler import ConnectionHandler
from interceptors.http.parser import HTTPMessage, HTTPParser

logger = logging.getLogger(__name__)

# Type aliases for clarity at call sites
HTTPRequest = HTTPMessage
HTTPResponse = HTTPMessage


class HTTPConnectionHandler(ConnectionHandler):
    """ConnectionHandler that operates on fully-parsed HTTP messages.

    Subclass this and override on_request / on_response to intercept HTTP
    traffic without dealing with raw bytes or partial buffers.

    Both methods receive an HTTPMessage and must return:
      - The (possibly modified) HTTPMessage to forward it.
      - None to drop/swallow the message entirely.

    write_to_client() / write_to_server() / close() are inherited from
    ConnectionHandler and work as usual for injection outside of the HTTP
    request/response cycle.
    """

    def __init__(self):
        super().__init__()
        self._parser = HTTPParser()
        self._req_buf = bytearray()   # accumulates client→server bytes
        self._resp_buf = bytearray()  # accumulates server→client bytes

    # ------------------------------------------------------------------
    # Internal: byte-level hooks wired to the HTTP parse/transform cycle
    # ------------------------------------------------------------------

    def on_outgoing(self, data: bytes, eof: bool) -> Optional[bytes]:
        self._req_buf.extend(data)
        result = bytearray()

        while True:
            msg, consumed = self._parser.parse(self._req_buf, eof=eof)
            if msg is None:
                break
            del self._req_buf[:consumed]
            modified = self.on_request(msg)
            if modified is not None:
                result.extend(self._serialize(modified))

        if eof and self._req_buf:
            # Pass through anything that couldn't be parsed as HTTP on EOF
            result.extend(self._req_buf)
            self._req_buf.clear()

        # Always return bytes so the manager knows we're handling the data
        # internally. Empty bytes = swallow (still buffering incomplete message).
        return bytes(result)

    def on_incoming(self, data: bytes, eof: bool) -> Optional[bytes]:
        self._resp_buf.extend(data)
        result = bytearray()

        while True:
            msg, consumed = self._parser.parse(self._resp_buf, eof=eof)
            if msg is None:
                break
            del self._resp_buf[:consumed]
            modified = self.on_response(msg)
            if modified is not None:
                result.extend(self._serialize(modified))

        if eof and self._resp_buf:
            result.extend(self._resp_buf)
            self._resp_buf.clear()

        return bytes(result)

    # ------------------------------------------------------------------
    # Public API: override in subclasses
    # ------------------------------------------------------------------

    def on_request(self, req: HTTPRequest) -> Optional[HTTPRequest]:
        """Called for each complete HTTP request (client→server).

        Return the (possibly modified) request to forward it, or None to drop it.
        """
        return req

    def on_response(self, resp: HTTPResponse) -> Optional[HTTPResponse]:
        """Called for each complete HTTP response (server→client).

        Return the (possibly modified) response to forward it, or None to drop it.
        """
        return resp

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _serialize(self, msg: HTTPMessage) -> bytes:
        """Serialize an HTTPMessage back to wire format.

        Handles de-chunked messages by stripping chunked-encoding headers and
        updating Content-Length to match the actual body.
        """
        if msg.was_chunked:
            msg.remove_header(b"Transfer-Encoding")
            msg.remove_header(b"Trailer")

        # Update Content-Length whenever a body is present or the header already
        # existed (so a modified body length is always reflected correctly).
        if msg.body or msg.get_header(b"Content-Length") is not None:
            msg.set_header(b"Content-Length", str(len(msg.body)).encode("ascii"))

        return msg.serialize()
