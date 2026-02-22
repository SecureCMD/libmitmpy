import socket
from typing import Optional, TYPE_CHECKING

from .connection_meta import ConnectionMeta

if TYPE_CHECKING:
    from net.socks import Pipe


class ConnectionHandler:
    def __init__(self):
        self.meta: ConnectionMeta = None  # injected before on_connect()
        self._pipe: "Pipe" = None         # injected before on_connect()

    def on_connect(self) -> None:
        pass

    def on_disconnect(self) -> None:
        pass

    def on_outgoing(self, data: bytes, eof: bool) -> Optional[bytes]:
        """Called for each chunk of client→server data.

        Return None to forward data unchanged.
        Return bytes to forward those bytes instead.
        Return b"" to swallow/drop the data without forwarding anything.
        """
        return None

    def on_incoming(self, data: bytes, eof: bool) -> Optional[bytes]:
        """Called for each chunk of server→client data.

        Return None to forward data unchanged.
        Return bytes to forward those bytes instead.
        Return b"" to swallow/drop the data without forwarding anything.
        """
        return None

    def write_to_client(self, data: bytes) -> None:
        """Send data directly to the client, outside of the normal forwarding flow."""
        if self._pipe is not None:
            self._pipe.write_to_downstream(data)

    def write_to_server(self, data: bytes) -> None:
        """Send data directly to the server, outside of the normal forwarding flow."""
        if self._pipe is not None:
            self._pipe.write_to_upstream(data)

    def close(self) -> None:
        """Terminate the connection from either side."""
        if self._pipe is not None:
            self._pipe.stop()
            try:
                self._pipe._upstream.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._pipe._downstream.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
