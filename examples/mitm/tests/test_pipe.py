"""
Unit tests for net.socks.pipe.Pipe and pipe_manager.PipeManager.

All tests are self-contained: they use os-level socket pairs (socketpair)
rather than real network connections, so no running proxy is required.

Test categories
---------------
* Pipe termination - client/server disconnect, pipe.stop(), abrupt RST
* Pipe events     - outgoing/incoming data events are fired with correct data
* PipeManager data forwarding - bytes actually travel end-to-end
* Concurrent pipes - N pipes running simultaneously without interference
* Handler callbacks - on_connect / on_outgoing / on_incoming / on_disconnect
"""

import socket
import struct
import threading
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest

from core import SafeSocket
from db import Database
from handlers import ConnectionHandler
from net.socks.pipe import Pipe, PipeMetaInfo
from pipe_manager import PipeManager
from traffic_logger import TrafficLogger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def socket_pair() -> tuple[SafeSocket, SafeSocket]:
    a, b = socket.socketpair()
    return SafeSocket(a), SafeSocket(b)


def make_meta(**kwargs) -> PipeMetaInfo:
    defaults = dict(dst_addr=b"localhost", dst_port=8080)
    defaults.update(kwargs)
    return PipeMetaInfo(**defaults)


def run_pipe_in_thread(pipe: Pipe) -> threading.Event:
    """Start pipe.start() in a daemon thread; return an Event that is set when it finishes."""
    done = threading.Event()

    def _run():
        pipe.start()
        done.set()

    threading.Thread(target=_run, daemon=True).start()
    return done


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def traffic_logger():
    db = Database(Path(":memory:"))
    return TrafficLogger(db)


@pytest.fixture
def pipe_manager(traffic_logger):
    pm = PipeManager(traffic_logger=traffic_logger)
    yield pm
    pm.stop_all()


# ---------------------------------------------------------------------------
# Pipe termination tests
# ---------------------------------------------------------------------------

class TestPipeTermination:
    def test_client_disconnects_cleanly(self):
        """Pipe must terminate gracefully when the client closes first."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())
        done = run_pipe_in_thread(pipe)

        client_end.close()
        time.sleep(0.05)
        server_end.close()

        assert done.wait(timeout=5), "Pipe hung after client disconnected"

    def test_server_disconnects_cleanly(self):
        """Pipe must terminate gracefully when the server closes first."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())
        done = run_pipe_in_thread(pipe)

        server_end.close()
        time.sleep(0.05)
        client_end.close()

        assert done.wait(timeout=5), "Pipe hung after server disconnected"

    def test_both_sides_close_simultaneously(self):
        """Pipe must handle both sides closing at the same time."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())
        done = run_pipe_in_thread(pipe)

        client_end.close()
        server_end.close()

        assert done.wait(timeout=5), "Pipe hung when both sides closed simultaneously"

    def test_explicit_stop(self):
        """pipe.stop() must unblock recv calls and let the pipe threads exit."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())
        done = run_pipe_in_thread(pipe)

        # Let the pipe settle, then forcefully stop it
        time.sleep(0.05)
        pipe.stop()

        assert done.wait(timeout=5), "Pipe threads did not exit after pipe.stop()"

    def test_abrupt_connection_loss_rst(self):
        """
        Simulate WiFi drop / network failure: SO_LINGER(0) causes a TCP RST
        when the socket is closed, bypassing the graceful FIN handshake.
        The pipe must recover and terminate instead of hanging forever.
        """
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())
        done = run_pipe_in_thread(pipe)

        # Abrupt close: l_onoff=1, l_linger=0 sends RST on close
        linger = struct.pack("ii", 1, 0)
        try:
            client_end._socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        except OSError:
            pass  # some platforms may not support this on Unix sockets
        client_end._socket.close()

        time.sleep(0.05)
        server_end.close()

        assert done.wait(timeout=5), "Pipe did not recover from abrupt connection loss (RST)"

    def test_pipe_finished_event_fires(self):
        """The 'pipe_finished' event must be emitted after both sides disconnect."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        finished = threading.Event()
        pipe.on("pipe_finished", lambda p: finished.set())
        run_pipe_in_thread(pipe)

        client_end.close()
        server_end.close()

        assert finished.wait(timeout=5), "'pipe_finished' event was never emitted"


# ---------------------------------------------------------------------------
# Pipe event tests
# ---------------------------------------------------------------------------

class TestPipeEvents:
    def test_outgoing_data_event_carries_payload(self):
        """'outgoing_data_available' events must carry the bytes sent by the client."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        chunks = []
        pipe.on(
            "outgoing_data_available",
            lambda p, data=None, eof=False: chunks.append(data) if data else None,
        )
        done = run_pipe_in_thread(pipe)

        client_end._socket.sendall(b"hello from client")
        client_end.close()
        server_end.close()

        done.wait(timeout=5)
        assert b"hello from client" in b"".join(c for c in chunks if c)

    def test_incoming_data_event_carries_payload(self):
        """'incoming_data_available' events must carry the bytes sent by the server."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        chunks = []
        pipe.on(
            "incoming_data_available",
            lambda p, data=None, eof=False: chunks.append(data) if data else None,
        )
        done = run_pipe_in_thread(pipe)

        server_end._socket.sendall(b"hello from server")
        server_end.close()
        client_end.close()

        done.wait(timeout=5)
        assert b"hello from server" in b"".join(c for c in chunks if c)

    def test_no_more_outgoing_event_on_client_eof(self):
        """'no_more_outgoing_data_available' must fire when the client closes."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        got_event = threading.Event()
        pipe.on("no_more_outgoing_data_available", lambda p: got_event.set())
        run_pipe_in_thread(pipe)

        client_end.close()
        time.sleep(0.05)
        server_end.close()

        assert got_event.wait(timeout=5), "'no_more_outgoing_data_available' was never emitted"

    def test_no_more_incoming_event_on_server_eof(self):
        """'no_more_incoming_data_available' must fire when the server closes."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        got_event = threading.Event()
        pipe.on("no_more_incoming_data_available", lambda p: got_event.set())
        run_pipe_in_thread(pipe)

        server_end.close()
        time.sleep(0.05)
        client_end.close()

        assert got_event.wait(timeout=5), "'no_more_incoming_data_available' was never emitted"


# ---------------------------------------------------------------------------
# PipeManager end-to-end forwarding tests
# ---------------------------------------------------------------------------

def _run_pipe_via_manager(pm: PipeManager, pipe: Pipe, handler=None) -> threading.Thread:
    """Run pipe_manager.add() (which blocks) in a daemon thread."""
    t = threading.Thread(target=pm.add, args=(pipe,), kwargs={"handler": handler}, daemon=True)
    t.start()
    return t


class TestPipeManagerForwarding:
    def test_client_to_server_forwarding(self, pipe_manager):
        """With PipeManager: bytes sent by the client reach the server unchanged."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        received = []

        def collect_server():
            while True:
                chunk = server_end._socket.recv(4096)
                if not chunk:
                    break
                received.append(chunk)

        server_t = threading.Thread(target=collect_server, daemon=True)
        server_t.start()

        pm_t = _run_pipe_via_manager(pipe_manager, pipe)
        time.sleep(0.05)

        client_end._socket.sendall(b"client data")
        client_end.close()

        pm_t.join(timeout=5)
        server_end.close()
        server_t.join(timeout=3)

        assert b"client data" in b"".join(received)

    def test_server_to_client_forwarding(self, pipe_manager):
        """With PipeManager: bytes sent by the server reach the client unchanged."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        received = []

        def collect_client():
            while True:
                chunk = client_end._socket.recv(4096)
                if not chunk:
                    break
                received.append(chunk)

        client_t = threading.Thread(target=collect_client, daemon=True)
        client_t.start()

        pm_t = _run_pipe_via_manager(pipe_manager, pipe)
        time.sleep(0.05)

        server_end._socket.sendall(b"server response")
        server_end.close()

        pm_t.join(timeout=5)
        client_end.close()
        client_t.join(timeout=3)

        assert b"server response" in b"".join(received)

    def test_bidirectional_forwarding(self, pipe_manager):
        """Data must flow in both directions within the same pipe."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        client_received = []
        server_received = []

        def collect_server():
            try:
                while True:
                    chunk = server_end._socket.recv(4096)
                    if not chunk:
                        break
                    server_received.append(chunk)
            except OSError:
                pass

        def collect_client():
            try:
                while True:
                    chunk = client_end._socket.recv(4096)
                    if not chunk:
                        break
                    client_received.append(chunk)
            except OSError:
                pass

        threading.Thread(target=collect_server, daemon=True).start()
        threading.Thread(target=collect_client, daemon=True).start()

        pm_t = _run_pipe_via_manager(pipe_manager, pipe)
        time.sleep(0.05)

        client_end._socket.sendall(b"ping")
        server_end._socket.sendall(b"pong")
        time.sleep(0.1)
        client_end.close()
        server_end.close()

        pm_t.join(timeout=5)

        assert b"ping" in b"".join(server_received)
        assert b"pong" in b"".join(client_received)

    def test_large_payload_forwarded_intact(self, pipe_manager):
        """A large payload (128 KB) must arrive at the other end without data loss."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        payload = b"X" * 131072  # 128 KB
        received = bytearray()

        def collect_server():
            while len(received) < len(payload):
                chunk = server_end._socket.recv(4096)
                if not chunk:
                    break
                received.extend(chunk)

        threading.Thread(target=collect_server, daemon=True).start()
        pm_t = _run_pipe_via_manager(pipe_manager, pipe)
        time.sleep(0.05)

        client_end._socket.sendall(payload)
        client_end.close()

        pm_t.join(timeout=10)
        server_end.close()

        assert bytes(received) == payload


# ---------------------------------------------------------------------------
# Concurrent pipes
# ---------------------------------------------------------------------------

class TestConcurrentPipes:
    def test_multiple_pipes_do_not_interfere(self, pipe_manager):
        """N independent pipes can run simultaneously; each receives the correct data."""
        N = 8
        results = {}
        errors = []

        def run_one(i):
            msg = f"payload-for-pipe-{i}".encode()
            client_end, proxy_downstream = socket_pair()
            proxy_upstream, server_end = socket_pair()
            pipe = Pipe(
                downstream=proxy_downstream,
                upstream=proxy_upstream,
                metainfo=make_meta(dst_port=8000 + i),
            )
            received = []

            def collect():
                while True:
                    chunk = server_end._socket.recv(4096)
                    if not chunk:
                        break
                    received.append(chunk)

            threading.Thread(target=collect, daemon=True).start()
            pm_t = _run_pipe_via_manager(pipe_manager, pipe)
            time.sleep(0.05)

            client_end._socket.sendall(msg)
            client_end.close()
            pm_t.join(timeout=10)
            server_end.close()

            results[i] = b"".join(received)

        threads = [threading.Thread(target=run_one, args=(i,), daemon=True) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        if len(results) != N:
            errors.append(f"Only {len(results)}/{N} pipes completed")

        for i in range(N):
            expected = f"payload-for-pipe-{i}".encode()
            if expected not in results.get(i, b""):
                errors.append(f"Pipe {i} received wrong data: {results.get(i)!r}")

        assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# Handler callback tests
# ---------------------------------------------------------------------------

class RecordingHandler(ConnectionHandler):
    """A handler that records calls and can optionally transform data."""

    def __init__(self, transform=None):
        super().__init__()
        self.events = []
        self._transform = transform

    def on_connect(self):
        self.events.append("connect")

    def on_disconnect(self):
        self.events.append("disconnect")

    def on_outgoing(self, data: bytes, eof: bool) -> Optional[bytes]:
        self.events.append(("outgoing", data, eof))
        if self._transform and data:
            return self._transform(data)
        return None

    def on_incoming(self, data: bytes, eof: bool) -> Optional[bytes]:
        self.events.append(("incoming", data, eof))
        return None


class TestHandlerCallbacks:
    def test_on_connect_and_disconnect_called(self, pipe_manager):
        """on_connect must be called before data flows; on_disconnect after pipe finishes."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        handler = RecordingHandler()
        pm_t = _run_pipe_via_manager(pipe_manager, pipe, handler=handler)

        time.sleep(0.05)
        client_end.close()
        server_end.close()
        pm_t.join(timeout=5)

        # Give the dispatcher a moment to process pipe_finished → on_disconnect
        time.sleep(0.2)

        assert "connect" in handler.events
        assert "disconnect" in handler.events
        assert handler.events.index("connect") < handler.events.index("disconnect")

    def test_on_outgoing_receives_client_data(self, pipe_manager):
        """on_outgoing must be called with every chunk the client sends."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        handler = RecordingHandler()

        # We need server_end to drain what's forwarded; otherwise write_to_upstream blocks
        def drain():
            while True:
                chunk = server_end._socket.recv(4096)
                if not chunk:
                    break

        threading.Thread(target=drain, daemon=True).start()
        pm_t = _run_pipe_via_manager(pipe_manager, pipe, handler=handler)
        time.sleep(0.05)

        client_end._socket.sendall(b"test outgoing")
        client_end.close()
        pm_t.join(timeout=5)
        server_end.close()

        outgoing_payloads = b"".join(d for ev in handler.events if isinstance(ev, tuple) and ev[0] == "outgoing" for d in [ev[1]])
        assert b"test outgoing" in outgoing_payloads

    def test_handler_data_transformation(self, pipe_manager):
        """A handler that returns modified bytes must cause the server to receive those bytes."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        handler = RecordingHandler(transform=lambda data: data.upper())

        received = []

        def collect():
            while True:
                chunk = server_end._socket.recv(4096)
                if not chunk:
                    break
                received.append(chunk)

        threading.Thread(target=collect, daemon=True).start()
        pm_t = _run_pipe_via_manager(pipe_manager, pipe, handler=handler)
        time.sleep(0.05)

        client_end._socket.sendall(b"hello world")
        client_end.close()
        pm_t.join(timeout=5)
        server_end.close()

        assert b"HELLO WORLD" in b"".join(received)

    def test_handler_drop_swallows_data(self, pipe_manager):
        """A handler returning b'' must prevent data from reaching the server."""
        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        handler = RecordingHandler(transform=lambda _: b"")

        received = []

        def collect():
            server_end._socket.settimeout(0.5)
            try:
                while True:
                    chunk = server_end._socket.recv(4096)
                    if not chunk:
                        break
                    received.append(chunk)
            except OSError:
                pass

        threading.Thread(target=collect, daemon=True).start()
        pm_t = _run_pipe_via_manager(pipe_manager, pipe, handler=handler)
        time.sleep(0.05)

        client_end._socket.sendall(b"secret data")
        client_end.close()
        pm_t.join(timeout=5)
        server_end.close()

        assert b"secret data" not in b"".join(received)

    def test_crashing_handler_does_not_kill_pipe(self, pipe_manager):
        """If a handler raises in on_outgoing, the pipe must terminate cleanly (no hang)."""

        class CrashHandler(ConnectionHandler):
            def on_outgoing(self, data, eof):
                raise RuntimeError("intentional crash")

        client_end, proxy_downstream = socket_pair()
        proxy_upstream, server_end = socket_pair()
        pipe = Pipe(downstream=proxy_downstream, upstream=proxy_upstream, metainfo=make_meta())

        pm_t = _run_pipe_via_manager(pipe_manager, pipe, handler=CrashHandler())
        time.sleep(0.05)

        client_end._socket.sendall(b"data after crash")
        # Close both sides so both pipe threads (downstream + upstream) can exit.
        client_end.close()
        server_end.close()
        pm_t.join(timeout=5)

        assert pm_t.is_alive() is False
