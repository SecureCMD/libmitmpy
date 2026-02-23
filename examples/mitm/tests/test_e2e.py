"""
End-to-end tests that require the proxy to be running on localhost:9090.

Unlike the unit tests, these exercise the full proxy stack in one shot:
    client → SOCKS5 handshake → proxy → (optional TLS MITM) → destination

They are designed to catch integration bugs that unit tests cannot:
concurrency races in PipeManager, resource leaks under bad client behaviour,
and incorrect protocol handling when all the moving parts interact together.

Start the proxy before running these tests:
    cd examples/mitm && sudo python main.py
"""

import socket
import ssl
import struct
import threading
import time
from contextlib import contextmanager

import pytest
import requests
import socks


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def require_proxy(proxy):
    """Skip every test in this module if the proxy port is not reachable."""
    try:
        s = socket.create_connection((proxy["host"], proxy["port"]), timeout=1)
        s.close()
    except OSError:
        pytest.skip(
            f"Proxy not reachable at {proxy['host']}:{proxy['port']} — "
            "start it with: cd examples/mitm && sudo python main.py"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@contextmanager
def local_echo_server():
    """
    Spin up a minimal TCP echo server on an ephemeral loopback port.
    The proxy (which is also local) can reach it at 127.0.0.1:<port>.

    Yields (host, port).
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(32)
    srv.settimeout(1)
    host, port = srv.getsockname()

    def _echo(conn):
        try:
            conn.settimeout(10)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    stop = threading.Event()

    def _serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(target=_echo, args=(conn,), daemon=True).start()
            except OSError:
                break

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        yield host, port
    finally:
        stop.set()
        srv.close()
        t.join(timeout=2)


def socks5_connect_ipv4(proxy_host: str, proxy_port: int,
                        dst_ip: str, dst_port: int,
                        timeout: float = 5) -> socket.socket:
    """
    Manually perform a SOCKS5 no-auth handshake followed by a CONNECT
    request using an IPv4 address.  Returns the raw connected socket.

    Uses a raw socket (not PySocks) so we have full control over timing
    and can test error scenarios.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((proxy_host, proxy_port))

    # Greeting: VER=5, NMETHODS=1, method=no-auth
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if resp != b"\x05\x00":
        s.close()
        raise RuntimeError(f"Unexpected SOCKS5 greeting reply: {resp!r}")

    # CONNECT with IPv4 address
    s.sendall(
        b"\x05\x01\x00\x01"
        + socket.inet_aton(dst_ip)
        + struct.pack(">H", dst_port)
    )
    reply = s.recv(10)
    if len(reply) < 2 or reply[1] != 0x00:
        s.close()
        raise RuntimeError(f"SOCKS5 CONNECT failed: {reply!r}")

    return s


def proxy_sanity_check(proxy: dict, *, msg: bytes = b"proxy-ok\n") -> None:
    """
    Quick smoke-test: send a short message through the proxy to a TCP echo
    server and verify it comes back intact.  Fails immediately if the proxy
    is no longer accepting or forwarding connections.
    """
    sock = socks.socksocket()
    sock.settimeout(10)
    sock.set_proxy(socks.SOCKS5, proxy["host"], proxy["port"])
    sock.connect(("tcpbin.com", 4242))
    sock.sendall(msg)
    got = b""
    while len(got) < len(msg):
        chunk = sock.recv(len(msg) - len(got))
        if not chunk:
            break
        got += chunk
    sock.close()
    assert got == msg, f"Sanity check failed: sent {msg!r}, received {got!r}"


# ---------------------------------------------------------------------------
# Client misbehaviour
# ---------------------------------------------------------------------------

class TestClientMisbehaviour:
    """
    What happens when clients connect to the proxy and then misbehave?
    After each scenario the proxy must remain stable and keep accepting
    new connections (verified by proxy_sanity_check).
    """

    def test_immediate_close_no_data(self, proxy):
        """
        Client opens a TCP connection to the proxy port then closes it
        immediately without sending a single byte.
        """
        s = socket.create_connection((proxy["host"], proxy["port"]), timeout=5)
        s.close()

        proxy_sanity_check(proxy)

    def test_partial_socks_greeting_then_close(self, proxy):
        """
        Client sends only the VER byte of the two-byte SOCKS5 greeting
        and then closes.  The proxy's recvall must not block forever.
        """
        s = socket.create_connection((proxy["host"], proxy["port"]), timeout=5)
        s.sendall(b"\x05")   # VER only — NMETHODS never arrives
        time.sleep(0.1)
        s.close()

        proxy_sanity_check(proxy)

    def test_wrong_socks_version(self, proxy):
        """
        Client sends a SOCKS4 greeting instead of SOCKS5.
        The proxy should reject and close without crashing.
        """
        s = socket.create_connection((proxy["host"], proxy["port"]), timeout=5)
        s.settimeout(3)
        # SOCKS4 CONNECT to 127.0.0.1:80
        s.sendall(b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")
        try:
            # proxy may send a rejection byte or just close
            s.recv(16)
        except (socket.timeout, OSError):
            pass
        s.close()

        proxy_sanity_check(proxy)

    def test_valid_greeting_then_garbage_request(self, proxy):
        """
        Client completes the SOCKS5 no-auth handshake but then sends
        garbage bytes instead of a valid CONNECT request.
        """
        s = socket.create_connection((proxy["host"], proxy["port"]), timeout=5)
        s.settimeout(5)

        s.sendall(b"\x05\x01\x00")      # greeting
        resp = s.recv(2)
        assert resp == b"\x05\x00", f"Unexpected greeting reply: {resp!r}"

        s.sendall(b"\xde\xad\xbe\xef" * 4)   # garbage request
        time.sleep(0.1)
        s.close()

        proxy_sanity_check(proxy)

    def test_no_application_data_after_socks_connect(self, proxy):
        """
        Client completes the full SOCKS5 CONNECT (gets a tunnel) but then
        never sends any application data and just closes.
        """
        with local_echo_server() as (dst_host, dst_port):
            s = socks5_connect_ipv4(proxy["host"], proxy["port"], dst_host, dst_port)
            time.sleep(0.2)
            s.close()

        proxy_sanity_check(proxy)

    def test_abrupt_disconnect_during_upload(self, proxy):
        """
        Client starts sending a large upload through the proxy and then
        abruptly closes with SO_LINGER(0) (TCP RST) mid-transfer.
        The proxy must handle the OSError / ECONNRESET and stay alive.
        """
        with local_echo_server() as (dst_host, dst_port):
            s = socks5_connect_ipv4(proxy["host"], proxy["port"], dst_host, dst_port)
            s.sendall(b"X" * 65536)

            # Force RST instead of graceful FIN
            linger = struct.pack("ii", 1, 0)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
            except OSError:
                pass  # not all platforms support this on all socket types
            s.close()

        time.sleep(0.3)
        proxy_sanity_check(proxy)

    def test_close_while_receiving_response(self, proxy):
        """
        Client receives part of a large response and then closes the
        connection before the server is done sending.
        """
        with local_echo_server() as (dst_host, dst_port):
            s = socks5_connect_ipv4(proxy["host"], proxy["port"], dst_host, dst_port)
            s.settimeout(5)

            payload = b"R" * 65536
            s.sendall(payload)

            # Read only a small fraction, then bail out
            s.recv(1024)
            s.close()

        time.sleep(0.3)
        proxy_sanity_check(proxy)


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------

class TestConcurrency:
    """
    Multiple clients operating through the proxy simultaneously.
    Catches race conditions in PipeManager (event queue, pipe dict, locks).
    """

    def test_simultaneous_connections(self, proxy):
        """
        N clients all connected through the proxy at the same time.
        Each must receive its own data back correctly (no cross-contamination).
        """
        N = 10
        errors = []

        with local_echo_server() as (dst_host, dst_port):
            barrier = threading.Barrier(N)

            def run_one(i):
                try:
                    msg = f"concurrent-{i:04d}\n".encode()
                    s = socks5_connect_ipv4(
                        proxy["host"], proxy["port"], dst_host, dst_port, timeout=10
                    )
                    s.settimeout(10)
                    barrier.wait(timeout=10)   # all N connected before anyone sends
                    s.sendall(msg)
                    got = b""
                    while len(got) < len(msg):
                        chunk = s.recv(len(msg) - len(got))
                        if not chunk:
                            break
                        got += chunk
                    s.close()
                    if got != msg:
                        errors.append(f"[{i}] sent {msg!r}, got {got!r}")
                except Exception as exc:
                    errors.append(f"[{i}] {exc}")

            threads = [
                threading.Thread(target=run_one, args=(i,), daemon=True)
                for i in range(N)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)

        assert not errors, "\n".join(errors)

    def test_rapid_connection_churn(self, proxy):
        """
        Many short-lived connections in rapid succession.
        Catches resource leaks (file descriptors, threads, pipe entries).
        """
        N = 30

        with local_echo_server() as (dst_host, dst_port):
            for i in range(N):
                msg = f"churn-{i}\n".encode()
                s = socks5_connect_ipv4(
                    proxy["host"], proxy["port"], dst_host, dst_port, timeout=10
                )
                s.settimeout(5)
                s.sendall(msg)
                got = b""
                while len(got) < len(msg):
                    chunk = s.recv(len(msg) - len(got))
                    if not chunk:
                        break
                    got += chunk
                s.close()
                assert got == msg, f"Churn [{i}]: sent {msg!r}, got {got!r}"

    def test_mixed_bad_and_good_connections(self, proxy):
        """
        Bad connections (immediate close, garbage) interleaved with good
        ones.  Good connections must continue working throughout.
        """
        errors = []

        with local_echo_server() as (dst_host, dst_port):
            def bad_client():
                try:
                    s = socket.create_connection(
                        (proxy["host"], proxy["port"]), timeout=5
                    )
                    s.sendall(b"\x04garbage")
                    time.sleep(0.05)
                    s.close()
                except OSError:
                    pass

            def good_client(i):
                try:
                    msg = f"good-{i}\n".encode()
                    s = socks5_connect_ipv4(
                        proxy["host"], proxy["port"], dst_host, dst_port, timeout=10
                    )
                    s.settimeout(10)
                    s.sendall(msg)
                    got = b""
                    while len(got) < len(msg):
                        chunk = s.recv(len(msg) - len(got))
                        if not chunk:
                            break
                        got += chunk
                    s.close()
                    if got != msg:
                        errors.append(f"good-{i}: got {got!r}")
                except Exception as exc:
                    errors.append(f"good-{i}: {exc}")

            threads = []
            for i in range(10):
                threads.append(threading.Thread(target=bad_client, daemon=True))
                threads.append(threading.Thread(target=good_client, args=(i,), daemon=True))

            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)

        assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# Data integrity
# ---------------------------------------------------------------------------

class TestDataIntegrity:
    """Verify that data arrives at the destination unchanged."""

    def test_large_data_transfer(self, proxy):
        """
        Transfer 1 MB through the proxy and verify every byte arrives intact.
        Catches buffer management bugs in the Pipe / PipeManager.
        """
        payload = bytes(range(256)) * 4096   # 1 048 576 bytes, non-trivial pattern

        with local_echo_server() as (dst_host, dst_port):
            s = socks5_connect_ipv4(
                proxy["host"], proxy["port"], dst_host, dst_port, timeout=30
            )
            s.settimeout(30)
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)   # tell the echo server we're done sending

            received = bytearray()
            while len(received) < len(payload):
                chunk = s.recv(4096)
                if not chunk:
                    break
                received.extend(chunk)
            s.close()

        assert bytes(received) == payload, (
            f"Data mismatch: sent {len(payload)} B, "
            f"received {len(received)} B"
        )

    def test_many_small_messages(self, proxy):
        """
        Many small messages sent sequentially over a single connection.
        Catches framing bugs where messages from one exchange bleed into
        the next.
        """
        N = 200

        with local_echo_server() as (dst_host, dst_port):
            s = socks5_connect_ipv4(
                proxy["host"], proxy["port"], dst_host, dst_port, timeout=30
            )
            s.settimeout(10)

            for i in range(N):
                msg = f"msg-{i:05d}\n".encode()
                s.sendall(msg)
                got = b""
                while len(got) < len(msg):
                    chunk = s.recv(len(msg) - len(got))
                    if not chunk:
                        pytest.fail(f"Connection closed early at message {i}")
                    got += chunk
                assert got == msg, f"Message {i}: got {got!r}"

            s.close()


# ---------------------------------------------------------------------------
# TLS MITM
# ---------------------------------------------------------------------------

class TestTlsMitm:
    """
    Tests for the TLS interception path.
    The proxy generates leaf certificates on the fly and performs two TLS
    handshakes (one with the client using a fake cert, one with the real server).
    """

    def test_tls_connection_closes_without_sending_data(self, proxy, ca_cert):
        """
        Client completes the TLS handshake through the proxy (which performs
        MITM with a generated cert) but then closes without sending any
        application data.  The proxy must not crash or hang.
        """
        sock = socks.socksocket()
        sock.settimeout(10)
        sock.set_proxy(socks.SOCKS5, proxy["host"], proxy["port"])
        sock.connect(("tcpbin.com", 4243))

        ctx = ssl.create_default_context(cafile=str(ca_cert))
        tls = ctx.wrap_socket(sock, server_hostname="tcpbin.com")
        # No data sent — just tear down
        tls.close()

        proxy_sanity_check(proxy)

    def test_multiple_concurrent_https_requests(self, proxy, ca_cert):
        """
        Several HTTPS requests through the proxy at the same time.
        Catches cert-cache races and concurrent pipe bugs in the TLS path.
        """
        N = 4
        errors = []

        def make_request(i):
            try:
                resp = requests.get(
                    "https://www.google.com/",
                    proxies={
                        "http": f"socks5h://{proxy['host']}:{proxy['port']}",
                        "https": f"socks5h://{proxy['host']}:{proxy['port']}",
                    },
                    headers={"Accept-Encoding": "identity"},
                    verify=str(ca_cert),
                    timeout=30,
                )
                if resp.status_code != 200:
                    errors.append(f"[{i}] HTTP {resp.status_code}")
            except Exception as exc:
                errors.append(f"[{i}] {exc}")

        threads = [
            threading.Thread(target=make_request, args=(i,), daemon=True)
            for i in range(N)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        assert not errors, "\n".join(errors)

    def test_https_after_failed_tls_client(self, proxy, ca_cert):
        """
        A client that aborts the TLS handshake (closes the connection right
        after SOCKS CONNECT but before completing TLS) must not poison the
        cert cache or break subsequent legitimate HTTPS connections.
        """
        # Aborted TLS client: connects but never sends a ClientHello
        sock = socks.socksocket()
        sock.settimeout(5)
        sock.set_proxy(socks.SOCKS5, proxy["host"], proxy["port"])
        sock.connect(("tcpbin.com", 4243))
        # Close immediately without doing a TLS handshake
        sock.close()

        time.sleep(0.3)

        # Legitimate TLS request must still work
        sock2 = socks.socksocket()
        sock2.settimeout(10)
        sock2.set_proxy(socks.SOCKS5, proxy["host"], proxy["port"])
        sock2.connect(("tcpbin.com", 4243))
        ctx = ssl.create_default_context(cafile=str(ca_cert))
        with ctx.wrap_socket(sock2, server_hostname="tcpbin.com") as tls:
            tls.sendall(b"hello after abort\n")
            got = tls.recv(64)
        assert got == b"hello after abort\n"

    def test_https_request_repeated_same_domain(self, proxy, ca_cert):
        """
        Two sequential HTTPS requests to the same domain go through the proxy.
        The second request should reuse the cached leaf certificate.
        Both must succeed.
        """
        proxies = {
            "http": f"socks5h://{proxy['host']}:{proxy['port']}",
            "https": f"socks5h://{proxy['host']}:{proxy['port']}",
        }
        for i in range(2):
            resp = requests.get(
                "https://www.google.com/",
                proxies=proxies,
                headers={"Accept-Encoding": "identity"},
                verify=str(ca_cert),
                timeout=30,
            )
            assert resp.status_code == 200, f"Request {i+1} failed: {resp.status_code}"
