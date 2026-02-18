import socks


def test_tcp_through_proxy(proxy):
    host = "tcpbin.com"
    port = 4242

    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, proxy["host"], proxy["port"])
    sock.connect((host, port))

    sock.sendall(b"hello world\n")
    data = sock.recv(1024)
    assert data == b"hello world\n"
