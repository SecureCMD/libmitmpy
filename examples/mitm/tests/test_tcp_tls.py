import ssl

import socks


def test_tcp_tls_through_proxy(proxy, ca_cert):
    host = "tcpbin.com"
    port = 4243

    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, proxy["host"], proxy["port"])
    sock.connect((host, port))

    context = ssl.create_default_context(cafile=str(ca_cert))
    with context.wrap_socket(sock, server_hostname=host) as s:
        s.sendall(b"hello world\n")
        data = s.recv(1024)
        assert data == b"hello world\n"
