import ssl

import socks

host = 'tcpbin.com'
port = 4243
# pem = "encripton.pem"
pem = "/Users/alexandernst/.mitmproxy/mitmproxy-ca.pem"

proxy_host = "localhost"
proxy_port = 9090

sock = socks.socksocket()
sock.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
sock.connect((host, port))

context = ssl.create_default_context(cafile=pem)
with context.wrap_socket(sock, server_hostname=host) as s:
    s.sendall(b'hello world\n')
    data = s.recv(1024)
    print(f"Received: {data.decode()}")