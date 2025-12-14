import socks

host = "tcpbin.com"
port = 4242

proxy_host = "localhost"
proxy_port = 9090

sock = socks.socksocket()
sock.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
sock.connect((host, port))

sock.sendall(b"hello world\n")
data = sock.recv(1024)
print(f"Received back: {data.decode()}")
