import ssl

from safe_socket import SafeSocket


def wrap_local(socket, cert_path=None, key_path=None):
    c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    socket = c_ctx.wrap_socket(socket, server_side=True)

    # SSL and timeouts are a nightmare. Just disable it completely and
    # let the proxy loop handle any fuckups
    socket.settimeout(None)

    return SafeSocket(socket)


def wrap_target(socket, domain):
    s_ctx = ssl.create_default_context()
    s_ctx.check_hostname = False
    s_ctx.verify_mode = ssl.CERT_NONE
    socket = s_ctx.wrap_socket(socket, server_hostname=domain)

    # SSL and timeouts are a nightmare. Just disable it completely and
    # let the proxy loop handle any fuckups
    socket.settimeout(None)

    return SafeSocket(socket)