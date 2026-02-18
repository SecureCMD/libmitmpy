import logging
import socket

from cert_manager import CertManager
from core import AutoThread, SafeConnection, SafeSocket
from net import socks, tls
from pipe_manager import PipeManager

logger = logging.getLogger(__name__)


class Encripton:
    """Manage exit status"""

    def __init__(self, local_addr: str, local_port):
        self._halt = False
        self.local_addr = local_addr
        self.local_port = local_port

        # Configure MITM pipes manager
        self.pipemanager = PipeManager()

        # Configure root certs
        self.certmanager = CertManager()
        if not self.certmanager.is_root_cert_valid() or not self.certmanager.is_root_cert_trusted():
            self.certmanager.create_root_cert()
            self.certmanager.install_root_cert()

        # Creat the main socket
        self.main_socket = SafeSocket.create()

        # Bind the socket to address and listen for connections made to the socket
        try:
            logger.info(f"Bind {self.local_port}")
            self.main_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.main_socket.bind((self.local_addr, self.local_port))
        except socket.error as err:
            logger.error("Bind failed", err)
            self.main_socket.close()
            raise Exception
        # Listen
        try:
            self.main_socket.listen()
        except socket.error as err:
            logger.error("Listen failed", err)
            self.main_socket.close()
            self._halt = True
            raise Exception

    def handle_client(self, client_socket: SafeSocket):
        """
        The client connects to the server and sends a header that contains the
        protocol version and the auth methods that it supports. Then the server
        must either reject the connection or reply with the selected verion and
        auth method.
        """
        client = socks.Client(client_socket)
        handshake = client.handshake()

        if not handshake:
            logger.error("I wasn't able to handshake with the client...")
            return

        dst_addr, dst_port = client.get_request_details()

        if not dst_addr:
            logger.error("Client didn't request a valid dst_addr, aborting...")
            client.reply_with_invalid_dst_addr()
            return

        logger.info(f"Client wants to connect to {dst_addr}, {dst_port}")

        target_socket = client.connect_to_dst(dst_addr, dst_port)

        if not target_socket:
            logger.error(f"I wasn't able to connect to {dst_addr}:{dst_port}, aborting...")
            return

        # Try to check if this is TLS/SSL
        # Parse the SNI / ALPN here and get the protocol and the hostname...
        sni, alpn_list = tls.get_sni_alpn(client_socket)
        if not sni:
            logger.info(f"Creating plain text pipe for sockets [{client_socket}, {target_socket}]")
            metainfo = socks.PipeMetaInfo(
                dst_addr=dst_addr,
                dst_port=dst_port,
            )
            pipe = socks.Pipe(downstream=client_socket, upstream=target_socket, metainfo=metainfo)
        else:
            logger.info(f"SNI: {sni}")
            logger.info(f"ALPN: {repr(alpn_list)}")

            # domain = dst_addr.decode() if isinstance(dst_addr, bytes) else dst_addr
            # TODO: check if domain matches sni

            cert_pem, key_pem = self.certmanager.get_or_generate_cert(sni)

            # wrap client socket with fake cert
            client_conn = SafeConnection(client_socket)
            client_conn.wrap_local(cert_pem=cert_pem, key_pem=key_pem)

            # wrap server socket with default client-side SSL
            target_conn = SafeConnection(target_socket)
            target_conn.wrap_target(sni)

            logger.info(f"Creating secure pipe for sockets [{client_conn}, {target_conn}]")
            metainfo = socks.PipeMetaInfo(
                dst_addr=dst_addr,
                dst_port=dst_port,
                sni=sni,
                alpn_list=alpn_list,
            )
            pipe = socks.Pipe(downstream=client_conn, upstream=target_conn, metainfo=metainfo)

        self.pipemanager.add(pipe)

    def start(self):
        while not self._halt:
            try:
                logger.info("Waiting for connection...")
                client_socket, addr = self.main_socket.accept()
                logger.info(f"Got connection from {addr}")
            except socket.error:
                self.stop()
                continue

            AutoThread(target=self.handle_client, args=[client_socket], name="<->")

    def stop(self):
        if self._halt:
            return

        self._halt = True

        try:
            self.pipemanager.stop_all()
            self.main_socket.close()
        except Exception:
            pass
