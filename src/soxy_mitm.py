import logging
import socket
import sys
from typing import Tuple

from cert_manager import CertManager
from core import AutoThread, SafeSocket
from net import socks, ssl, tls
from pipe_manager import PipeManager

logger = logging.getLogger(__name__)

CERTS_PATH = "certs"
ROOT_CERT = "encripton.pem"
ROOT_KEY = "encripton.key"

class Soxy():
    """ Manage exit status """
    def __init__(self, local_addr: str, local_port):
        self._halt = False
        self.local_addr = local_addr
        self.local_port = local_port

        # Configure MITM pipes manager
        self.pipemanager = PipeManager()

        # Configure root certs
        self.certmanager = CertManager(cert_cache_dir=CERTS_PATH, root_cert=ROOT_CERT, root_key=ROOT_KEY)
        if not self.certmanager.is_cert_valid(ROOT_CERT):
            self.certmanager.create_root_cert()

        # Creat the main socket
        self.main_socket = SafeSocket.create()

        # Bind the socket to address and listen for connections made to the socket
        try:
            logger.info(f'Bind {self.local_port}')
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
        if sni:
            logger.info(f"SNI: {sni}")
            logger.info(f"ALPN: {repr(alpn_list)}")

            # domain = dst_addr.decode() if isinstance(dst_addr, bytes) else dst_addr
            # TODO: check if domain matches sni

            logger.info(f"Generating spoofed cert for {sni}")
            cert_path, key_path = self.certmanager.get_or_generate_cert(sni)

            # wrap client socket with fake cert
            client_socket = ssl.wrap_local(client_socket, cert_path=cert_path, key_path=key_path)

            # wrap server socket with default client-side SSL
            target_socket = ssl.wrap_target(target_socket, sni)

        pipe = socks.Pipe(client_socket, target_socket)
        self.pipemanager.add(pipe)
        pipe.start()

    def start(self):
        while not self._halt:
            try:
                logger.info("Waiting for connection...")
                client_socket, addr = self.main_socket.accept()
                logger.info(f"Got connection from {addr}")
            except socket.error:
                self.stop()
                continue

            AutoThread(target=self.handle_client, args=[client_socket], tname="<->")

    def stop(self):
        try:
            for pipe in self.pipemanager.pipes:
                pipe.stop()

            self._halt = True
            self.main_socket.close()
        except Exception:
            pass