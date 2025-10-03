import logging
import socket
import sys
from typing import Tuple

from autothread import AutoThread
from cert_manager import CertManager
from handlers import socks, ssl, tls
from safe_socket import SafeSocket

logger = logging.getLogger(__name__)

CERTS_PATH = "certs"
ROOT_CERT = "encripton.pem"
ROOT_KEY = "encripton.key"

BUFSIZE = 2048

class Soxy():
    """ Manage exit status """
    def __init__(self, local_addr: str, local_port):
        self.halt = False
        self.local_addr = local_addr
        self.local_port = local_port

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
            self.halt = True
            raise Exception

    def _pipe(self, reader: SafeSocket, writer: SafeSocket):
        try:
            while not self.halt:
                logger.info("Receiving data")
                data = reader.recv(BUFSIZE)
                if not data:
                    logger.info("No more data to receive!")
                    break
                logger.info(f"Received {data[0:10]}... ({len(data)} bytes)")

                logger.info("Sending data...")
                writer.sendall(data)
        except (OSError, ssl.SSLError):
            pass
        finally:
            reader.close()
            writer.close()

    def handle_conn_socket(self, conn_socket: SafeSocket, client_addr: Tuple[bytes, int]):
        """
        The client connects to the server and sends a header that contains the
        protocol version and the auth methods that it supports. Then the server
        must either reject the connection or reply with the selected verion and
        auth method.
        """

        logger.info("Handling conn socket...")

        socks_client = socks.SocksClient(conn_socket)
        handshake = socks_client.handshake()

        if not handshake:
            return

        dst_addr, dst_port = socks_client.get_request_details()

        if not dst_addr:
            logger.error("Client didn't request a valid dst_addr, aborting...")
            socks_client.reply_with_invalid_dst_addr()
            return

        logger.info(f"Client wants to connect to {dst_addr}, {dst_port}")

        socket_dst = socks_client.connect_to_dst(dst_addr, dst_port)

        if not socket_dst:
            logger.error(f"I wasn't able to connect to {dst_addr}:{dst_port}, aborting...")
            return

        # Try to check if this is TLS/SSL
        # Parse the SNI / ALPN here and get the protocol and the hostname...
        sni, alpn_list = tls.get_sni_alpn(conn_socket)
        if sni:
            logger.info(sni)
            logger.info(alpn_list)

            # domain = dst_addr.decode() if isinstance(dst_addr, bytes) else dst_addr
            # TODO: check if domain matches sni

            cert_path, key_path = self.certmanager.get_or_generate_cert(sni)

            # wrap client socket with fake cert
            conn_socket = ssl.wrap_local(conn_socket, cert_path=cert_path, key_path=key_path)

            # wrap server socket with default client-side SSL
            socket_dst = ssl.wrap_target(socket_dst, sni)

        t1 = AutoThread(target=self._pipe, args=(conn_socket, socket_dst))
        t2 = AutoThread(target=self._pipe, args=(socket_dst, conn_socket))
        t1.join()
        t2.join()

        conn_socket.close()
        socket_dst.close()

    def wait_for_connection(self) -> Tuple[SafeSocket, Tuple[bytes, int]]:
        logger.info("Waiting for connection...")
        conn_socket, addr = self.main_socket.accept()
        logger.info(f"Got connection from {addr}")
        return conn_socket, addr

    def run(self):
        while not self.halt:
            try:
                conn_socket, client_addr = self.wait_for_connection()
            except socket.timeout:
                continue
            except socket.error:
                self.stop()
                continue
            except TypeError:
                self.stop()
                sys.exit(0)

            AutoThread(target=self.handle_conn_socket, args=[conn_socket, client_addr])

    def stop(self):
        try:
            self.halt = True
            self.main_socket.close()
        except Exception:
            pass
        except Exception:
            pass
