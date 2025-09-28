import logging
# Network
import socket
import ssl
import sys
# System
from struct import pack, unpack
from typing import Tuple

from autothread import AutoThread
from certs_manager import Manager
from safe_socket import SafeSocket

logger = logging.getLogger(__name__)

#
# Configuration
#
CERTS_PATH = "certs"
ROOT_CERT = "encripton.pem"
ROOT_KEY = "encripton.key"

BUFSIZE = 2048
TIMEOUT_SOCKET = 5

# --- Version of the protocol ---
VER = b'\x05' # PROTOCOL VERSION
# --- Method constants ---
M_NOAUTH = b'\x00' # NO AUTHENTICATION REQUIRED
M_AUTH = b'\x02' # USER / PASSWORD AUTHENTICATION
M_NOTAVAILABLE = b'\xff' # NO ACCEPTABLE METHODS
# --- Command constants ---
CMD_CONNECT = b'\x01' # CONNECT
# --- Address type constants ---
ATYP_IPV4 = b'\x01' # IPv4 address
ATYP_DOMAINNAME = b'\x03' # DOMAINNAME
ATYP_IPV6 = b'\x04' # IPv6 address

class Soxy():
    """ Manage exit status """
    def __init__(self, local_addr: str, local_port):
        self.halt = False
        self.local_addr = local_addr
        self.local_port = local_port

        # Configure root certs
        self.cmanager = Manager(cert_cache_dir=CERTS_PATH, root_cert=ROOT_CERT, root_key=ROOT_KEY)
        if not self.cmanager.is_cert_valid(ROOT_CERT):
            self.cmanager.create_root_cert()

        # Creat the main socket
        self.main_socket = self._create_socket()

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

    def _create_socket(self) -> SafeSocket:
        """ Create an INET, STREAMing socket """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock = SafeSocket(sock)
            sock.settimeout(TIMEOUT_SOCKET)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except socket.error as err:
            self.error("Failed to create socket", err)
            raise Exception
        return sock


    def _socket_handshake(self, conn_socket: socket.socket) -> bool:
        # header sent by the client
        # +-----+----------+---------+
        # | VER | NMETHODS | METHODS |
        # +-----+----------+---------+
        try:
            header = conn_socket.recvall(2)
            ver, nmethods = header[0:1], header[1]
            if ver != VER or nmethods == 0:
                conn_socket.sendall(ver + M_NOTAVAILABLE)
                conn_socket.close()
                return
            else:
                methods = conn_socket.recvall(nmethods)
                if M_NOAUTH not in methods:
                    logger.warning("We support only M_NOAUTH method, aborting connection and closing socket...")
                    conn_socket.sendall(VER + M_NOTAVAILABLE)
                    conn_socket.close()
                    return False
        except Exception as ex:
            logger.error("Something unexpected happened, handle it", ex)
            conn_socket.close()
            return False

        # reply sent by us
        # +-----+--------+
        # | VER | METHOD |
        # +-----+--------+
        try:
            conn_socket.sendall(VER + M_NOAUTH)
        except Exception as ex:
            logger.error("Something unexpected happened, handle it", ex)
            conn_socket.close()
            return False

        return True


    def _get_request_details(self, conn_socket: socket.socket) -> Tuple[bytes, int]:
        # +-----+-----+-----+------+----------+----------+
        # | VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
        # +-----+-----+-----+------+----------+----------+
        try:
            header = conn_socket.recvall(4)
            ver, cmd, rsv, atyp = header[0:1], header[1:2], header[2:3], header[3:4]
        except ConnectionResetError:
            if conn_socket != 0:
                conn_socket.close()
            return b"", 0

        if ver != VER or cmd != CMD_CONNECT or rsv != b'\x00':
            return b"", 0

        if atyp == ATYP_IPV4:
            target = conn_socket.recvall(6)
            dst_addr = socket.inet_ntoa(target[:-2])
            dst_port = unpack('>H', target[-2:])[0]
        elif atyp == ATYP_DOMAINNAME:
            size = conn_socket.recvall(1)
            target = conn_socket.recvall(size[0] + 2)
            dst_addr = target[0:-2]
            dst_port = unpack('>H', target[-2:])[0]
        elif atyp == ATYP_IPV6:
            target = conn_socket.recvall(16)
            dst_addr = socket.inet_ntop(target[:-2])
            dst_port = unpack('>H', target[-2:])[0]
        else:
            return b"", 0

        return dst_addr, dst_port


    def _connect_to_dst(self, conn_socket: socket.socket, dst_addr: str, dst_port: int) -> SafeSocket:
        # Server Reply
        # +-----+-----+-----+------+----------+----------+
        # | VER | REP | RSV | ATYP | BND.ADDR | BND.PORT |
        # +-----+-----+-----+------+----------+----------+
        socket_dst: SafeSocket = self._create_socket()

        try:
            socket_dst.connect((dst_addr, dst_port))
        except socket.error as err:
            self.error("Failed to connect to DST", err)
            return None

        if not socket_dst:
            reply = VER + b'\x01' + b'\x00' + ATYP_IPV4 + b'\x00' * 6
            conn_socket.sendall(reply)
            conn_socket.close()
            return None

        bnd = socket.inet_aton(socket_dst.getsockname()[0])
        bnd += pack(">H", socket_dst.getsockname()[1])

        reply = VER + b'\x00' + b'\x00' + ATYP_IPV4 + bnd

        conn_socket.sendall(reply)
        return socket_dst

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

    def handle_conn_socket(self, conn_socket: SafeSocket):
        """
        The client connects to the server and sends a header that contains the
        protocol version and the auth methods that it supports. Then the server
        must either reject the connection or reply with the selected verion and
        auth method.
        """

        logger.info("Handling conn socket...")

        handshake = self._socket_handshake(conn_socket)

        if not handshake:
            return

        dst_addr, dst_port = self._get_request_details(conn_socket)

        if not dst_addr:
            logger.error("Client didn't request a valid dst_addr, aborting...")
            reply = VER + b'\x01' + b'\x00' + ATYP_IPV4 + b'\x00' * 6
            conn_socket.sendall(reply)
            conn_socket.close()
            return

        logger.info(f"Client wants to connect to {dst_addr}, {dst_port}")

        socket_dst = self._connect_to_dst(conn_socket, dst_addr, dst_port)

        if not socket_dst:
            logger.error(f"I wasn't able to connect to {dst_addr}:{dst_port}, aborting...")
            return

        if dst_port == 443:
            domain = dst_addr.decode() if isinstance(dst_addr, bytes) else dst_addr
            # logger.info(f"Intercepting TCP packet for {domain}")
            cert_path, key_path = self.cmanager.get_or_generate_cert(domain)

            # wrap client socket with fake cert
            c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            c_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            conn_socket = c_ctx.wrap_socket(conn_socket, server_side=True)
            # SSL and timeouts are a nightmare. Just disable it completely and
            # let the proxy loop handle any fuckups
            conn_socket.settimeout(None)
            conn_socket = SafeSocket(conn_socket)

            # wrap server socket with default client-side SSL
            s_ctx = ssl.create_default_context()
            s_ctx.check_hostname = False
            s_ctx.verify_mode = ssl.CERT_NONE
            socket_dst = s_ctx.wrap_socket(socket_dst, server_hostname=domain)
            # SSL and timeouts are a nightmare. Just disable it completely and
            # let the proxy loop handle any fuckups
            socket_dst.settimeout(None)
            socket_dst = SafeSocket(socket_dst)

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
        return SafeSocket(conn_socket), addr

    def run(self):
        while not self.halt:
            try:
                conn_socket, addr = self.wait_for_connection()
            except socket.timeout:
                continue
            except socket.error:
                self.stop()
                continue
            except TypeError:
                self.stop()
                sys.exit(0)

            AutoThread(target=self.handle_conn_socket, args=[conn_socket])

    def stop(self):
        try:
            self.halt = True
            self.main_socket.close()
        except Exception:
            pass
