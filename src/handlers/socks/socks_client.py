import logging
import socket
from struct import pack, unpack
from typing import Tuple

from safe_socket import SafeSocket

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

logger = logging.getLogger(__name__)

class SocksClient:
    def __init__(self, socket: SafeSocket):
        self.socket = socket


    def handshake(self) -> bool:
        # header sent by the client
        # +-----+----------+---------+
        # | VER | NMETHODS | METHODS |
        # +-----+----------+---------+
        try:
            header = self.socket.recvall(2)
            ver, nmethods = header[0:1], header[1]
            if ver != VER or nmethods == 0:
                self.socket.sendall(ver + M_NOTAVAILABLE)
                self.socket.close()
                return
            else:
                methods = self.socket.recvall(nmethods)
                if M_NOAUTH not in methods:
                    logger.warning("We support only M_NOAUTH method, aborting connection and closing socket...")
                    self.socket.sendall(VER + M_NOTAVAILABLE)
                    self.socket.close()
                    return False
        except Exception as ex:
            logger.error("Something unexpected happened, handle it", ex)
            self.socket.close()
            return False

        # reply sent by us
        # +-----+--------+
        # | VER | METHOD |
        # +-----+--------+
        try:
            self.socket.sendall(VER + M_NOAUTH)
        except Exception as ex:
            logger.error("Something unexpected happened, handle it", ex)
            self.socket.close()
            return False

        return True

    def get_request_details(self) -> Tuple[bytes, int]:
        # +-----+-----+-----+------+----------+----------+
        # | VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
        # +-----+-----+-----+------+----------+----------+
        try:
            header = self.socket.recvall(4)
            ver, cmd, rsv, atyp = header[0:1], header[1:2], header[2:3], header[3:4]
        except ConnectionResetError:
            if self.socket != 0:
                self.socket.close()
            return b"", 0

        if ver != VER or cmd != CMD_CONNECT or rsv != b'\x00':
            return b"", 0

        if atyp == ATYP_IPV4:
            target = self.socket.recvall(6)
            dst_addr = socket.inet_ntoa(target[:-2])
            dst_port = unpack('>H', target[-2:])[0]
        elif atyp == ATYP_DOMAINNAME:
            size = self.socket.recvall(1)
            target = self.socket.recvall(size[0] + 2)
            dst_addr = target[0:-2]
            dst_port = unpack('>H', target[-2:])[0]
        elif atyp == ATYP_IPV6:
            target = self.socket.recvall(16)
            dst_addr = socket.inet_ntop(target[:-2])
            dst_port = unpack('>H', target[-2:])[0]
        else:
            return b"", 0

        return dst_addr, dst_port

    def reply_with_invalid_dst_addr(self):
        reply = VER + b'\x01' + b'\x00' + ATYP_IPV4 + b'\x00' * 6
        self.socket.sendall(reply)
        self.socket.close()


    def connect_to_dst(self, dst_addr: str, dst_port: int) -> SafeSocket:
        # Server Reply
        # +-----+-----+-----+------+----------+----------+
        # | VER | REP | RSV | ATYP | BND.ADDR | BND.PORT |
        # +-----+-----+-----+------+----------+----------+
        socket_dst: SafeSocket = SafeSocket.create()

        try:
            socket_dst.connect((dst_addr, dst_port))
        except socket.error as err:
            self.error("Failed to connect to DST", err)
            return None

        if not socket_dst:
            reply = VER + b'\x01' + b'\x00' + ATYP_IPV4 + b'\x00' * 6
            self.socket.sendall(reply)
            self.socket.close()
            return None

        bnd = socket.inet_aton(socket_dst.getsockname()[0])
        bnd += pack(">H", socket_dst.getsockname()[1])

        reply = VER + b'\x00' + b'\x00' + ATYP_IPV4 + bnd

        self.socket.sendall(reply)
        return socket_dst