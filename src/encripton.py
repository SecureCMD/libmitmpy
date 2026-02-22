import inspect
import logging
import socket
import uuid
from pathlib import Path
from typing import Callable, Optional, Tuple, Type

import psutil

from cert_manager import CertManager
from core import AutoThread, SafeConnection, SafeSocket
from db import Database
from handlers import ConnectionHandler, ConnectionMeta
from net import socks, tls
from pipe_manager import PipeManager
from traffic_logger import TrafficLogger

logger = logging.getLogger(__name__)


class Encripton:
    """Manage exit status"""

    def __init__(
        self,
        local_addr: str,
        local_port,
        app_id: str,
        data_dir: Path,
        handler: Optional[Type[ConnectionHandler] | Callable[[ConnectionMeta], Optional[Type[ConnectionHandler]]]] = None,
    ):
        self._halt = False
        self.local_addr = local_addr
        self.local_port = local_port
        self.app_id = app_id
        self.data_dir = data_dir
        self._handler_selector = self._resolve_selector(handler)

        # Shared database (certs + traffic)
        self.db = Database(data_dir / "data.db")

        # Configure root certs
        self.certmanager = CertManager(data_dir=data_dir, app_id=app_id, db_conn=self.db.connection)
        if not self.certmanager.is_root_cert_valid() or not self.certmanager.is_root_cert_trusted():
            self.certmanager.create_root_cert()
            self.certmanager.install_root_cert()

        # Configure MITM pipes manager with traffic logger
        self._traffic_logger = TrafficLogger(self.db)
        self.pipemanager = PipeManager(traffic_logger=self._traffic_logger)

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

    @staticmethod
    def _resolve_selector(handler):
        """Normalise the handler argument into a selector callable.

        Accepts:
          - None                    → every connection is passed through unchanged
          - A ConnectionHandler subclass → every connection uses that class
          - A callable (meta) → Type | None → per-connection routing
        """
        if handler is None:
            return lambda meta: None
        if inspect.isclass(handler) and issubclass(handler, ConnectionHandler):
            return lambda meta: handler
        if callable(handler):
            return handler
        raise TypeError(
            f"handler must be a ConnectionHandler subclass or a callable "
            f"(ConnectionMeta) -> Type[ConnectionHandler] | None, got {type(handler)}"
        )

    @staticmethod
    def _get_client_process(client_socket: SafeSocket) -> Tuple[Optional[int], Optional[str]]:
        try:
            _, src_port = client_socket.getpeername()
            for conn in psutil.net_connections(kind="tcp"):
                if conn.laddr.port == src_port and conn.pid is not None:
                    return conn.pid, psutil.Process(conn.pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
        return None, None

    def handle_client(self, client_socket: SafeSocket):
        """
        The client connects to the server and sends a header that contains the
        protocol version and the auth methods that it supports. Then the server
        must either reject the connection or reply with the selected verion and
        auth method.
        """
        pid, process_name = self._get_client_process(client_socket)
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
                pid=pid,
                process_name=process_name,
            )
            pipe = socks.Pipe(downstream=client_socket, upstream=target_socket, metainfo=metainfo)
        else:
            logger.info(f"SNI: {sni}")
            logger.info(f"ALPN: {repr(alpn_list)}")

            # domain = dst_addr.decode() if isinstance(dst_addr, bytes) else dst_addr
            # TODO: check if domain matches sni

            cert_pem, key_pem = self.certmanager.get_or_generate_cert(sni)
            ca_cert_pem = self.certmanager.get_root_cert_pem()

            # wrap client socket with fake cert
            client_conn = SafeConnection(client_socket)
            client_conn.wrap_local(cert_pem=cert_pem, key_pem=key_pem, ca_cert_pem=ca_cert_pem)

            # wrap server socket with default client-side SSL
            target_conn = SafeConnection(target_socket)
            target_conn.wrap_target(sni)

            logger.info(f"Creating secure pipe for sockets [{client_conn}, {target_conn}]")
            metainfo = socks.PipeMetaInfo(
                dst_addr=dst_addr,
                dst_port=dst_port,
                sni=sni,
                alpn_list=alpn_list,
                pid=pid,
                process_name=process_name,
            )
            pipe = socks.Pipe(downstream=client_conn, upstream=target_conn, metainfo=metainfo)

        # Build ConnectionMeta and resolve the handler for this connection
        dst_addr_str = dst_addr.decode("utf-8", errors="replace") if isinstance(dst_addr, bytes) else dst_addr
        meta = ConnectionMeta(
            id=str(uuid.uuid4()),
            dst_addr=dst_addr_str,
            dst_port=dst_port,
            sni=sni,
            alpn=list(alpn_list) if alpn_list else [],
            is_tls=sni is not None,
            pid=pid,
            process_name=process_name,
        )

        handler_class = self._handler_selector(meta)
        handler_instance = None
        if handler_class is not None:
            handler_instance = handler_class()
            handler_instance.meta = meta
            handler_instance._pipe = pipe

        self.pipemanager.add(pipe, handler_instance)

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
