import logging
import ssl
import weakref

from autothread import AutoThread
from safe_socket import SafeSocket

BUFSIZE = 2048

logger = logging.getLogger(__name__)

class Pipe:
    def __init__(self, conn_socket: SafeSocket, socket_dst: SafeSocket, on_pipe_finished: callable):
        self._halt = False
        self._finalizer = weakref.finalize(self, on_pipe_finished, self)

        self.conn_socket = conn_socket
        self.socket_dst = socket_dst

    def start(self):
        t1 = AutoThread(target=self.process, args=(self.conn_socket, self.socket_dst))
        t2 = AutoThread(target=self.process, args=(self.socket_dst, self.conn_socket))
        t1.join()
        t2.join()

        self.conn_socket.close()
        self.socket_dst.close()

    def stop(self):
        self._halt = True

    def process(self, reader: SafeSocket, writer: SafeSocket):
        try:
            while not self._halt:
                logger.info("Receiving data")
                data = reader.recv(BUFSIZE)
                if not data:
                    logger.info("No more data to receive!")
                    # notify parent?
                    break
                logger.info(f"Received {data[0:10]}... ({len(data)} bytes)")

                logger.info("Sending data...")
                writer.sendall(data)
        except (OSError, ssl.SSLError):
            pass
        finally:
            reader.close()
            writer.close()