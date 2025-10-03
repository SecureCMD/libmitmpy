import logging
import ssl

from autothread import AutoThread
from safe_socket import SafeSocket

BUFSIZE = 2048

logger = logging.getLogger(__name__)

class Pipe:
    def __init__(self, conn_socket: SafeSocket, socket_dst: SafeSocket):
        self._halt = False

        t1 = AutoThread(target=self.pipe, args=(conn_socket, socket_dst))
        t2 = AutoThread(target=self.pipe, args=(socket_dst, conn_socket))
        t1.join()
        t2.join()

        conn_socket.close()
        socket_dst.close()

    def pipe(self, reader: SafeSocket, writer: SafeSocket):
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

    def halt(self):
        self._halt = True