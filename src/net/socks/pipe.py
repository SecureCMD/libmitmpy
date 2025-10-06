import logging
import socket
import ssl

from core import AutoThread, SafeSocket
from parsers.http import HTTPParser
from transformers.http import HTTPTransformer

BUFSIZE = 2048

logger = logging.getLogger(__name__)

class Pipe:
    def __init__(self, client_socket: SafeSocket, target_socket: SafeSocket, on_pipe_finished: callable):
        self._halt = False
        self._on_finished = on_pipe_finished

        self.client_socket = client_socket
        self.target_socket = target_socket

        self.buffers = {
            (self.client_socket, self.target_socket): bytearray(),
            (self.target_socket, self.client_socket): bytearray(),
        }

        self.parser = HTTPParser()
        self.transformer = HTTPTransformer()

    def start(self):
        t1 = AutoThread(target=self.send, args=(self.client_socket, self.target_socket), tname="->")
        t2 = AutoThread(target=self.receive, args=(self.target_socket, self.client_socket), tname="<-")
        t1.join()
        t2.join()

        self.client_socket.close()
        self.target_socket.close()

        self._on_finished(self)

    def stop(self):
        self._halt = True
        self.client_socket.shutdown(socket.SHUT_RDWR)
        self.target_socket.shutdown(socket.SHUT_RDWR)

    def send(self, reader: SafeSocket, writer: SafeSocket):
        buf = self.buffers[(reader, writer)]

        try:
            while not self._halt:
                logger.debug("Receiving data from local socket...")
                data = reader.recv(BUFSIZE)
                logger.debug(f"Received {len(data)} bytes.")

                if not data:
                    logger.debug("No more data to receive, closing local socket!")
                    # Half-close request side; keep reading server response
                    writer.shutdown(socket.SHUT_WR)
                    break

                buf.extend(data)
                #logger.info(f"Received {data[0:10]}... ({len(data)} bytes)")

                logger.debug(f"Sending {len(buf)} bytes to remote socket...")
                writer.sendall(buf)
                buf.clear()

        except (socket.timeout, TimeoutError):
            pass

        except (OSError, ssl.SSLError):
            logger.error("Something failed, killing MITM receiver...")
            self.stop()


    def receive(self, reader: SafeSocket, writer: SafeSocket):
        buf = self.buffers[(reader, writer)]

        def drain_parsed(eof=False):
            # Try to parse and forward as much as possible from buf
            while True:
                parsed, consumed = self.parser.parse(buf, eof=eof)

                if not parsed:
                    break

                transformed = self.transformer.transform(parsed)

                logger.debug(f"Sending {len(transformed)} to local socket...")
                writer.sendall(transformed)
                del buf[:consumed]

        try:
            while not self._halt:
                logger.debug("Receiving data from remote socket...")
                data = reader.recv(BUFSIZE)
                logger.debug(f"Received {len(data)} bytes.")

                if not data:
                    logger.debug("No more data to receive, closing remote socket!")
                    drain_parsed(eof=True)
                    # Fallback: pass-through any leftover bytes so client isn’t starved
                    if buf:
                        logger.debug(f"{len(buf)} bytes left in the buffer, sending to local socket...")
                        writer.sendall(buf)
                        buf.clear()

                    writer.shutdown(socket.SHUT_WR)
                    break

                buf.extend(data)
                drain_parsed()

        except (socket.timeout, TimeoutError):
            # Treat timeouts as an opportunity to drain parseable data, not as fatal
            drain_parsed()

        except (OSError, ssl.SSLError):
            logger.error("Something failed, killing MITM sender...")
            self.stop()