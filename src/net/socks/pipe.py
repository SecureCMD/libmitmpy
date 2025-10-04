import logging
import ssl
import weakref

from core import AutoThread, SafeSocket
from parsers.http import HTTPParser
from transformers.http import HTTPTransformer

BUFSIZE = 2048

logger = logging.getLogger(__name__)

class Pipe:
    def __init__(self, conn_socket: SafeSocket, socket_dst: SafeSocket, on_pipe_finished: callable):
        self._halt = False
        self._on_finished = on_pipe_finished

        self.conn_socket = conn_socket
        self.socket_dst = socket_dst

        self.buffers = {
            (self.conn_socket, self.socket_dst): bytearray(),
            (self.socket_dst, self.conn_socket): bytearray(),
        }

        self.parser = HTTPParser()
        self.transformer = HTTPTransformer()

    def start(self):
        t1 = AutoThread(target=self.process, args=(self.conn_socket, self.socket_dst))
        t2 = AutoThread(target=self.process, args=(self.socket_dst, self.conn_socket))
        t1.join()
        t2.join()

        self.conn_socket.close()
        self.socket_dst.close()

        self._on_finished(self)

    def stop(self):
        self._halt = True

    def process(self, reader: SafeSocket, writer: SafeSocket):
        buf = self.buffers[(reader, writer)]

        try:
            while not self._halt:
                #logger.info("Receiving data")
                data = reader.recv(BUFSIZE)
                if not data:
                    #logger.info("No more data to receive!")
                    self.stop()
                    break

                buf.extend(data)
                #logger.info(f"Received {data[0:10]}... ({len(data)} bytes)")

                while True:
                    parsed, consumed = self.parser.parse(buf)
                    if not parsed:
                        break

                    transformed = self.transformer.transform(parsed)

                    #logger.info("Sending data...")
                    writer.sendall(transformed)

                    # drop consumed bytes from buffer
                    del buf[:consumed]
        except (OSError, ssl.SSLError):
            logger.error("Something failed, killing MITM pipe...")
            self.stop()
        finally:
            reader.close()
            writer.close()