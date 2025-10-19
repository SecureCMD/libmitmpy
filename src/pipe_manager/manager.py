import logging
from typing import List

from net.socks import Pipe
from parsers.http import HTTPParser
from transformers.http import HTTPTransformer

logger = logging.getLogger(__name__)

class PipeManager:
    def __init__(self):
        self.pipes: List[Pipe] = []

        self.parser = HTTPParser()
        self.transformer = HTTPTransformer()

    def add(self, pipe):
        self.pipes.append(pipe)
        pipe.on("pipe_closed", self.remove)
        pipe.on("outgoing_data_available", self.flush_outgoing_data)
        pipe.on("incoming_data_available", self.flush_incoming_data)

    def remove(self, pipe):
        pipe.off("pipe_closed", self.remove)
        if pipe in self.pipes:
            self.pipes.remove(pipe)

    def flush_outgoing_data(self, pipe, eof=False):
        buf = pipe.get_outgoing_buffer()

        # Try to parse and forward as much as possible from buf
        while True:
            parsed, consumed = self.parser.parse(buf, eof=eof)

            if not parsed:
                break

            transformed = self.transformer.transform(parsed)

            logger.debug(f"Sending {len(transformed)} to remote socket...")
            pipe.write_to_upstream(transformed)
            del buf[:consumed]

        # Fallback: pass-through any leftover bytes so target isn’t starved
        if eof and buf:
            logger.debug(f"{len(buf)} bytes left in the buffer, sending to target socket...")
            pipe.write_to_upstream(buf)
            buf.clear()

    def flush_incoming_data(self, pipe, eof=False):
        buf = pipe.get_incoming_buffer()

        # Try to parse and forward as much as possible from buf
        while True:
            parsed, consumed = self.parser.parse(buf, eof=eof)

            if not parsed:
                break

            transformed = self.transformer.transform(parsed)

            logger.debug(f"Sending {len(transformed)} to local socket...")
            pipe.write_to_downstream(transformed)
            del buf[:consumed]

        # Fallback: pass-through any leftover bytes so client isn’t starved
        if eof and buf:
            logger.debug(f"{len(buf)} bytes left in the buffer, sending to local socket...")
            pipe.write_to_downstream(buf)
            buf.clear()