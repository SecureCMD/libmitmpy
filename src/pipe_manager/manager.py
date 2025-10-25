import logging
from typing import List

from net.socks import Pipe
from parsers.dummy import DummyParser
from parsers.http import HTTPParser
from transformers.dummy import DummyTransformer
from transformers.http import HTTPTransformer

logger = logging.getLogger(__name__)

class PipeManager:
    def __init__(self):
        self.pipes: List[Pipe] = []

        self.parser = HTTPParser()
        self.transformer = HTTPTransformer()

        self.parser = DummyParser()
        self.transformer = DummyTransformer()

    def add(self, pipe):
        self.pipes.append(pipe)
        pipe.on("pipe_finished", self.remove)
        pipe.on("outgoing_data_available", self.flush_outgoing_data)
        pipe.on("incoming_data_available", self.flush_incoming_data)

        logger.info(f"Starting pipe {pipe}")
        pipe.start()

    def stop_all(self):
        for pipe in self.pipes:
            logger.info(f"Stopping pipe {pipe}")
            pipe.stop()

    def remove(self, pipe):
        pipe.off("pipe_finished", self.remove)
        if pipe in self.pipes:
            logger.info(f"Stopping pipe {pipe}")
            pipe.stop()

            logger.info(f"Removing pipe {pipe}")
            self.pipes.remove(pipe)

    def flush_outgoing_data(self, pipe, eof=False):
        buf = pipe.get_outgoing_buffer()

        # Try to parse and forward as much as possible from buf
        while True:
            parsed, consumed = self.parser.parse(buf, eof=eof)

            if not parsed:
                break

            transformed = self.transformer.transform(parsed)

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

            pipe.write_to_downstream(transformed)
            del buf[:consumed]

        # Fallback: pass-through any leftover bytes so client isn’t starved
        if eof and buf:
            logger.debug(f"{len(buf)} bytes left in the buffer, sending to local socket...")
            pipe.write_to_downstream(buf)
            buf.clear()