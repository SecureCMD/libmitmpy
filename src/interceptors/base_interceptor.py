import logging

logger = logging.getLogger(__name__)

class BaseInterceptor:
    def __init__(self):
        pass

    def process_incoming_data(self, pipe, eof=False):
        buf = pipe.get_incoming_buffer()

        # Try to parse and forward as much as possible from buf
        logger.debug(
            f"Attempting to parse / transform with {type(self.parser).__name__} and {type(self.transformer).__name__}"
        )
        while True:
            parsed, consumed = self.parser.parse(buf, eof=eof)
            logger.debug(f"Consumed {consumed} bytes after parsing {len(buf)} of incoming data")

            if not parsed:
                logger.debug("Breaking...")
                break

            transformed = self.transformer.transform(parsed)
            logger.debug(f"Left with {len(transformed)} bytes after transforming...")

            pipe.write_to_downstream(transformed)
            del buf[:consumed]

        # Fallback: pass-through any leftover bytes so client isn’t starved
        if eof and buf:
            logger.debug(f"{len(buf)} bytes left in the buffer, sending to local socket...")
            pipe.write_to_downstream(buf)
            buf.clear()


    def process_outgoing_data(self, pipe, eof=False):
        buf = pipe.get_outgoing_buffer()

        # Try to parse and forward as much as possible from buf
        logger.debug(
            f"Attempting to parse / transform with {type(self.parser).__name__} and {type(self.transformer).__name__}"
        )
        while True:
            parsed, consumed = self.parser.parse(buf, eof=eof)
            logger.debug(f"Consumed {consumed} bytes after parsing {len(buf)} of outgoing data")

            if not parsed:
                logger.debug("Breaking...")
                break

            transformed = self.transformer.transform(parsed)
            logger.debug(f"Left with {len(transformed)} bytes after transforming...")

            pipe.write_to_upstream(transformed)
            del buf[:consumed]

        # Fallback: pass-through any leftover bytes so target isn’t starved
        if eof and buf:
            logger.debug(f"{len(buf)} bytes left in the buffer, sending to target socket...")
            pipe.write_to_upstream(buf)
            buf.clear()
