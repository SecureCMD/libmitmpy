import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class DummyParser:
    def parse(self, data: bytearray, eof: bool = False) -> Tuple[Optional[bytes], int]:
        data = bytes(data)
        return data, len(data)
