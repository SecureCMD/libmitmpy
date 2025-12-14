import logging

logger = logging.getLogger(__name__)


class DummyTransformer:
    def transform(self, data: bytes) -> bytes:
        return data
