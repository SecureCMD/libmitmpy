from ..base_interceptor import BaseInterceptor
from .parser import DummyParser
from .transformer import DummyTransformer


class DummyInterceptor(BaseInterceptor):
    def __init__(self):
        self.parser = DummyParser()
        self.transformer = DummyTransformer()