from ..base_interceptor import BaseInterceptor
from .parser import HTTPParser
from .transformer import HTTPTransformer


class HTTPInterceptor(BaseInterceptor):
    def __init__(self):
        self.parser = HTTPParser()
        self.transformer = HTTPTransformer()