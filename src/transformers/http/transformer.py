import logging

logger = logging.getLogger(__name__)

class HTTPTransformer:
    def transform(self, msg: bytes) -> bytes:
        #import pdb
        #pdb.set_trace()
        #logger.info("replacing...")
        #logger.info(msg)
        return msg.replace(b"</html>", b"OLA K ASE MODIFICA TRAFICO ENCRIPTADO O K ASE?</html>")