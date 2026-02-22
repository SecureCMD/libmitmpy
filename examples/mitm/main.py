import logging
import threading
from datetime import datetime as dt
from signal import SIGINT, SIGTERM, signal
from typing import Optional

from config import APP_ID, DATA_DIR

from encripton import Encripton
from handlers import ConnectionMeta, HTTPConnectionHandler, HTTPResponse


class ThreadIdentFilter(logging.Filter):
    def filter(self, record):
        record.thread_ident = getattr(threading.current_thread(), "c_ident", f"{record.thread:#x}")
        return True


handler = logging.StreamHandler()
handler.addFilter(ThreadIdentFilter())
handler.setFormatter(
    logging.Formatter(
        "[%(asctime)s][%(threadName)s %(thread_ident)s][%(levelname)s] "
        "%(filename)s:%(funcName)s:%(lineno)d %(message)s",
        datefmt="%H:%M:%S.%f",
    )
)
logging.Formatter.formatTime = lambda _, r, f: dt.fromtimestamp(r.created).strftime(f)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)


class MyHTTPHandler(HTTPConnectionHandler):
    def on_response(self, resp: HTTPResponse) -> Optional[HTTPResponse]:
        resp.body = resp.body.replace(b"</html>", b"OLA K ASE MODIFICA TRAFICO ENCRIPTADO O K ASE?</html>")
        return resp


def select_handler(meta: ConnectionMeta):
    if meta.dst_port in (80, 443):
        return MyHTTPHandler
    return None  # pass-through for non-HTTP traffic


LOCAL_ADDR = "0.0.0.0"
LOCAL_PORT = 9090

signal(SIGINT, lambda *args, **kwargs: encripton.stop())
signal(SIGTERM, lambda *args, **kwargs: encripton.stop())

encripton = Encripton(
    local_addr=LOCAL_ADDR,
    local_port=LOCAL_PORT,
    app_id=APP_ID,
    data_dir=DATA_DIR,
    handler=select_handler,
)
encripton.start()
