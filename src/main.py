import logging
import threading
from datetime import datetime as dt
from signal import SIGINT, SIGTERM, signal

from encripton import Encripton


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

LOCAL_ADDR = "0.0.0.0"
LOCAL_PORT = 9090

signal(SIGINT, lambda *args, **kwargs: encripton.stop())
signal(SIGTERM, lambda *args, **kwargs: encripton.stop())

encripton = Encripton(local_addr=LOCAL_ADDR, local_port=LOCAL_PORT)
encripton.start()
