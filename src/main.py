import logging
from datetime import datetime as dt
from signal import SIGINT, SIGTERM, signal

from soxy_mitm import Soxy

logging.basicConfig(
    format='[%(asctime)s][%(threadName)s %(thread)#x] %(levelname)s:%(filename)s:%(funcName)s:%(lineno)d %(message)s',
    level=logging.INFO,
    datefmt="%H:%M:%S.%f"
)
logging.Formatter.formatTime = lambda _, r, f: dt.fromtimestamp(r.created).strftime(f)

LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 9090

def exit_handler(signum, frame):
    soxy.stop()

signal(SIGINT, exit_handler)
signal(SIGTERM, exit_handler)

soxy = Soxy(local_addr=LOCAL_ADDR, local_port=LOCAL_PORT)
soxy.start()