import logging
import time
from threading import Lock

from db import Database

logger = logging.getLogger(__name__)


class TrafficLogger:
    def __init__(self, db: Database):
        self._conn = db.connection
        self._lock = Lock()
        self._pipe_ids: dict[int, int] = {}  # id(pipe) -> pipes.id

    def register_pipe(self, pipe) -> None:
        meta = pipe.metainfo
        dst_addr = meta.dst_addr
        if isinstance(dst_addr, bytes):
            dst_addr = dst_addr.decode("utf-8", errors="replace")
        alpn = ",".join(meta.alpn_list) if meta.alpn_list else None
        encrypted = 1 if meta.sni is not None else 0
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO pipes (created_at, dst_addr, dst_port, sni, alpn, encrypted, pid, process_name)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), dst_addr, meta.dst_port, meta.sni, alpn, encrypted, meta.pid, meta.process_name),
            )
            self._conn.commit()
            self._pipe_ids[id(pipe)] = cur.lastrowid
            logger.debug(f"Registered pipe {pipe} as pipes.id={cur.lastrowid}")

    def log_outgoing(self, pipe, data: bytes) -> None:
        self._log(pipe, "outgoing", data)

    def log_incoming(self, pipe, data: bytes) -> None:
        self._log(pipe, "incoming", data)

    def _log(self, pipe, direction: str, data: bytes) -> None:
        with self._lock:
            pipe_id = self._pipe_ids.get(id(pipe))
            if pipe_id is None:
                logger.warning(f"TrafficLogger._log: no pipe_id for pipe {pipe}, skipping")
                return
            self._conn.execute(
                "INSERT INTO traffic (pipe_id, direction, recorded_at, data) VALUES (?, ?, ?, ?)",
                (pipe_id, direction, time.time(), data),
            )
            self._conn.commit()

    def unregister_pipe(self, pipe) -> None:
        with self._lock:
            removed = self._pipe_ids.pop(id(pipe), None)
            if removed is None:
                logger.warning(f"TrafficLogger.unregister_pipe: pipe {pipe} was not registered")
            else:
                logger.debug(f"Unregistered pipe {pipe} (pipes.id={removed})")
