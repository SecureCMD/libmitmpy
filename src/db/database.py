import sqlite3
from pathlib import Path


class Database:
    def __init__(self, path: Path):
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.executescript("""
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS root_cert (
                id       INTEGER PRIMARY KEY CHECK (id = 1),
                cert_pem BLOB NOT NULL,
                key_pem  BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS leaf_certs (
                domain     TEXT PRIMARY KEY,
                cert_pem   BLOB NOT NULL,
                key_pem    BLOB NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pipes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                dst_addr   TEXT NOT NULL,
                dst_port   INTEGER NOT NULL,
                sni        TEXT,
                alpn       TEXT
            );
            CREATE TABLE IF NOT EXISTS traffic (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                pipe_id     INTEGER NOT NULL REFERENCES pipes(id),
                direction   TEXT NOT NULL CHECK(direction IN ('outgoing', 'incoming')),
                recorded_at REAL NOT NULL,
                data        BLOB NOT NULL
            );
        """)

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn
