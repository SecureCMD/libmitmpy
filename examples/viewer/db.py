import sqlite3

from config import DATA_DIR

DB_PATH = DATA_DIR / "data.db"


def query(sql: str, params: tuple = ()) -> list:
    """Run a read-only query against the database; returns [] on any error."""
    if not DB_PATH.exists():
        return []
    try:
        with sqlite3.connect(str(DB_PATH)) as conn:
            return conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []
