import re
import sqlite3

from config import DATA_DIR

DB_PATH = DATA_DIR / "data.db"


def _regexp(pattern: str, value) -> bool:
    try:
        return bool(re.search(pattern, value or ""))
    except re.error:
        return False


def execute(sql: str, params: tuple = ()) -> bool:
    """Run a write query against the database; returns True on success."""
    if not DB_PATH.exists():
        return False
    try:
        with sqlite3.connect(str(DB_PATH)) as conn:
            conn.execute(sql, params)
            conn.commit()
        return True
    except sqlite3.Error:
        return False


def query(sql: str, params: tuple = ()) -> list:
    """Run a read-only query against the database; returns [] on any error."""
    if not DB_PATH.exists():
        return []
    try:
        with sqlite3.connect(str(DB_PATH)) as conn:
            conn.create_function("regexp", 2, _regexp)
            return conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []
