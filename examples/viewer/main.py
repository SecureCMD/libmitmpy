"""
TUI traffic viewer for encriptón.

Reads from the SQLite database written by the proxy (data.db).
The database path is resolved from config.DATA_DIR.

Usage:
    python examples/viewer/main.py
"""

from app import ViewerApp

if __name__ == "__main__":
    ViewerApp().run()
