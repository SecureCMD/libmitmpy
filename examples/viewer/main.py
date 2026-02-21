"""
TUI traffic viewer for encriptón.

Reads from the SQLite database written by the proxy (data.db).
The database path is resolved from config.DATA_DIR.

Usage:
    python examples/viewer/main.py
"""

import sqlite3
from datetime import datetime

from config import DATA_DIR
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

DB_PATH = DATA_DIR / "data.db"
MAX_DISPLAY_BYTES = 16 * 1024  # 16 KiB — truncate beyond this to keep the UI responsive


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _query(sql: str, params: tuple = ()) -> list:
    """Run a read-only query against the database; returns [] on any error."""
    if not DB_PATH.exists():
        return []
    try:
        with sqlite3.connect(str(DB_PATH)) as conn:
            return conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []


# ---------------------------------------------------------------------------
# Data rendering helpers
# ---------------------------------------------------------------------------

def _hex_dump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        row = data[i : i + 16]
        left  = " ".join(f"{b:02x}" for b in row[:8])
        right = " ".join(f"{b:02x}" for b in row[8:])
        hex_part = f"{left:<23}  {right:<23}"
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{i:08x}  {hex_part}  |{printable}|")
    return "\n".join(lines)


def _render_data(data: bytes) -> Text:
    """Try to decode as UTF-8, fall back to hex dump. Truncates large blobs."""
    display = data[:MAX_DISPLAY_BYTES]
    try:
        content = Text(display.decode("utf-8"))
    except UnicodeDecodeError:
        content = Text(_hex_dump(display), style="green")
    if len(data) > MAX_DISPLAY_BYTES:
        content.append(
            f"\n\n… {len(data) - MAX_DISPLAY_BYTES} more bytes not shown",
            style="dim italic",
        )
    return content


# ---------------------------------------------------------------------------
# Traffic screen — shows chunks for one pipe
# ---------------------------------------------------------------------------

class TrafficScreen(Screen):
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("left",   "go_back", "Back", show=False),
    ]
    CSS = """
    Horizontal   { height: 1fr; }

    #traffic-table {
        width: 2fr;
        border-right: solid $accent;
    }

    #data-view {
        width: 3fr;
        padding: 0 1;
    }
    """

    def __init__(self, pipe_id: int, subtitle: str) -> None:
        super().__init__()
        self._pipe_id    = pipe_id
        self._subtitle   = subtitle
        self._chunk_ids: list[int] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield DataTable(id="traffic-table", cursor_type="row")
            with VerticalScroll(id="data-view"):
                yield Static(id="data-content")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = self._subtitle
        table = self.query_one("#traffic-table", DataTable)
        table.add_columns("Time", "Dir", "Size")
        self._load_chunks()

    # ------------------------------------------------------------------

    def _load_chunks(self) -> None:
        table = self.query_one("#traffic-table", DataTable)
        self._chunk_ids.clear()

        rows = _query(
            "SELECT id, direction, recorded_at, length(data) "
            "FROM traffic WHERE pipe_id = ? ORDER BY recorded_at ASC",
            (self._pipe_id,),
        )
        for chunk_id, direction, recorded_at, size in rows:
            self._chunk_ids.append(chunk_id)
            ts    = datetime.fromtimestamp(recorded_at).strftime("%H:%M:%S.%f")[:-3]
            arrow = (
                Text("↑ out", style="cyan")
                if direction == "outgoing"
                else Text("↓ in ", style="yellow")
            )
            table.add_row(ts, arrow, f"{size} B")

        if self._chunk_ids:
            self._show_chunk(self._chunk_ids[0])

    def _show_chunk(self, chunk_id: int) -> None:
        rows = _query("SELECT data FROM traffic WHERE id = ?", (chunk_id,))
        if not rows:
            return
        self.query_one("#data-content", Static).update(_render_data(bytes(rows[0][0])))

    # ------------------------------------------------------------------

    @on(DataTable.RowHighlighted)
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._chunk_ids):
            self._show_chunk(self._chunk_ids[idx])

    def action_go_back(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Pipes screen — main screen listing all recorded connections
# ---------------------------------------------------------------------------

class PipesScreen(Screen):
    BINDINGS = [
        Binding("enter", "select_pipe", "Inspect"),
        Binding("right", "select_pipe", "Inspect", show=False),
        Binding("r",     "refresh",     "Refresh"),
    ]
    CSS = """
    DataTable { height: 1fr; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._pipe_ids: list[int] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield DataTable(id="pipes-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#pipes-table", DataTable)
        table.add_columns("Time", "Address", "Port", "SNI", "ALPN", "Chunks")
        self._load_pipes()

    # ------------------------------------------------------------------

    def _load_pipes(self) -> None:
        table = self.query_one("#pipes-table", DataTable)
        prev_row = table.cursor_row
        table.clear()
        self._pipe_ids.clear()

        rows = _query("""
            SELECT p.id,
                   p.created_at,
                   p.dst_addr,
                   p.dst_port,
                   p.sni,
                   p.alpn,
                   COUNT(t.id) AS chunks
            FROM pipes p
            LEFT JOIN traffic t ON t.pipe_id = p.id
            GROUP BY p.id
            ORDER BY p.created_at DESC
        """)

        for pipe_id, created_at, dst_addr, dst_port, sni, alpn, chunks in rows:
            self._pipe_ids.append(pipe_id)
            ts = datetime.fromtimestamp(created_at).strftime("%H:%M:%S")
            table.add_row(
                ts,
                dst_addr,
                str(dst_port),
                sni  or "—",
                alpn or "—",
                str(chunks),
            )

        # restore cursor position after refresh
        if self._pipe_ids and prev_row < len(self._pipe_ids):
            table.move_cursor(row=prev_row)

    # ------------------------------------------------------------------

    def action_refresh(self) -> None:
        self._load_pipes()

    def action_select_pipe(self) -> None:
        table = self.query_one("#pipes-table", DataTable)
        idx = table.cursor_row
        if not self._pipe_ids or not (0 <= idx < len(self._pipe_ids)):
            return

        pipe_id = self._pipe_ids[idx]
        rows = _query(
            "SELECT dst_addr, dst_port, sni FROM pipes WHERE id = ?",
            (pipe_id,),
        )
        if rows:
            dst_addr, dst_port, sni = rows[0]
            subtitle = f"{dst_addr}:{dst_port}" + (f"  [{sni}]" if sni else "")
        else:
            subtitle = f"pipe #{pipe_id}"

        self.app.push_screen(TrafficScreen(pipe_id, subtitle))


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class ViewerApp(App):
    TITLE = "Encriptón Viewer"

    def on_mount(self) -> None:
        self.push_screen(PipesScreen())


if __name__ == "__main__":
    ViewerApp().run()
