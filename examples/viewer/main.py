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
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Label, Static

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
    COLS = 32  # bytes per row
    GROUP = 8  # bytes per space-separated group within a row
    lines = []
    for i in range(0, len(data), COLS):
        row = data[i : i + COLS]
        groups = []
        for g in range(0, COLS, GROUP):
            chunk = row[g : g + GROUP]
            groups.append(f"{' '.join(f'{b:02x}' for b in chunk):<{GROUP * 3 - 1}}")
        hex_part = "  ".join(groups)
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{i:08x}  {hex_part}  |{printable}|")
    return "\n".join(lines)


def _render_hex(data: bytes) -> Text:
    display = data[:MAX_DISPLAY_BYTES]
    content = Text(_hex_dump(display), style="green")
    if len(data) > MAX_DISPLAY_BYTES:
        content.append(
            f"\n\n… {len(data) - MAX_DISPLAY_BYTES} more bytes not shown",
            style="dim italic",
        )
    return content


def _render_text(data: bytes) -> Text:
    """Decode as UTF-8, replacing undecodable bytes with \ufffd."""
    display = data[:MAX_DISPLAY_BYTES]
    content = Text(display.decode("utf-8", errors="replace"))
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
        Binding("left", "go_back", "Back", show=False),
        Binding("t", "toggle_view", "Toggle hex/text"),
    ]
    CSS = """
    Horizontal { height: 1fr; }

    #traffic-table {
        width: 2fr;
        border-right: solid $accent;
    }

    #data-panel {
        width: 3fr;
    }

    #view-mode-label {
        height: 1;
        padding: 0 1;
        background: $accent;
        color: $text;
    }

    #data-view {
        height: 1fr;
        padding: 0 1;
    }
    """

    def __init__(self, pipe_id: int, subtitle: str) -> None:
        super().__init__()
        self._pipe_id = pipe_id
        self._subtitle = subtitle
        self._chunk_ids: list[int] = []
        self._hex_mode: bool = True
        self._current_data: bytes | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield DataTable(id="traffic-table", cursor_type="row")
            with Vertical(id="data-panel"):
                yield Label("", id="view-mode-label")
                with VerticalScroll(id="data-view"):
                    yield Static(id="data-content")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = self._subtitle
        table = self.query_one("#traffic-table", DataTable)
        table.add_columns("Time", "Dir", "Size")
        self._update_mode_label()
        self._load_chunks()
        self.set_interval(2.0, self._poll_new_chunks)

    # ------------------------------------------------------------------

    def _update_mode_label(self) -> None:
        mode = "HEX" if self._hex_mode else "TEXT"
        self.query_one("#view-mode-label", Label).update(f" {mode}  (T to toggle)")

    def _update_content(self) -> None:
        if self._current_data is None:
            return
        render = _render_hex if self._hex_mode else _render_text
        self.query_one("#data-content", Static).update(render(self._current_data))

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

    def _poll_new_chunks(self) -> None:
        """Append any traffic rows added since the last load without disturbing the view."""
        if not self._chunk_ids:
            return
        rows = _query(
            "SELECT id, direction, recorded_at, length(data) "
            "FROM traffic WHERE pipe_id = ? AND id > ? ORDER BY recorded_at ASC",
            (self._pipe_id, self._chunk_ids[-1]),
        )
        if not rows:
            return
        table = self.query_one("#traffic-table", DataTable)
        was_at_last = table.cursor_row == len(self._chunk_ids) - 1
        for chunk_id, direction, recorded_at, size in rows:
            self._chunk_ids.append(chunk_id)
            ts    = datetime.fromtimestamp(recorded_at).strftime("%H:%M:%S.%f")[:-3]
            arrow = (
                Text("↑ out", style="cyan")
                if direction == "outgoing"
                else Text("↓ in ", style="yellow")
            )
            table.add_row(ts, arrow, f"{size} B")
        if was_at_last:
            table.move_cursor(row=len(self._chunk_ids) - 1)

    def _show_chunk(self, chunk_id: int) -> None:
        rows = _query("SELECT data FROM traffic WHERE id = ?", (chunk_id,))
        if not rows:
            return
        self._current_data = bytes(rows[0][0])
        self._update_content()

    # ------------------------------------------------------------------

    @on(DataTable.RowHighlighted)
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._chunk_ids):
            self._show_chunk(self._chunk_ids[idx])

    def action_toggle_view(self) -> None:
        self._hex_mode = not self._hex_mode
        self._update_mode_label()
        self._update_content()

    def action_go_back(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Pipes screen — main screen listing all recorded connections
# ---------------------------------------------------------------------------

class PipesScreen(Screen):
    BINDINGS = [
        Binding("enter", "select_pipe", "Inspect"),
        Binding("right", "select_pipe", "Inspect", show=False),
        Binding("r", "refresh", "Refresh"),
        Binding("q", "app.quit", "Quit"),
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
        table.add_columns("Time", "Address", "Port", "Enc", "SNI", "ALPN", "Chunks")
        self._load_pipes()
        self.set_interval(2.0, self._load_pipes)

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
                   p.encrypted,
                   p.sni,
                   p.alpn,
                   COUNT(t.id) AS chunks
            FROM pipes p
            LEFT JOIN traffic t ON t.pipe_id = p.id
            GROUP BY p.id
            ORDER BY p.created_at DESC
        """)

        for pipe_id, created_at, dst_addr, dst_port, encrypted, sni, alpn, chunks in rows:
            self._pipe_ids.append(pipe_id)
            ts = datetime.fromtimestamp(created_at).strftime("%H:%M:%S")
            enc_label = Text("🔒 yes", style="green") if encrypted else Text("   no", style="dim")
            table.add_row(
                ts,
                dst_addr,
                str(dst_port),
                enc_label,
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
