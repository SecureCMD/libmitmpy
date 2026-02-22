from datetime import datetime

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Label, Static

from db import query
from render import render_hex, render_text


class TrafficScreen(Screen):
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("left", "go_back", "Back", show=False),
        Binding("t", "toggle_view", "Toggle hex/text"),
    ]
    CSS = """
    Horizontal { height: 1fr; }

    #traffic-table {
        width: auto;
        border-right: solid $accent;
    }

    #data-panel {
        width: 1fr;
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
        table.add_column("Time", width=12)
        table.add_column("Dir", width=5)
        table.add_column("Size", width=8)
        self._update_mode_label()
        self._load_chunks()
        self.set_interval(0.5, self._poll_new_chunks)

    # ------------------------------------------------------------------

    def _update_mode_label(self) -> None:
        mode = "HEX" if self._hex_mode else "TEXT"
        self.query_one("#view-mode-label", Label).update(f" {mode}  (T to toggle)")

    def _update_content(self) -> None:
        if self._current_data is None:
            return
        render = render_hex if self._hex_mode else render_text
        self.query_one("#data-content", Static).update(render(self._current_data))

    # ------------------------------------------------------------------

    def _load_chunks(self) -> None:
        table = self.query_one("#traffic-table", DataTable)
        self._chunk_ids.clear()

        rows = query(
            "SELECT id, direction, recorded_at, length(data) "
            "FROM traffic WHERE pipe_id = ? ORDER BY recorded_at ASC",
            (self._pipe_id,),
        )
        for chunk_id, direction, recorded_at, size in rows:
            self._chunk_ids.append(chunk_id)
            ts = datetime.fromtimestamp(recorded_at).strftime("%H:%M:%S.%f")[:-3]
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
        rows = query(
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
            ts = datetime.fromtimestamp(recorded_at).strftime("%H:%M:%S.%f")[:-3]
            arrow = (
                Text("↑ out", style="cyan")
                if direction == "outgoing"
                else Text("↓ in ", style="yellow")
            )
            table.add_row(ts, arrow, f"{size} B")
        if was_at_last:
            table.move_cursor(row=len(self._chunk_ids) - 1)

    def _show_chunk(self, chunk_id: int) -> None:
        rows = query("SELECT data FROM traffic WHERE id = ?", (chunk_id,))
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
