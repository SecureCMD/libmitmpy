from datetime import datetime

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Label
from traffic_screen import TrafficScreen

from db import query


class QuitModal(ModalScreen[bool]):
    BINDINGS = [
        Binding("y", "press_yes", "Yes", show=False),
        Binding("n", "press_no", "No", show=False),
        Binding("left", "focus_yes", "", show=False),
        Binding("right", "focus_no", "", show=False),
    ]
    CSS = """
    QuitModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 36;
        height: auto;
        border: solid $accent;
        background: $surface;
    }
    #dialog-title {
        width: 1fr;
        content-align: center middle;
        margin-bottom: 1;
    }
    #dialog-buttons {
        width: 1fr;
        align: center middle;
        height: auto;

    }
    #dialog-buttons Button {
        margin: 0 1;
        min-width: 0;
        width: 10;
        text-align: center;
        content-align: center middle;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Quit the viewer?", id="dialog-title")
            with Horizontal(id="dialog-buttons"):
                yield Button("Yes", variant="error", id="btn-yes")
                yield Button("No", variant="primary", id="btn-no")

    def on_mount(self) -> None:
        self.query_one("#btn-no", Button).focus()

    def action_press_yes(self) -> None:
        self.dismiss(True)

    def action_press_no(self) -> None:
        self.dismiss(False)

    def action_focus_yes(self) -> None:
        self.query_one("#btn-yes", Button).focus()

    def action_focus_no(self) -> None:
        self.query_one("#btn-no", Button).focus()

    @on(Button.Pressed, "#btn-yes")
    def _yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#btn-no")
    def _no(self) -> None:
        self.dismiss(False)


class PipesScreen(Screen):
    BINDINGS = [
        Binding("enter", "select_pipe", "Inspect"),
        Binding("right", "select_pipe", "Inspect", show=False),
        Binding("r", "refresh", "Refresh"),
        Binding("f", "toggle_follow", "Follow"),
        Binding("escape", "quit_confirm", "Quit"),
    ]
    CSS = """
    DataTable { height: 1fr; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._pipe_ids: list[int] = []
        self._follow: bool = False
        self._last_pipe_id: int = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield DataTable(id="pipes-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#pipes-table", DataTable)
        table.add_columns("Time", "PID", "Process", "Address", "Port", "Enc", "SNI", "ALPN", "Chunks")
        self._load_pipes()
        self.set_interval(0.5, self._poll_pipes)

    _QUERY = """
        SELECT p.id,
               p.created_at,
               p.pid,
               p.process_name,
               p.dst_addr,
               p.dst_port,
               p.encrypted,
               p.sni,
               p.alpn,
               COUNT(t.id) AS chunks
        FROM pipes p
        LEFT JOIN traffic t ON t.pipe_id = p.id
        WHERE p.id > ?
        GROUP BY p.id
        ORDER BY p.created_at ASC
    """

    def _append_rows(self, table: DataTable, rows: list) -> int:
        """Add rows to the table, return the count of rows added."""
        for pipe_id, created_at, pid, process_name, dst_addr, dst_port, encrypted, sni, alpn, chunks in rows:
            self._pipe_ids.append(pipe_id)
            self._last_pipe_id = max(self._last_pipe_id, pipe_id)
            ts = datetime.fromtimestamp(created_at).strftime("%H:%M:%S")
            enc_label = Text("🔒 yes", style="green") if encrypted else Text("   no", style="dim")
            table.add_row(
                ts,
                str(pid) if pid is not None else "—",
                process_name or "—",
                dst_addr,
                str(dst_port),
                enc_label,
                sni  or "—",
                alpn or "—",
                str(chunks),
            )
        return len(rows)

    # ------------------------------------------------------------------

    def _load_pipes(self) -> None:
        """Full reload — clears the table and re-fetches everything."""
        table = self.query_one("#pipes-table", DataTable)
        table.clear()
        self._pipe_ids.clear()
        self._last_pipe_id = 0
        self._append_rows(table, query(self._QUERY, (0,)))
        if self._follow and self._pipe_ids:
            table.move_cursor(row=len(self._pipe_ids) - 1)

    def _poll_pipes(self) -> None:
        """Incremental update — only fetches pipes newer than the last seen id."""
        rows = query(self._QUERY, (self._last_pipe_id,))
        if not rows:
            return
        table = self.query_one("#pipes-table", DataTable)
        self._append_rows(table, rows)
        if self._follow:
            table.move_cursor(row=len(self._pipe_ids) - 1)

    # ------------------------------------------------------------------

    def action_refresh(self) -> None:
        self._load_pipes()

    def action_quit_confirm(self) -> None:
        def _on_dismiss(confirmed: bool) -> None:
            if confirmed:
                self.app.exit()

        self.app.push_screen(QuitModal(), _on_dismiss)

    def action_toggle_follow(self) -> None:
        self._follow = not self._follow
        self.notify("Follow: ON" if self._follow else "Follow: OFF", timeout=1.5)
        if self._follow and self._pipe_ids:
            self.query_one("#pipes-table", DataTable).move_cursor(row=len(self._pipe_ids) - 1)

    def action_select_pipe(self) -> None:
        table = self.query_one("#pipes-table", DataTable)
        idx = table.cursor_row
        if not self._pipe_ids or not (0 <= idx < len(self._pipe_ids)):
            return

        pipe_id = self._pipe_ids[idx]
        rows = query(
            "SELECT dst_addr, dst_port, sni FROM pipes WHERE id = ?",
            (pipe_id,),
        )
        if rows:
            dst_addr, dst_port, sni = rows[0]
            subtitle = f"{dst_addr}:{dst_port}" + (f"  [{sni}]" if sni else "")
        else:
            subtitle = f"pipe #{pipe_id}"

        self.app.push_screen(TrafficScreen(pipe_id, subtitle))
