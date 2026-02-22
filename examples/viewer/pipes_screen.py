from datetime import datetime

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header

from clear_modal import ClearModal
from db import execute, query
from filter_modal import FilterModal
from quit_modal import QuitModal
from traffic_screen import TrafficScreen


class PipesScreen(Screen):
    BINDINGS = [
        Binding("enter", "select_pipe", "Inspect"),
        Binding("right", "select_pipe", "Inspect", show=False),
        Binding("r", "refresh", "Refresh"),
        Binding("f", "toggle_follow", "Follow"),
        Binding("/", "open_filter", "Filter"),
        Binding("c", "clear_confirm", "Clear"),
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
        self._last_traffic_id: int = 0
        self._filters: dict = {}
        self._chunks_col_key = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield DataTable(id="pipes-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#pipes-table", DataTable)
        cols = table.add_columns("Time", "PID", "Process", "Address", "Port", "Enc", "SNI", "ALPN", "Chunks")
        self._chunks_col_key = cols[-1]
        self._load_pipes()
        self.set_interval(0.5, self._poll_pipes)

    # ------------------------------------------------------------------

    def _build_query(self, min_id: int) -> tuple[str, tuple]:
        """Build the filtered SQL query and its parameter tuple."""
        conditions: list[str] = ["p.id > ?"]
        params: list = [min_id]

        if "process" in self._filters:
            f = self._filters["process"]
            if f["type"] == "exact":
                conditions.append("COALESCE(p.process_name, '') = ?")
                params.append(f["value"])
            elif f["type"] == "contains":
                conditions.append("COALESCE(p.process_name, '') LIKE ?")
                params.append(f"%{f['value']}%")
            elif f["type"] == "regex":
                conditions.append("COALESCE(p.process_name, '') REGEXP ?")
                params.append(f["value"])

        if "sni" in self._filters:
            f = self._filters["sni"]
            if f["type"] == "exact":
                conditions.append("COALESCE(p.sni, '') = ?")
                params.append(f["value"])
            elif f["type"] == "contains":
                conditions.append("COALESCE(p.sni, '') LIKE ?")
                params.append(f"%{f['value']}%")
            elif f["type"] == "regex":
                conditions.append("COALESCE(p.sni, '') REGEXP ?")
                params.append(f["value"])

        if "port" in self._filters:
            f = self._filters["port"]
            op = {"lte": "<=", "exact": "=", "gte": ">="}[f["type"]]
            conditions.append(f"p.dst_port {op} ?")
            params.append(f["value"])

        where = " AND ".join(conditions)
        sql = f"""
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
            WHERE {where}
            GROUP BY p.id
            ORDER BY p.created_at ASC
        """
        return sql, tuple(params)

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
                key=str(pipe_id),
            )
        return len(rows)

    # ------------------------------------------------------------------

    def _load_pipes(self) -> None:
        """Full reload — clears the table and re-fetches everything."""
        table = self.query_one("#pipes-table", DataTable)
        table.clear()
        self._pipe_ids.clear()
        self._last_pipe_id = 0
        sql, params = self._build_query(0)
        self._append_rows(table, query(sql, params))
        rows = query("SELECT COALESCE(MAX(id), 0) FROM traffic")
        self._last_traffic_id = rows[0][0] if rows else 0
        if self._follow and self._pipe_ids:
            table.move_cursor(row=len(self._pipe_ids) - 1)

    def _poll_pipes(self) -> None:
        """Incremental update — fetch new pipes and update chunk counts for existing ones."""
        table = self.query_one("#pipes-table", DataTable)

        # Add any new pipes.
        sql, params = self._build_query(self._last_pipe_id)
        new_rows = query(sql, params)
        if new_rows:
            self._append_rows(table, new_rows)
            if self._follow:
                table.move_cursor(row=len(self._pipe_ids) - 1)

        # For each pipe that received new traffic, get its total chunk count and
        # the highest new traffic id (to advance the watermark) in one query.
        count_rows = query(
            """
            SELECT t.pipe_id, COUNT(t.id), MAX(new_t.max_id)
            FROM traffic t
            INNER JOIN (
                SELECT pipe_id, MAX(id) AS max_id
                FROM traffic
                WHERE id > ?
                GROUP BY pipe_id
            ) new_t ON new_t.pipe_id = t.pipe_id
            GROUP BY t.pipe_id
            """,
            (self._last_traffic_id,),
        )
        if not count_rows:
            return

        self._last_traffic_id = max(row[2] for row in count_rows)
        pipe_id_set = set(self._pipe_ids)
        for pipe_id, total, _ in count_rows:
            if pipe_id in pipe_id_set:
                table.update_cell(str(pipe_id), self._chunks_col_key, str(total))

    # ------------------------------------------------------------------

    def _update_subtitle(self) -> None:
        if not self._filters:
            self.sub_title = ""
            return
        parts = []
        for col, f in self._filters.items():
            if col == "port":
                op = {"lte": "≤", "exact": "=", "gte": "≥"}[f["type"]]
                parts.append(f"Port {op} {f['value']}")
            else:
                parts.append(f"{col.capitalize()} {f['type']} '{f['value']}'")
        self.sub_title = "Filters: " + " | ".join(parts)

    # ------------------------------------------------------------------

    def action_clear_confirm(self) -> None:
        def _on_dismiss(confirmed: bool) -> None:
            if not confirmed:
                return
            execute("DELETE FROM traffic")
            execute("DELETE FROM pipes")
            self._last_pipe_id = 0
            self._load_pipes()
            self.notify("Cleared", timeout=1.5)

        self.app.push_screen(ClearModal(), _on_dismiss)

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

    def action_open_filter(self) -> None:
        def _on_dismiss(result) -> None:
            if result is None:  # cancelled — no change
                return
            self._filters = result
            self._update_subtitle()
            self._load_pipes()
            if self._filters:
                self.notify(f"Filters active: {', '.join(self._filters.keys())}", timeout=2)
            else:
                self.notify("Filters cleared", timeout=1.5)

        self.app.push_screen(FilterModal(self._filters), _on_dismiss)

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
