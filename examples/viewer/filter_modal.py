from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select


class FilterModal(ModalScreen):
    BINDINGS = [Binding("escape", "cancel", "", show=False)]
    CSS = """
    FilterModal {
        align: center middle;
    }
    #filter-dialog {
        padding: 1 2;
        width: 72;
        height: auto;
        border: solid $accent;
        background: $surface;
    }
    #filter-title {
        width: 1fr;
        content-align: center middle;
        margin-bottom: 1;
    }
    .filter-row {
        height: auto;
        margin-bottom: 1;
        align: left middle;
    }
    .filter-label {
        width: 10;
        height: 100%;
        content-align: left middle;
        text-align: left;
    }
    .filter-select {
        width: 16;
        margin-right: 1;
    }
    .filter-input {
        width: 1fr;
    }
    #filter-buttons {
        width: 1fr;
        align: center middle;
        height: auto;
        margin-top: 1;
    }
    #filter-buttons Button {
        margin: 0 1;
        min-width: 10;
    }
    """

    def __init__(self, current_filters: dict) -> None:
        super().__init__()
        self._current = current_filters

    def compose(self) -> ComposeResult:
        pf  = self._current.get("process", {})
        sf  = self._current.get("sni", {})
        pof = self._current.get("port", {})
        with Vertical(id="filter-dialog"):
            yield Label("Filter Pipes", id="filter-title")
            with Horizontal(classes="filter-row"):
                yield Label("Process", classes="filter-label")
                yield Select(
                    [("Exact", "exact"), ("Contains", "contains"), ("Regex", "regex")],
                    value=pf.get("type", "contains"),
                    id="process-type",
                    classes="filter-select",
                )
                yield Input(
                    value=pf.get("value", ""),
                    placeholder="filter…",
                    id="process-value",
                    classes="filter-input",
                )
            with Horizontal(classes="filter-row"):
                yield Label("SNI", classes="filter-label")
                yield Select(
                    [("Exact", "exact"), ("Contains", "contains"), ("Regex", "regex")],
                    value=sf.get("type", "contains"),
                    id="sni-type",
                    classes="filter-select",
                )
                yield Input(
                    value=sf.get("value", ""),
                    placeholder="filter…",
                    id="sni-value",
                    classes="filter-input",
                )
            with Horizontal(classes="filter-row"):
                yield Label("Port", classes="filter-label")
                yield Select(
                    [("≤", "lte"), ("=", "exact"), ("≥", "gte")],
                    value=pof.get("type", "exact"),
                    id="port-type",
                    classes="filter-select",
                )
                yield Input(
                    value=str(pof["value"]) if "value" in pof else "",
                    placeholder="port number…",
                    id="port-value",
                    classes="filter-input",
                )
            with Horizontal(id="filter-buttons"):
                yield Button("Apply", variant="primary", id="btn-apply")
                yield Button("Clear All", variant="warning", id="btn-clear")
                yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        self.query_one("#process-value", Input).focus()

    def _collect_filters(self) -> dict:
        result = {}

        process_val  = self.query_one("#process-value", Input).value.strip()
        process_type = self.query_one("#process-type", Select).value
        if process_val and process_type is not Select.BLANK:
            result["process"] = {"type": process_type, "value": process_val}

        sni_val  = self.query_one("#sni-value", Input).value.strip()
        sni_type = self.query_one("#sni-type", Select).value
        if sni_val and sni_type is not Select.BLANK:
            result["sni"] = {"type": sni_type, "value": sni_val}

        port_val  = self.query_one("#port-value", Input).value.strip()
        port_type = self.query_one("#port-type", Select).value
        if port_val and port_type is not Select.BLANK:
            try:
                result["port"] = {"type": port_type, "value": int(port_val)}
            except ValueError:
                pass

        return result

    @on(Button.Pressed, "#btn-apply")
    @on(Input.Submitted)
    def _apply(self) -> None:
        self.dismiss(self._collect_filters())

    @on(Button.Pressed, "#btn-clear")
    def _clear(self) -> None:
        self.dismiss({})

    @on(Button.Pressed, "#btn-cancel")
    def _cancel(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
