from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label


class ClearModal(ModalScreen[bool]):
    BINDINGS = [
        Binding("y", "press_yes", "Yes", show=False),
        Binding("n", "press_no", "No", show=False),
        Binding("left", "focus_yes", "", show=False),
        Binding("right", "focus_no", "", show=False),
    ]
    CSS = """
    ClearModal {
        align: center middle;
    }
    #dialog {
        padding: 1 2;
        width: 44;
        height: auto;
        border: solid $warning;
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
            yield Label("Clear all pipes and traffic?", id="dialog-title")
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
