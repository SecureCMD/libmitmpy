from textual.app import App

from pipes_screen import PipesScreen


class ViewerApp(App):
    TITLE = "Encriptón Viewer"

    def on_mount(self) -> None:
        self.push_screen(PipesScreen())
