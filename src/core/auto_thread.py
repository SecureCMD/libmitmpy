from threading import Thread


class AutoThread(Thread):
    def __init__(self, *args, **kwargs):
        name = kwargs.pop("tname", "")
        super().__init__(*args, **kwargs)
        if name:
            self.name = name
        self.start()