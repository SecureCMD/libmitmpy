from threading import Thread as PThread
from uuid import uuid4


class Thread(PThread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon = True
        self.c_ident = hex(id(uuid4()))

    def __str__(self):
        return f"{self.name} {self.c_ident}"


class AutoThread(Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start()
