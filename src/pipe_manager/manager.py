from typing import List

from net.socks import Pipe


class PipeManager:
    def __init__(self):
        self.pipes: List[Pipe] = []

    def add(self, pipe):
        self.pipes.append(pipe)
        pipe.on("pipe_closed", self.remove)

    def remove(self, pipe):
        pipe.off("pipe_closed", self.remove)
        if pipe in self.pipes:
            self.pipes.remove(pipe)