from .util import tag


class Engine:
    def __init__(self, name="stock"):
        self.name = name

    def go(self):
        return tag(f"engine[{self.name}] running")
