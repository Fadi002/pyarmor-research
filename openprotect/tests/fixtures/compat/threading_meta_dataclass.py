import threading
from dataclasses import dataclass, field


class Meta(type):
    registry = {}

    def __new__(mcs, name, bases, ns):
        cls = super().__new__(mcs, name, bases, ns)
        mcs.registry[name] = cls
        return cls


@dataclass
class Point:
    x: int
    y: int
    tags: list = field(default_factory=list)


results = []
lock = threading.Lock()


def worker(n):
    with lock:
        results.append(n * n)


threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()

p = Point(3, 4)
print(sorted(results))
print(p, p.x + p.y)
print(sorted(Meta.registry))
print(Point.__dataclass_fields__["x"].type)
