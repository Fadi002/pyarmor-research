import functools


def trace(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        result = fn(*a, **kw)
        print(f"traced {fn.__name__} -> {result}")
        return result

    return wrapper


def make_counter():
    count = 0

    def inc(step=1):
        nonlocal count
        count += step
        return count

    return inc


@trace
def add(a, b):
    return a + b


counter = make_counter()
counter(2)
print(add(3, 4))
print(counter())
print(counter(10))
sq = lambda x: x * x
print(sq(9))
print(sorted([(2, "b"), (1, "c")], key=lambda p: p[0]))
