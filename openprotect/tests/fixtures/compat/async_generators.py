import asyncio


async def fetch(name, delay):
    await asyncio.sleep(delay)
    return f"{name}:done"


async def main():
    single = await fetch("db", 0.01)
    both = await asyncio.gather(fetch("a", 0.01), fetch("b", 0.02))
    return single, sorted(both)


def squares(n):
    for i in range(n):
        yield i * i


def fib_gen():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b


print(asyncio.run(main()))
print(list(squares(5)))
g = fib_gen()
print([next(g) for _ in range(8)])
