def greet(name):
    message = "hello " + name
    return message


class Calculator:
    def add(self, a, b):
        return a + b

    def multiply(self, a, b):
        return a * b


SECRET = "s3cr3t-token-value"


def fib(n):
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)


async def async_double(x):
    return x * 2


def main():
    calc = Calculator()
    print(greet("world"))
    print(calc.add(2, 3), calc.multiply(4, 5))
    print(len(SECRET))
    print(fib(10))


if __name__ == "__main__":
    main()
