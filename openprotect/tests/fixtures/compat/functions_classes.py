def classify(n):
    if n < 0:
        return "negative"
    return "even" if n % 2 == 0 else "odd"


def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


class Animal:
    kind = "generic"

    def speak(self):
        return f"...{self.kind}..."


class Dog(Animal):
    kind = "dog"

    def speak(self):
        return super().speak().upper()


print(classify(-5), classify(4), classify(7))
print(fib(15))
print(Dog().speak())
print(isinstance(Dog(), Animal), len(Animal.__subclasses__()))
