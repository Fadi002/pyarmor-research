class SafeExit:
    def __init__(self, label):
        self.label = label

    def __enter__(self):
        print(f"enter {self.label}")
        return self

    def __exit__(self, exc_type, exc, tb):
        print(f"exit {self.label} ({exc_type.__name__ if exc_type else 'clean'})")
        return False


def divide(a, b):
    try:
        with SafeExit("math"):
            result = a // b
        return result
    except ZeroDivisionError:
        print("caught zero")
        return None
    finally:
        print("finally runs")


def level1():
    raise ValueError("deep")


def level2():
    try:
        level1()
    except ValueError as e:
        print(f"handled {e}")
        raise RuntimeError("wrapped") from e


print(divide(10, 2))
print(divide(5, 0))
try:
    level2()
except RuntimeError as e:
    print(f"outer {e} cause={type(e.__cause__).__name__}")

with SafeExit("multi") as a, SafeExit("second") as b:
    print("inside both")
