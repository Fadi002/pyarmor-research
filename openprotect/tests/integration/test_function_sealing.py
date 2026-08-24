import asyncio
import ast
import marshal
import os
import pathlib
import shutil
import sys
import tempfile
import types
import unittest

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(_ROOT, "src"))

from openprotect.gen import Options, protect_source

SOURCE = '''\
import functools


def add(a, b=3):
    """adds"""
    return a + b


def fib(n):
    return n if n < 2 else fib(n - 1) + fib(n - 2)


def shout(fn):
    @functools.wraps(fn)
    def w(*a, **k):
        return fn(*a, **k).upper()
    return w


@shout
def greet(name):
    return "hi " + name


async def double(x):
    return x * 2


def count(n):
    i = 0
    while i < n:
        yield i
        i += 1
'''


class FunctionSealingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="op-seal-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "mod.py"
        self.src.write_text(SOURCE, encoding="utf-8")

    def _build_module(self, level: str = "standard", key: bytes = b"\x07" * 32, **opt_kw):
        result = protect_source(SOURCE, "mod", str(self.src), key, Options(level=level, seed="t", **opt_kw))
        blob = None
        for node in ast.walk(ast.parse(result.stub_text)):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "__pyarmor__":
                blob = ast.literal_eval(node.args[-1])

        loader_file = (
            pathlib.Path(_ROOT) / "src" / "openprotect" / "runtime" / "standalone_loader.py"
        )
        ns: dict = {}
        exec(loader_file.read_text(encoding="utf-8"), ns)
        loader = ns["make_loader"](key)

        g: dict = {"__name__": "mod", "__file__": "mod.py"}

        class FF:
            def __init__(self, gg):
                self.f_globals = gg

        old = sys._getframe
        sys._getframe = lambda d=0: FF(g) if d == 1 else old(d)
        try:
            loader("mod", "mod.py", blob)
        finally:
            sys._getframe = old
        return g

    def test_sync_functions_forward(self):
        m = self._build_module()
        self.assertEqual(m["add"](2), 5)
        self.assertEqual(m["fib"](10), 55)

    def test_decorator_applied(self):
        m = self._build_module()
        self.assertEqual(m["greet"]("bob"), "HI BOB")
        self.assertEqual(m["greet"].__name__, "greet")

    def test_async_and_generator(self):
        m = self._build_module()
        self.assertEqual(asyncio.run(m["double"](21)), 42)
        self.assertEqual(list(m["count"](3)), [0, 1, 2])

    def test_metadata_preserved(self):
        m = self._build_module()
        # before first call we hold the forwarding wrapper; it carries the
        # public name, and behaves identically once invoked
        self.assertEqual(m["add"].__name__, "add")
        self.assertEqual(m["add"](2), 5)
        self.assertEqual(m["add"](2, b=10), 12)

    def test_recursion_through_wrapper(self):
        m = self._build_module()
        self.assertEqual(m["fib"](12), 144)

    def test_wrap_mode_keeps_wrapper_permanent(self):
        g = self._build_module()
        self.assertEqual(g["add"](2), 5)
        # wrap mode (default): the public name stays bound to the forwarding
        # wrapper so every call keeps passing the runtime hop
        self.assertEqual(g["add"].__code__.co_varnames, ("args", "kwargs"))
        self.assertEqual(g["add"](2, b=4), 6)

    def test_no_wrap_self_heals(self):
        g = self._build_module(wrap=False)
        self.assertEqual(g["add"](2), 5)
        # --no-wrap: first call rebuilds directly into module globals and
        # replaces the wrapper with the real function
        self.assertIn("b", g["add"].__code__.co_varnames)

    def test_bodies_replaced_by_forwarders(self):
        from openprotect.compiler import builder
        from openprotect.frontend.function_seal import FunctionSealer

        sealer = FunctionSealer("mod.py")
        tree = sealer.process(ast.parse(SOURCE))
        code = builder.compile_tree(tree, "mod.py")
        nested = [c for c in code.co_consts if isinstance(c, types.CodeType)]
        by_name = {c.co_name: c for c in nested}
        # every sealed function's module-level code object is now a thin
        # forwarder (*args, **kwargs), not the original body
        for fname in ("add", "fib", "double", "count"):
            self.assertIn(fname, by_name)
            self.assertEqual(
                by_name[fname].co_varnames,
                ("args", "kwargs"),
                f"{fname} was not replaced by a forwarding wrapper",
            )

    def test_minimal_level_skips_sealing(self):
        import json
        import struct

        result = protect_source(
            SOURCE, "mod", str(self.src), b"\x07" * 32, Options(level="minimal", seed="t")
        )
        _, hlen = struct.unpack(">HH", result.container[8:12])
        header = json.loads(result.container[12 : 12 + hlen].decode())
        self.assertFalse(header["sealed_funcs"])

    def test_standard_level_reports_sealing(self):
        import json
        import struct

        result = protect_source(
            SOURCE, "mod", str(self.src), b"\x07" * 32, Options(level="standard", seed="t")
        )
        _, hlen = struct.unpack(">HH", result.container[8:12])
        header = json.loads(result.container[12 : 12 + hlen].decode())
        self.assertTrue(header["sealed_funcs"])


if __name__ == "__main__":
    unittest.main()
