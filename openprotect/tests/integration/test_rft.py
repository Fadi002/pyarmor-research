import ast
import os
import pathlib
import sys
import tempfile
import unittest

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(_ROOT, "src"))

from openprotect.gen import Options, protect_source

SOURCE = '''\
import math as m


def public_api(x):
    return _helper(x) + 1


def _helper(x):
    return x * 2


def shadowed(y):
    return y * 10


def uses_shadow():
    shadowed = 5
    return shadowed


def calls_shadowed():
    return shadowed(3)


class Tool:
    def use(self):
        return m.sqrt(4)
'''


class RftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="op-rft-"))
        self.src = self.tmp / "r.py"
        self.src.write_text(SOURCE, encoding="utf-8")

    def _build(self, key: bytes = b"\x33" * 32):
        result = protect_source(
            SOURCE, "r", str(self.src), key, Options(level="standard", seed="r1", enable_rft=True)
        )
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

        g: dict = {"__name__": "r", "__file__": "r.py"}

        class FF:
            def __init__(self, gg):
                self.f_globals = gg

        old = sys._getframe
        sys._getframe = lambda d=0: FF(g) if d == 1 else old(d)
        try:
            loader("r", "r.py", blob)
        finally:
            sys._getframe = old
        return g, result

    def test_renamed_functions_still_work(self):
        from openprotect.frontend.rft import RftRenamer, _new_name

        salt = RftRenamer.salt_for(b"\x33" * 32, "r")
        g, _ = self._build()
        # the rename map is deterministic - assert exact names + behavior
        self.assertEqual(g[_new_name("public_api", salt)](10), 21)
        self.assertEqual(g[_new_name("_helper", salt)](5), 10)
        tool = g[_new_name("Tool", salt)]()
        self.assertEqual(tool.use(), 2.0)

    def test_original_names_gone(self):
        g, _ = self._build()
        for gone in ("public_api", "_helper", "Tool"):
            self.assertNotIn(gone, g)

    def test_shadowed_name_not_renamed(self):
        g, _ = self._build()
        # a local `shadowed = 5` elsewhere blocked renaming of the top-level
        # def, so its public name survives...
        self.assertIn("shadowed", g)
        # ...and a renamed caller that references it still resolves correctly
        sentinel = object()
        results = []
        for k, v in g.items():
            if callable(v) and not k.startswith("__"):
                try:
                    results.append(v())
                except TypeError:
                    continue  # arity-required function; not our zero-arg caller
        self.assertIn(30, results)

    def test_deterministic_renames(self):
        _, r1 = self._build()
        result2 = protect_source(
            SOURCE, "r", str(self.src), b"\x33" * 32,
            Options(level="standard", seed="r1", enable_rft=True),
        )
        import re

        names1 = sorted(re.findall(r"_op[0-9a-f]{8}", r1.stub_text))
        names2 = sorted(re.findall(r"_op[0-9a-f]{8}", result2.stub_text))
        self.assertEqual(names1, names2)

    def test_rft_disabled_by_default(self):
        result = protect_source(SOURCE, "r", str(self.src), b"\x33" * 32, Options(seed="r"))
        self.assertNotIn("_op", result.stub_text)


if __name__ == "__main__":
    unittest.main()
