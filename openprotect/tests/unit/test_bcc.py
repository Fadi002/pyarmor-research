import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from openprotect.bcc import (
    SETUP_TEMPLATE,
    _bootstrap_source,
    build_command,
    validate_introspection,
)


class ValidatorTests(unittest.TestCase):
    def test_inspect_usage_flagged(self):
        src = (
            "import inspect\n"
            "def f():\n"
            "    return inspect.getsource(f)\n"
        )
        warnings = validate_introspection(ast.parse(src))
        self.assertTrue(any("getsource" in w for w in warnings))
        self.assertTrue(any("inspect" in w for w in warnings))

    def test_clean_source_passes(self):
        src = "def add(a, b):\n    return a + b\n"
        self.assertEqual(validate_introspection(ast.parse(src)), [])

    def test_getframe_flagged(self):
        src = "import sys\nprint(sys._getframe(1))\n"
        self.assertTrue(validate_introspection(ast.parse(src)))


class StubShapeTests(unittest.TestCase):
    def test_bootstrap_unlicensed(self):
        src = _bootstrap_source("abc123", "None", "None")
        tree = ast.parse(src)  # must parse
        names = {
            t.id for n in tree.body if isinstance(n, ast.Assign)
            for t in ([n.targets[0]] if isinstance(n.targets[0], ast.Name) else [])
        }
        self.assertIn("_OP_STRS", names)
        self.assertIn("_OP_LIC", names)

    def test_bootstrap_licensed_literal_shape(self):
        lic = "{'lic': 'D', 'lic_sig': 'S'}"
        src = _bootstrap_source("abc123", "b'blob'", lic)
        tree = ast.parse(src)
        values = {}
        for n in tree.body:
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    for sub in ast.walk(t):
                        if isinstance(sub, ast.Name):
                            try:
                                values[sub.id] = ast.literal_eval(n.value)
                            except Exception:
                                pass
        self.assertEqual(values["_OP_LIC"]["lic"], "D")
        self.assertEqual(values["_OP_STRS"], b"blob")


class BuildCommandTests(unittest.TestCase):
    def test_argv_shape(self):
        import pathlib

        cmd = build_command("mymod", pathlib.Path("/w"))
        self.assertEqual(cmd[-2:], ["build_ext", "--inplace"])
        self.assertTrue(cmd[1].endswith("setup.py"))


if __name__ == "__main__":
    unittest.main()
