import ast
import os
import pathlib
import sys
import types
import unittest

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(_ROOT, "src"))

from openprotect.gen import Options, protect_source

SOURCE = '''\
GREETING = "hello from table"
TARGET = "world"


def build():
    return GREETING + " " + "literal-inside"


class Msg:
    KIND = "kind-string"
'''


def _build_module(level: str = "standard", key: bytes = b"\x21" * 32):
    result = protect_source(SOURCE, "m", "m.py", key, Options(level=level, seed="s"))
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

    g: dict = {"__name__": "m", "__file__": "m.py"}

    class FF:
        def __init__(self, gg):
            self.f_globals = gg

    old = sys._getframe
    sys._getframe = lambda d=0: FF(g) if d == 1 else old(d)
    try:
        loader("m", "m.py", blob)
    finally:
        sys._getframe = old
    return g


class MixStrTests(unittest.TestCase):
    def test_strings_resolve_at_runtime(self):
        g = _build_module()
        self.assertEqual(g["GREETING"], "hello from table")
        self.assertEqual(g["TARGET"], "world")
        self.assertEqual(g["Msg"].KIND, "kind-string")
        self.assertEqual(g["build"](), "hello from table literal-inside")

    def test_header_flags_mixed_strs(self):
        import json
        import struct

        result = protect_source(SOURCE, "m", "m.py", b"\x21" * 32, Options(level="standard", seed="s"))
        _, hlen = struct.unpack(">HH", result.container[8:12])
        header = json.loads(result.container[12 : 12 + hlen].decode())
        self.assertTrue(header["mixed_strs"])

    def test_minimal_level_keeps_plain(self):
        import json
        import struct

        result = protect_source(SOURCE, "m", "m.py", b"\x21" * 32, Options(level="minimal", seed="s"))
        _, hlen = struct.unpack(">HH", result.container[8:12])
        header = json.loads(result.container[12 : 12 + hlen].decode())
        self.assertFalse(header["mixed_strs"])

    def test_plaintext_strings_absent_from_payload(self):
        from openprotect.compiler import builder
        from openprotect.frontend.string_mix import StringMixer

        mixer = StringMixer()
        tree = mixer.process(ast.parse(SOURCE))
        code = builder.compile_tree(tree, "m.py")
        raw = builder.marshal_code(code)
        # the marshaled payload must not carry any of the original literals
        self.assertNotIn(b"hello from table", raw)
        self.assertNotIn(b"literal-inside", raw)


if __name__ == "__main__":
    unittest.main()
