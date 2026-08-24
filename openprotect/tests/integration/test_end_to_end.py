import ast
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(_ROOT, "src"))

from openprotect.deobfuscate import deobfuscate, default_output_for, extract_container, load_outer_key
from openprotect.gen import Options, protect_path
from openprotect.inspection import inspect, verify

FIXTURE = pathlib.Path(_ROOT) / "tests" / "fixtures" / "hello.py"


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="openprotect-e2e-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _protect(self, seed="s1", **kw):
        dist = self.tmp / "dist"
        written = protect_path(FIXTURE, dist, Options(seed=seed, **kw))
        return dist, written

    def _load_stub(self, stub: pathlib.Path):
        # mirror real usage: script dir is importable (python dist/hello.py)
        stub_dir = str(stub.parent)
        if stub_dir not in sys.path:
            sys.path.insert(0, stub_dir)
            self.addCleanup(sys.path.remove, stub_dir)
        spec = importlib.util.spec_from_file_location("protected_hello", stub)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_protect_run_deobfuscate_roundtrip(self):
        original = FIXTURE.read_text(encoding="utf-8")
        dist, written = self._protect()
        stub = dist / "hello.py"
        self.assertIn(stub, written)
        text = stub.read_text(encoding="utf-8")
        self.assertNotIn("def greet", text)
        self.assertIn("__pyarmor__(__name__, __file__, b'OPENPRT1", text)

        runtime_pkgs = list(dist.glob("openprotect_runtime_*"))
        self.assertEqual(len(runtime_pkgs), 1)
        self.assertTrue((runtime_pkgs[0] / "openprotect_runtime.py").exists())

        module = self._load_stub(stub)
        self.assertEqual(module.greet("x"), "hello x")
        self.assertEqual(module.Calculator().add(2, 3), 5)
        self.assertEqual(module.SECRET, "s3cr3t-token-value")
        self.assertEqual(module.fib(10), 55)

        out = self.tmp / "restored.py"
        deobfuscate(stub, out)
        self.assertEqual(out.read_text(encoding="utf-8"), original)

    def test_deterministic_builds_with_seed(self):
        d1, w1 = self._protect(seed="det")
        # second run into a fresh dir must be byte-identical
        d2 = self.tmp / "dist2"
        w2 = protect_path(FIXTURE, d2, Options(seed="det"))
        self.assertEqual(
            (d1 / "hello.py").read_bytes(), (d2 / "hello.py").read_bytes()
        )
        r1 = next(d1.glob("openprotect_runtime_*/openprotect_runtime.py"))
        r2 = next(d2.glob("openprotect_runtime_*/openprotect_runtime.py"))
        k1 = r1.read_text().splitlines()[2]
        k2 = r2.read_text().splitlines()[2]
        self.assertNotEqual(k1, "")  # key line exists
        # runtime ids identical under same seed
        self.assertEqual(r1.parent.name, r2.parent.name)

    def test_unseeded_builds_differ(self):
        d1, _ = self._protect()
        d2 = self.tmp / "dist2"
        protect_path(FIXTURE, d2, Options())
        a = (d1 / "hello.py").read_bytes()
        b = (d2 / "hello.py").read_bytes()
        self.assertNotEqual(a, b)

    def test_inspect_and_verify(self):
        dist, _ = self._protect(no_recovery=False)
        stub = str(dist / "hello.py")
        header = inspect(stub)
        self.assertEqual(header["module"], "hello")
        self.assertIn("pytag", header)
        self.assertTrue(verify(stub))

    def test_verify_detects_tamper(self):
        dist, _ = self._protect()
        stub = dist / "hello.py"
        text = stub.read_text(encoding="utf-8")
        original_blob = extract_container(stub)
        tampered = bytearray(original_blob)
        tampered[len(tampered) // 2] ^= 0xFF
        flipped_text = text.replace(repr(original_blob), repr(bytes(tampered)))
        stub.write_text(flipped_text, encoding="utf-8")
        self.assertFalse(verify(str(stub)))

    def test_no_recovery_flag(self):
        dist, _ = self._protect(no_recovery=True)
        stub = dist / "hello.py"
        from openprotect.deobfuscate import recover_source

        with self.assertRaises(Exception):
            recover_source(stub)

    def test_docstrings_stripped_at_standard_level(self):
        src = 'def f():\n    """docstring"""\n    return 1\n'
        p = self.tmp / "mini.py"
        p.write_text(src, encoding="utf-8")
        dist = self.tmp / "dist_mini"
        protect_path(p, dist, Options(seed="lvl"))
        module = self._load_stub(dist / "mini.py")
        self.assertIsNone(module.f.__doc__)

    def test_extract_container_never_executes_source(self):
        dist, _ = self._protect()
        blob = extract_container(dist / "hello.py")
        self.assertTrue(blob.startswith(b"OPENPRT1"))


if __name__ == "__main__":
    unittest.main()
