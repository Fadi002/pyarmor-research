"""End-to-end BCC tests.

Skipped automatically when Cython or a C compiler is unavailable, so CI
machines without toolchains stay green while dev machines get full native
coverage.
"""

import ast
import importlib.util
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(_ROOT, "src"))


def _cython_available() -> bool:
    return importlib.util.find_spec("Cython") is not None


def _compiler_available() -> bool:
    from shutil import which

    if any(which(c) for c in ("cl", "gcc", "cc", "clang")):
        return True
    # MSVC installs are common without PATH entries; vswhere marks them
    pf86 = os.environ.get("ProgramFiles(x86)")
    if pf86:
        vswhere = pathlib.Path(pf86) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
        return vswhere.exists()
    return False


def _outer_key_from(rt_file: pathlib.Path) -> bytes:
    ns: dict = {}
    exec(rt_file.read_text(encoding="utf-8"), ns)
    key = ns.get("_OUTER_KEY")
    if not key:
        raise AssertionError(f"runtime package missing _OUTER_KEY: {rt_file}")
    return key


@unittest.skipUnless(
    _cython_available() and _compiler_available(),
    "requires cython + a C compiler",
)
class BccEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="op-bcc-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _build(self, source: str, name: str = "m", **opt_kw):
        from openprotect.bcc import build_bcc_module, recover_bcc_source

        src = self.tmp / f"{name}.py"
        src.write_text(source, encoding="utf-8")
        result = build_bcc_module(
            source,
            name,
            str(src),
            b"\x44" * 32,
            self.tmp,
            seed="bcc-e2e",
            **opt_kw,
        )

        rt_pkg = next(self.tmp.glob("openprotect_runtime_*"))
        outer_key = _outer_key_from(rt_pkg / "openprotect_runtime.py")
        recovered, _hdr = (
            None,
            None,
        )
        from openprotect.bcc import recover_bcc_source

        recovered, hdr = recover_bcc_source(result.stub_path, outer_key)

        sys.path.insert(0, str(self.tmp))
        try:
            native = __import__(name)
        finally:
            sys.path.remove(str(self.tmp))
        return native, recovered, result

    def test_native_module_runs_and_roundtrips(self):
        SOURCE = (
            "def add(a, b):\n"
            "    return a + b\n\n\n"
            "def fib(n):\n"
            "    return n if n < 2 else fib(n - 1) + fib(n - 2)\n"
        )
        native, recovered, result = self._build(SOURCE, name="nativemod")
        self.assertEqual(native.add(20, 22), 42)
        self.assertEqual(native.fib(12), 144)
        self.assertEqual(recovered, SOURCE)
        self.assertTrue(result.native_module.exists())
        self.assertGreater(result.native_module.stat().st_size, 10_000)
        # staged sources must never ship; stub carries no original defs
        self.assertEqual(list(self.tmp.glob(".bcc_work")), [])
        stub_text = result.stub_path.read_text(encoding="utf-8")
        self.assertNotIn("def add(", stub_text)
        self.assertNotIn("def fib(", stub_text)

    def test_secret_string_absent_from_native_artifact(self):
        SECRET = "xyzzy-plugh-777"
        SOURCE = f"TOKEN = {SECRET!r}\n"
        native, _, result = self._build(SOURCE, name="strmod")
        raw = result.native_module.read_bytes()
        self.assertNotIn(SECRET.encode(), raw)

    def test_expired_license_refused_at_import(self):
        from openprotect.gen import Options, prepare_license

        opts = Options(seed="exp", expired="2001-01-01")
        license_key, license_header = prepare_license(opts)
        SOURCE = "VALUE = 1\n"
        with self.assertRaises(RuntimeError) as ctx:
            self._build(SOURCE, name="expmod", license_key=license_key, license_header=license_header)
        self.assertIn("expired", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
