import ast
import base64
import hashlib
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(_ROOT, "src"))

from openprotect.gen import Options, protect_path
from openprotect.protection import license as licensing
from openprotect.protection import rsa

SEED_KEY = rsa.generate_deterministic_keypair(hashlib.sha256(b"unit-test-license").digest())


class RsaTests(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        msg = b"descriptor-json-bytes"
        sig = rsa.sign(SEED_KEY, msg, salt=b"\x42" * 32)
        self.assertTrue(rsa.verify((SEED_KEY["n"], SEED_KEY["e"]), msg, sig))

    def test_tampered_message_rejected(self):
        sig = rsa.sign(SEED_KEY, b"original")
        self.assertFalse(rsa.verify((SEED_KEY["n"], SEED_KEY["e"]), b"tampered", sig))

    def test_wrong_key_rejected(self):
        other = rsa.generate_deterministic_keypair(hashlib.sha256(b"other").digest())
        sig = rsa.sign(SEED_KEY, b"msg")
        self.assertFalse(rsa.verify((other["n"], other["e"]), b"msg", sig))


class DescriptorTests(unittest.TestCase):
    def test_build_normalizes_devices(self):
        import json

        d = json.loads(licensing.build_descriptor(None, ["AA-BB-CC-DD-EE-FF", "laptop"], None, None))
        self.assertEqual(d["dev"], ["mac:aabbccddeeff", "str:laptop"])

    def test_invalid_expiry_rejected_early(self):
        with self.assertRaises(ValueError):
            licensing.build_descriptor("not-a-date", None, None, None)

    def test_check_license_roundtrip(self):
        desc = licensing.build_descriptor("2099-01-01", None, "user-123", 7)
        desc_b64, sig_b64 = licensing.sign_descriptor(SEED_KEY, desc)
        info = licensing.check_license(SEED_KEY["n"], SEED_KEY["e"], desc_b64, sig_b64)
        self.assertEqual(info["data"], "user-123")

    def test_expired_descriptor_raises(self):
        desc = licensing.build_descriptor("2001-01-01", None, None, None)
        desc_b64, sig_b64 = licensing.sign_descriptor(SEED_KEY, desc)
        with self.assertRaises(licensing.LicenseError):
            licensing.check_license(SEED_KEY["n"], SEED_KEY["e"], desc_b64, sig_b64)

    def test_bad_signature_raises(self):
        desc = licensing.build_descriptor(None, None, None, None)
        _b64, sig_b64 = licensing.sign_descriptor(SEED_KEY, desc)
        bad_sig = base64.b64encode(bytes(a ^ 1 for a in base64.b64decode(sig_b64))).decode()
        with self.assertRaises(licensing.LicenseError):
            licensing.check_license(SEED_KEY["n"], SEED_KEY["e"], desc, bad_sig)


SOURCE = 'VALUE = "licensed-ok"\n'


class LicensedLoadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="op-lic-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _build(self, opts: Options) -> dict:
        src = self.tmp / "m.py"
        src.write_text(SOURCE, encoding="utf-8")
        dist = self.tmp / "dist"
        protect_path(src, dist, opts)

        stub = dist / "m.py"
        blob = None
        pkg_name = None
        for node in ast.walk(ast.parse(stub.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module:
                pkg_name = node.module
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "__pyarmor__":
                blob = ast.literal_eval(node.args[-1])

        rt_file = dist / pkg_name / "openprotect_runtime.py"
        ns: dict = {}
        exec(rt_file.read_text(encoding="utf-8"), ns)
        loader = ns["__pyarmor__"]

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

    def test_unlicensed_still_loads(self):
        g = self._build(Options(seed="L"))
        self.assertEqual(g["VALUE"], "licensed-ok")

    def test_licensed_with_satisfied_binding(self):
        opts = Options(seed="L2", expired="2099-01-01", bind_devices=["str:lab-node"], bind_data="u-77")
        with mock.patch.dict(os.environ, {"OPENPROTECT_DEVICE": "lab-node"}):
            g = self._build(opts)
        self.assertEqual(g["VALUE"], "licensed-ok")
        self.assertEqual(g["__pyarmor_license__"]["data"], "u-77")

    def test_unsatisfied_device_refused(self):
        opts = Options(seed="L3", bind_devices=["str:not-this-machine"])
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENPROTECT_DEVICE", None)
            with self.assertRaises(RuntimeError) as ctx:
                self._build(opts)
        self.assertIn("device binding", str(ctx.exception))

    def test_expired_container_refused(self):
        opts = Options(seed="L4", expired="2001-06-15")
        with self.assertRaises(RuntimeError) as ctx:
            self._build(opts)
        self.assertIn("expired", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
