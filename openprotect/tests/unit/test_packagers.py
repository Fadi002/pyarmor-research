import os
import pathlib
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from openprotect.packagers import (
    PackError,
    _artifact_path,
    build_command,
    detect_tool,
)

STUB = pathlib.Path("/x/dist/hello.py")
DIST = pathlib.Path("/x/dist")
OUT = pathlib.Path("/x/out")
WORK = pathlib.Path("/x/work")


class CommandConstructionTests(unittest.TestCase):
    def test_pyinstaller_onefile(self):
        cmd = build_command("pyinstaller", "onefile", STUB, DIST, OUT, WORK)
        self.assertIn("--onefile", cmd)
        self.assertNotIn("--onedir", cmd)
        self.assertIn(str(STUB), cmd)
        self.assertIn(f"--distpath={OUT}", cmd)
        self.assertIn("--name", cmd)
        self.assertEqual(cmd[cmd.index("--paths") + 1], str(DIST))

    def test_pyinstaller_onedir(self):
        cmd = build_command("pyinstaller", "onedir", STUB, DIST, OUT, WORK)
        self.assertIn("--onedir", cmd)
        self.assertNotIn("--onefile", cmd)

    def test_nuitka_modes(self):
        onefile = build_command("nuitka", "onefile", STUB, DIST, OUT, WORK)
        self.assertIn("--standalone", cmd_ok := onefile)
        self.assertIn("--onefile", cmd_ok)
        onedir = build_command("nuitka", "onedir", STUB, DIST, OUT, WORK)
        self.assertNotIn("--onefile", onedir)
        self.assertTrue(any(a.startswith("--output-dir=") for a in onedir))
        self.assertTrue(any(a.startswith("--output-filename=") for a in onedir))
        self.assertIn(str(STUB), onedir)

    def test_invalid_mode_and_tool_rejected(self):
        with self.assertRaises(PackError):
            build_command("pyinstaller", "zip", STUB, DIST, OUT, WORK)
        with self.assertRaises(PackError):
            build_command("makeshift", "onefile", STUB, DIST, OUT, WORK)


class ArtifactPathTests(unittest.TestCase):
    def test_layouts(self):
        exe = "hello.exe" if os.name == "nt" else "hello"
        self.assertEqual(_artifact_path("pyinstaller", "onefile", OUT, "hello"), OUT / exe)
        self.assertEqual(
            _artifact_path("pyinstaller", "onedir", OUT, "hello"), OUT / "hello" / exe
        )
        self.assertEqual(_artifact_path("nuitka", "onefile", OUT, "hello"), OUT / exe)
        self.assertEqual(
            _artifact_path("nuitka", "onedir", OUT, "hello"), OUT / "hello.dist" / exe
        )


class DetectToolTests(unittest.TestCase):
    def test_unknown_tool_raises(self):
        with self.assertRaises(PackError):
            detect_tool("makeshift")

    def test_auto_or_known_returns_supported_name(self):
        try:
            tool = detect_tool()
        except PackError:
            self.skipTest("no packer installed")
        self.assertIn(tool, ("pyinstaller", "nuitka"))


if __name__ == "__main__":
    unittest.main()
