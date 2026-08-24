"""Differential suite: SOURCE -> protect -> run -> compare against original.

Covers the compatibility fixture matrix (spec section 18/19): plain scripts
across language features plus a package with relative + dynamic imports.
"""

import ast
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.dirname(__file__))

import harness  # noqa: E402

from openprotect.gen import Options, protect_path  # noqa: E402


class DifferentialTests(unittest.TestCase):
    SEED = "diff-matrix"

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="op-diff-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _protect_and_run(self, source_path: pathlib.Path) -> harness.RunResult:
        dist = self.tmp / ("dist_" + source_path.stem)
        written = protect_path(source_path, dist, Options(seed=self.SEED))
        stub = next(w for w in written if w.name == source_path.name)
        return harness.run_script(stub)

    def test_plain_fixtures_match_original(self):
        failures = []
        for fixture in harness.compat_fixtures():
            with self.subTest(fixture=fixture.name):
                original = harness.run_script(fixture)
                protected = self._protect_and_run(fixture)
                problems = harness.compare(original, protected)
                if problems:
                    failures.append(f"{fixture.name}: {problems}")
        if failures:
            self.fail("differential mismatches: " + " | ".join(failures))

    def test_package_with_relative_and_dynamic_imports(self):
        pkg = harness.package_fixture()
        dist = self.tmp / "dist_pkg"
        protect_path(pkg, dist, Options(seed=self.SEED))

        driver_src = (
            "import importlib, sys\n"
            f"sys.path.insert(0, r'{dist}')\n"
            "from pkg_demo import Engine\n"
            "print(Engine('turbo').go())\n"
            "util = importlib.import_module('pkg_demo.util')\n"
            "print(util.tag('dyn-ok'))\n"
            "import pkg_demo\n"
            "print(sorted(pkg_demo.__all__))\n"
        )
        driver = dist / "_driver.py"
        driver.write_text(driver_src, encoding="utf-8")

        # reference run against the ORIGINAL package tree
        orig_driver = self.tmp / "_orig_driver.py"
        orig_driver.write_text(
            driver_src.replace(f"r'{dist}'", f"r'{pkg.parent}'"), encoding="utf-8"
        )
        original = harness.run_script(orig_driver, cwd=pkg.parent)
        protected = harness.run_script(driver, cwd=dist)
        problems = harness.compare(original, protected)
        if problems:
            self.fail("package differential mismatch: " + " | ".join(problems))

    def test_protected_stub_hides_source(self):
        """Every produced stub must contain zero original source text."""
        for fixture in harness.compat_fixtures():
            with self.subTest(fixture=fixture.name):
                src_text = fixture.read_text(encoding="utf-8")
                dist = self.tmp / ("hide_" + fixture.stem)
                written = protect_path(fixture, dist, Options(seed=self.SEED))
                stub_text = next(iter(written)).read_text(encoding="utf-8")
                for line in src_text.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith(("#", '"""', "'''")):
                        continue
                    if stripped.startswith(("import ", "from ")):
                        continue
                    first_token = stripped.split("(")[0].strip()
                    if len(first_token) >= 12:
                        self.assertNotIn(first_token, stub_text)


if __name__ == "__main__":
    unittest.main()
