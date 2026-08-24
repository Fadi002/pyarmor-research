"""Differential harness: run original vs protected, compare observable behavior.

Per spec section 19: stdout, stderr and exit code must match. Fixtures are
deterministic (no clock, no randomness, no network). Each protected build
uses a fixed seed so the comparison is stable across runs.
"""

from __future__ import annotations

import dataclasses
import pathlib
import subprocess
import sys

_COMPAT_ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "compat"


@dataclasses.dataclass
class RunResult:
    stdout: str
    stderr: str
    exit_code: int


def run_script(script_path: pathlib.Path, cwd: pathlib.Path | None = None) -> RunResult:
    proc = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(cwd) if cwd else None,
    )
    return RunResult(proc.stdout, proc.stderr, proc.returncode)


def compare(original: RunResult, protected: RunResult) -> list[str]:
    mismatches = []
    if original.stdout != protected.stdout:
        mismatches.append(f"stdout differs:\n--original--\n{original.stdout}\n--protected--\n{protected.stdout}")
    if original.stderr != protected.stderr:
        mismatches.append(f"stderr differs:\n--original--\n{original.stderr}\n--protected--\n{protected.stderr}")
    if original.exit_code != protected.exit_code:
        mismatches.append(f"exit code {original.exit_code} != {protected.exit_code}")
    return mismatches


def compat_fixtures() -> list[pathlib.Path]:
    return sorted(_COMPAT_ROOT.glob("*.py"))


def package_fixture() -> pathlib.Path:
    pkg = _COMPAT_ROOT / "pkg_demo"
    if not pkg.is_dir():  # pragma: no cover - layout guard
        raise AssertionError(f"missing package fixture at {pkg}")
    return pkg
