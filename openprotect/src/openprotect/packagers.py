"""Bundling of protected distributions via PyInstaller or Nuitka.

Both tools follow the stub's `from openprotect_runtime_<id> import ...`
statically: PyInstaller bundles the runtime package as bytecode, Nuitka
compiles it to C. Either way the encrypted blobs ride along untouched and
the loader keeps working inside the bundle - no data-file tricks needed,
just a module search path pointing at the dist directory.

Command construction lives in :func:`build_command` (pure, unit-testable);
:func:`pack` orchestrates detection, staging and invocation.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

SUPPORTED_TOOLS = ("pyinstaller", "nuitka")
MODES = ("onefile", "onedir")


class PackError(Exception):
    pass


def _tool_available(tool: str) -> bool:
    import importlib.util

    if tool == "nuitka":
        return importlib.util.find_spec("nuitka") is not None or shutil.which("nuitka") is not None
    # pyinstaller ships both an importable package and a CLI wrapper
    return importlib.util.find_spec("PyInstaller") is not None or shutil.which(tool) is not None


def detect_tool(preferred: str | None = None) -> str:
    order = [preferred] if preferred else list(SUPPORTED_TOOLS)
    for tool in order:
        if tool not in SUPPORTED_TOOLS:
            raise PackError(f"unknown packer {tool!r}; choose from {', '.join(SUPPORTED_TOOLS)}")
        if _tool_available(tool):
            return tool
    raise PackError(
        "no packer found; install pyinstaller (`pip install pyinstaller`) "
        "or nuitka (`pip install nuitka`)"
    )


def build_command(
    tool: str,
    mode: str,
    entry_stub: pathlib.Path,
    dist_dir: pathlib.Path,
    out_dir: pathlib.Path,
    work_dir: pathlib.Path,
) -> list[str]:
    """Build the argv for the external bundler. Pure function."""
    if mode not in MODES:
        raise PackError(f"pack mode must be one of {', '.join(MODES)}")
    if tool not in SUPPORTED_TOOLS:
        raise PackError(f"unknown packer {tool!r}")

    env_path = str(dist_dir)
    if tool == "pyinstaller":
        cmd = [
            sys_executable(),
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            f"--distpath={out_dir}",
            f"--workpath={work_dir / 'build'}",
            f"--specpath={work_dir}",
            "--paths",
            env_path,
            "--name",
            entry_stub.stem,
        ]
        cmd.append("--onefile" if mode == "onefile" else "--onedir")
        cmd.append(str(entry_stub))
        return cmd

    # nuitka
    cmd = [
        sys_executable(),
        "-m",
        "nuitka",
        "--standalone",
        "--assume-yes-for-downloads",
        f"--output-dir={out_dir}",
        f"--output-filename={_exe_name(entry_stub.stem)}",
    ]
    if mode == "onefile":
        cmd.append("--onefile")
    # the openprotect runtime package is discovered by following imports,
    # with PYTHONPATH pointing at dist_dir (set by pack()).
    cmd.append(str(entry_stub))
    return cmd


def _exe_name(stem: str) -> str:
    return stem + (".exe" if os.name == "nt" else "")


def sys_executable() -> str:
    import sys

    return sys.executable


def _env_with_dist(dist_dir: pathlib.Path) -> dict[str, str]:
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(dist_dir) + (os.pathsep + existing if existing else "")
    return env


def _artifact_path(tool: str, mode: str, out_dir: pathlib.Path, stem: str) -> pathlib.Path:
    exe = _exe_name(stem)
    if mode == "onefile":
        return out_dir / exe
    if tool == "pyinstaller":
        return out_dir / stem / exe
    return out_dir / f"{stem}.dist" / exe


def pack(
    entry_stub: pathlib.Path,
    dist_dir: pathlib.Path,
    mode: str = "onefile",
    tool: str | None = None,
    out_dir: pathlib.Path | None = None,
) -> pathlib.Path:
    """Bundle a protected distribution. Returns the produced artifact path."""
    entry_stub = pathlib.Path(entry_stub)
    dist_dir = pathlib.Path(dist_dir)
    out_dir = pathlib.Path(out_dir) if out_dir else dist_dir / "pack"
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = dist_dir / ".pack_work"
    work_dir.mkdir(parents=True, exist_ok=True)

    selected = detect_tool(tool)
    cmd = build_command(selected, mode, entry_stub.resolve(), dist_dir.resolve(), out_dir.resolve(), work_dir)

    proc = subprocess.run(
        cmd,
        cwd=str(work_dir),
        env=_env_with_dist(dist_dir),
        capture_output=True,
        text=True,
        timeout=3600,
    )
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.splitlines()[-25:] or proc.stdout.splitlines()[-25:])
        hint = ""
        if "Allocation error" in proc.stderr and mode == "onefile":
            hint = (
                "\nhint: the bundler's compressor ran out of memory during onefile "
                "packing; try --pack onedir"
            )
        raise PackError(f"{selected} failed (exit {proc.returncode}):\n{tail}{hint}")

    expected = _artifact_path(selected, mode, out_dir, entry_stub.stem)
    if expected.exists():
        return expected
    fallback = sorted(out_dir.glob("**/" + _exe_name(entry_stub.stem)))
    if fallback:
        return fallback[0]
    raise PackError(f"bundle produced no recognizable artifact in {out_dir}")
