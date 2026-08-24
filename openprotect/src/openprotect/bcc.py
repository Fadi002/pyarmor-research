"""BCC mode: compile obfuscated modules to native extensions via Cython.

Pipeline (decisions locked with maintainer):

    source -> strip docstrings -> mix-str -> rft (opt-in)
           -> prepend compiled-in bootstrap (license check + string table)
           -> ast.unparse -> Cython build_ext -> <name>.<tag>.pyd
           -> guarded stub (import surface + undo map)

The compiled prologue calls back into the generated runtime package
(`bcc_init`) for license verification and string-table decryption - all
cryptography stays in one auditable place, and dist-only attackers cannot
strip checks they cannot recompile without the original source.

Known semantic deltas, warned about by :func:`validate_introspection`:
native modules have no Python frames, so ``inspect.getsource``,
``sys._getframe``-style tricks and tracing hooks do not observe them.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys

from . import __version__
from .compiler import builder
from .frontend import transforms as tx
from .frontend.function_seal import FunctionSealer  # noqa: F401  (parity reference)
from .frontend.rft import RftRenamer
from .frontend.string_mix import StringMixer
from .protection.gcm import AesGcm
from .protection.keys import hkdf_expand
from .runtime.generator import make_runtime_id

_INTROSPECTION_MARKERS = ("getsource", "getsourcelines", "_getframe", "settrace", "setprofile", "currentframe")


@dataclasses.dataclass
class BccResult:
    stub_path: pathlib.Path
    native_module: pathlib.Path
    warnings: list[str]


def _append_bcc_helpers(rt_file: pathlib.Path, licensed: bool) -> None:
    """Append license verification helper used by compiled prologues."""
    if not licensed:
        return
    helpers = (
        "\n\n"
        "def verify_license(desc_b64, sig_b64):\n"
        "    import base64, json\n"
        "    desc = base64.b64decode(desc_b64)\n"
        "    sig = base64.b64decode(sig_b64)\n"
        "    if not _rsa_pss_verify(_LICENSE_PUBLIC_N, _LICENSE_PUBLIC_E, desc, sig):\n"
        "        raise RuntimeError('license signature verification failed')\n"
        "    info = json.loads(desc.decode('utf-8'))\n"
        "    import datetime as _dt\n"
        "    if 'exp' in info and _dt.datetime.now(_dt.timezone.utc).date() > _dt.date.fromisoformat(info['exp']):\n"
        "        raise RuntimeError(f\"license expired on {info['exp']}\")\n"
        "    return info\n"
    )
    text = rt_file.read_text(encoding="utf-8")
    rt_file.write_text(text + helpers, encoding="utf-8")


# --- pre-flight validation --------------------------------------------------


def validate_introspection(tree: ast.Module) -> list[str]:
    """Warn about constructs whose semantics change under native compilation."""
    warnings: list[str] = []

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("inspect", "traceback"):
                    imported.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module in ("inspect", "traceback"):
            for alias in node.names:
                imported.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _INTROSPECTION_MARKERS:
            warnings.append(f"line {node.lineno}: uses '{node.attr}' - no Python frames exist in native code")
        elif isinstance(node, ast.Name) and node.id in imported and isinstance(node.ctx, ast.Load):
            warnings.append(f"line {node.lineno}: introspection module '{node.id}' sees nothing through native code")
    return sorted(set(warnings))


# --- main-guard extraction ---------------------------------------------------


def extract_main_guard(tree: ast.Module) -> bool:
    """Replace ``if __name__ == "__main__": BODY`` with a callable entry.

    Native modules initialize under their own name at import time, so a
    literal __main__ check would be dead code. The stub calls
    ``_op_main_entry`` when IT executes as a script, preserving semantics.
    Returns True when a guard was found and rewritten.
    """

    def is_main_guard(node: ast.stmt) -> bool:
        if not isinstance(node, ast.If):
            return False
        test = node.test
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__"
        ):
            return False
        return True

    replaced = False
    new_body = []
    for stmt in tree.body:
        if not replaced and is_main_guard(stmt):
            entry = ast.FunctionDef(
                name="_op_main_entry",
                args=ast.arguments(
                    posonlyargs=[],
                    args=[],
                    vararg=None,
                    kwonlyargs=[],
                    kw_defaults=[],
                    kwarg=None,
                    defaults=[],
                ),
                body=stmt.body,
                decorator_list=[],
                returns=None,
                type_comment=None,
            )
            marker = ast.Assign(
                targets=[ast.Name(id="_OP_HAS_ENTRY", ctx=ast.Store())],
                value=ast.Constant(value=True),
            )
            new_body.extend([entry, marker])
            ast.fix_missing_locations(entry)
            ast.fix_missing_locations(marker)
            replaced = True
        else:
            new_body.append(stmt)
    tree.body = new_body  # type: ignore[assignment]
    return replaced


# --- prologue ---------------------------------------------------------------


def _bootstrap_source(runtime_id: str, str_blob_literal: str, lic_literal: str) -> str:
    return (
        f"_OP_STRS = {str_blob_literal}\n"
        f"_OP_LIC = {lic_literal}\n"
        f"from openprotect_runtime_{runtime_id} import bcc_init\n"
        "__pyarmor_str__, __pyarmor_license__, __pyarmor_periodic__ = "
        "bcc_init(_OP_STRS, _OP_LIC)\n"
    )


def build_command(module_stem: str, work_dir: pathlib.Path) -> list[str]:
    """Pure helper: argv for the staged cythonize build."""
    return [
        sys.executable,
        str(work_dir / "setup.py"),
        "build_ext",
        "--inplace",
    ]


SETUP_TEMPLATE = """\
from setuptools import setup
from Cython.Build import cythonize

setup(
    name="{stem}",
    ext_modules=cythonize(["{stem}.py"], language_level="3"),
)
"""


# --- main pipeline -----------------------------------------------------------


def build_bcc_module(
    source: str,
    module_name: str,
    filename: str,
    outer_key: bytes,
    dist_dir: pathlib.Path,
    *,
    seed: str | None = None,
    no_recovery: bool = False,
    enable_rft: bool = False,
    license_key: dict | None = None,
    license_header: dict | None = None,
    timeout: int = 3600,
) -> BccResult:
    if not _cython_available():
        raise RuntimeError("bcc mode requires Cython: pip install cython")

    dist_dir = pathlib.Path(dist_dir).resolve()
    work = dist_dir / ".bcc_work"
    work.mkdir(parents=True, exist_ok=True)

    # 1. transform
    tree = ast.parse(source, filename=filename)
    tree = tx.apply_transforms(tree, ["strip_docstrings"])
    # guard extraction MUST precede mix-str: encrypting the "__main__"
    # literal would make the comparison unrecognizable
    had_main_guard = extract_main_guard(tree)
    mixer = StringMixer()
    tree = mixer.process(tree)
    if enable_rft:
        salt = hashlib.sha256(f"openprotect-rft:{seed}:{module_name}".encode()).digest()[:8]
        tree = RftRenamer(salt).process(tree)

    warnings = validate_introspection(tree)

    # 2. seal string table + bootstrap prologue
    nonce_material = f"openprotect-nonce:{module_name}:{seed or ''}".encode()
    nonce = hashlib.sha256(nonce_material).digest()[:12]
    str_blob = None
    if mixer.count:
        import json

        plaintext = json.dumps(mixer._table, ensure_ascii=False).encode("utf-8")  # noqa: SLF001
        mac = hmac_digest(outer_key, b"strconv" + nonce)
        iv = mac[:12]
        skey = hkdf_expand(outer_key, b"str" + nonce)
        ct, tag = AesGcm(skey).seal(iv, plaintext)
        str_blob = nonce + iv + ct + tag  # self-describing: runtime derives key from nonce

    runtime_id = make_runtime_id(seed)
    str_literal = repr(str_blob) if str_blob else "None"
    lic_literal = (
        "{" + f"'lic': {license_header['lic']!r}, 'lic_sig': {license_header['lic_sig']!r}" + "}"
        if license_header
        else "None"
    )
    prologue_src = _bootstrap_source(runtime_id, str_literal, lic_literal)
    prologue_tree = ast.parse(prologue_src)
    tree.body = prologue_tree.body + tree.body  # type: ignore[assignment]
    ast.fix_missing_locations(tree)

    # 3. stage and compile
    staged_src = ast.unparse(tree)
    (work / f"{module_name}.py").write_text(staged_src, encoding="utf-8")
    (work / "setup.py").write_text(SETUP_TEMPLATE.format(stem=module_name), encoding="utf-8")

    proc = subprocess.run(
        build_command(module_name, work),
        cwd=str(work),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.splitlines()[-25:] or proc.stdout.splitlines()[-25:])
        raise RuntimeError(f"bcc build failed (exit {proc.returncode}):\n{tail}")

    native = _find_native_module(work, module_name)
    final_native = dist_dir / native.name
    shutil.move(str(native), final_native)

    # staged sources must never ship - they contain the pre-compile logic
    shutil.rmtree(work, ignore_errors=True)

    # 3b. runtime package (outer key + optional license pubkey + bcc helpers)
    from .runtime.generator import generate_runtime_package

    generate_runtime_package(dist_dir, runtime_id, outer_key, license_key)
    _append_bcc_helpers(dist_dir / f"openprotect_runtime_{runtime_id}" / "openprotect_runtime.py", bool(license_header))

    # 4. undo map (exact round-trip), encrypted under the same key model
    undo_blob = None
    if not no_recovery:
        undo_key = hkdf_expand(outer_key, b"undo" + nonce)
        import zlib

        ct, tag = AesGcm(undo_key).seal(nonce, zlib.compress(source.encode("utf-8"), 9))
        undo_blob = nonce + ct + tag

    created = (
        None if seed is not None else __import__("datetime").datetime.now().isoformat(timespec="seconds")
    )
    stamp = "" if created is None else f", {created}"
    header_line = f"# openprotect {__version__} bcc, {runtime_id}{stamp}"
    stub_lines = [
        header_line,
        f"import {module_name} as _op_native",
        f"from {module_name} import *",  # noqa: F403 - native surface
    ]
    if had_main_guard:
        stub_lines.extend(
            [
                "if __name__ == '__main__' and getattr(_op_native, '_OP_HAS_ENTRY', False):",
                "    _op_native._op_main_entry()",
            ]
        )
    if undo_blob is not None:
        stub_lines.append(f"_OP_UNDO = {undo_blob!r}")
    stub_path = dist_dir / f"{module_name}.py"
    stub_path.write_text("\n".join(stub_lines) + "\n", encoding="utf-8")

    return BccResult(stub_path=stub_path, native_module=final_native, warnings=warnings)


# --- deobfuscation support ----------------------------------------------------


def recover_bcc_source(stub_path: pathlib.Path, outer_key: bytes) -> tuple[str, dict]:
    """Recover original source from a BCC stub's _OP_UNDO blob."""
    tree = ast.parse(stub_path.read_text(encoding="utf-8"), filename=str(stub_path))
    undo = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name) and t.id == "_OP_UNDO":
                undo = ast.literal_eval(node.value)
    if undo is None:
        raise RuntimeError("bcc stub has no recovery map (--no-recovery was used)")

    # outer key comes from the sibling runtime package (same model as OPC2)
    import base64  # noqa: F401

    candidates = sorted(stub_path.parent.glob("openprotect_runtime_*"))
    if not candidates:
        raise RuntimeError("no openprotect_runtime_* package found next to the bcc stub")
    ns: dict = {}
    exec((candidates[0] / "openprotect_runtime.py").read_text(encoding="utf-8"), ns)
    outer_key = ns["_OUTER_KEY"]

    import zlib

    from .protection.gcm import AesGcm
    from .protection.keys import hkdf_expand

    nonce = undo[:12]
    undo_key = hkdf_expand(outer_key, b"undo" + nonce)
    plain = zlib.decompress(AesGcm(undo_key).open(nonce, undo[12:-16], undo[-16:]))
    return plain.decode("utf-8"), {"module": stub_path.stem}


# --- small helpers ------------------------------------------------------------


def _cython_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("Cython") is not None


def _compiler_present() -> bool:
    import shutil

    return shutil.which("cl") is not None or shutil.which("gcc") is not None or shutil.which("cc") is not None


def hmac_digest(key: bytes, data: bytes) -> bytes:
    import hmac as _hmac

    return _hmac.new(key, data, hashlib.sha256).digest()


def _find_native_module(out_dir: pathlib.Path, module_name: str) -> pathlib.Path:
    pattern = re.compile(re.escape(module_name) + r"\..+\.(pyd|so)$")
    for candidate in sorted(out_dir.iterdir()):
        if pattern.fullmatch(candidate.name):
            return candidate
    raise RuntimeError(f"no native module produced for {module_name!r} in {out_dir}")
