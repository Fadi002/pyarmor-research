"""Exact round-trip recovery: container back to original source.

Works on openprotect's own documented format. It is deliberately possible:
the undo map travels inside the same encrypted envelope as the code, so
anyone who can RUN the module already holds everything needed to unpack it.
Use ``--no-recovery`` at protect time for distribution builds where even
this convenience should be absent.
"""

from __future__ import annotations

import ast
import base64
import importlib.util
import pathlib
import sys
import zlib

from .protection import container, keys


class DeobfuscateError(Exception):
    pass


def extract_container(stub_path: pathlib.Path) -> bytes:
    """Pull the OPC1 blob out of a protected stub without executing it."""
    tree = ast.parse(stub_path.read_text(encoding="utf-8"), filename=str(stub_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "__pyarmor__" and node.args:
                last = node.args[-1]
                if isinstance(last, ast.Constant) and isinstance(last.value, bytes):
                    return last.value
    raise DeobfuscateError(f"no __pyarmor__ container found in {stub_path}")


def referenced_runtime_package(stub_path: pathlib.Path) -> str | None:
    """Return the runtime package name this stub imports, if determinable."""
    tree = ast.parse(stub_path.read_text(encoding="utf-8"), filename=str(stub_path))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith("openprotect_runtime_")
        ):
            return node.module
    return None


def load_outer_key(stub_path: pathlib.Path) -> tuple[bytes, str]:
    """Locate the runtime package the stub imports and read its outer key.

    Selection follows the stub's own import statement; falling back to a
    directory scan only when the stub is not import-shaped. This matters
    because dist directories can legitimately contain several runtime
    packages from different build seeds.
    """
    pkg_name = referenced_runtime_package(stub_path)
    candidates = []
    if pkg_name:
        candidates.append(stub_path.parent / pkg_name)
    candidates += sorted(
        p for p in stub_path.parent.glob("openprotect_runtime_*") if p.name != pkg_name
    )
    for candidate in candidates:
        loader_file = candidate / "openprotect_runtime.py"
        if not loader_file.exists():
            continue
        spec = importlib.util.spec_from_file_location(candidate.name, loader_file)
        if spec is None or spec.loader is None:  # pragma: no cover
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        key: bytes | None = getattr(module, "_OUTER_KEY", None)
        if key:
            return key, candidate.name
    raise DeobfuscateError(
        f"no openprotect_runtime_* package with a key found next to {stub_path}"
    )


def recover_source(stub_path: pathlib.Path) -> tuple[str, dict]:
    data = extract_container(stub_path)
    header = container.read_header_unverified(data)
    outer_key, _rid = load_outer_key(stub_path)
    nonce = base64.b64decode(header["nonce"])
    inner = keys.derive_inner_keys(outer_key, nonce)

    _hdr, payload, undo_blob = container.unpack(data, inner["enc"], inner["undo"])
    if not header.get("undo") or undo_blob is None:
        raise DeobfuscateError("container has no recovery map (--no-recovery was used)")

    source = zlib.decompress(undo_blob).decode("utf-8")
    return source, header


def deobfuscate(stub_path: pathlib.Path, output: pathlib.Path) -> pathlib.Path:
    source, _header = recover_source(stub_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(source, encoding="utf-8", newline="")
    return output


def default_output_for(stub_path: pathlib.Path) -> pathlib.Path:
    return stub_path.with_name(stub_path.stem + ".restored.py")


def _self_check() -> None:  # pragma: no cover - debug helper
    if len(sys.argv) != 2:
        print("usage: python deobfuscate.py <protected.py>", file=sys.stderr)
        raise SystemExit(2)
    out = deobfuscate(pathlib.Path(sys.argv[1]), default_output_for(pathlib.Path(sys.argv[1])))
    print(f"recovered -> {out}")


if __name__ == "__main__":  # pragma: no cover
    _self_check()
