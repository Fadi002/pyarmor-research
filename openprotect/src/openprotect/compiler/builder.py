"""Compile transformed AST into a marshaled code object."""

from __future__ import annotations

import ast
import marshal
import pathlib
import sys


def compile_tree(tree: ast.Module, filename: str) -> "types.CodeType":  # type: ignore[name-defined]
    import types

    code = compile(tree, filename, "exec", dont_inherit=True)
    assert isinstance(code, types.CodeType)
    return code


def marshal_code(code) -> bytes:
    return marshal.dumps(code)


def unmarshal_code(data: bytes):
    return marshal.loads(data)


def python_tag(version: "tuple[int, int, int] | None" = None) -> str:
    v = version or sys.version_info[:3]
    return ".".join(map(str, v))


def check_runtime_compatible(container_pytag: str) -> None:
    here = ".".join(map(str, sys.version_info[:3]))
    if container_pytag.split(".")[:2] != here.split(".")[:2]:
        raise SystemExit(
            f"container was built for Python {container_pytag} but runtime is {here}; "
            "regenerate with the matching interpreter"
        )


def safe_filename(path: pathlib.Path) -> str:
    return str(path).replace("\\", "/")
