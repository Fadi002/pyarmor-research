"""AST transformation registry.

Transforms run in registration order before compilation. Each transform is a
pure AST->AST function so the pipeline stays deterministic and testable.
Phase 1 ships conservative transforms; later phases add identifier/string/
control-flow layers on this same registry.
"""

from __future__ import annotations

import ast
from typing import Callable

Transform = Callable[[ast.Module], ast.Module]

_REGISTRY: list[tuple[str, Transform]] = []


def register(name: str):
    def wrap(fn: Transform) -> Transform:
        _REGISTRY.append((name, fn))
        return fn

    return wrap


def apply_transforms(tree: ast.Module, names: list[str] | None = None) -> ast.Module:
    selected = _REGISTRY if names is None else [t for t in _REGISTRY if t[0] in set(names)]
    for _, transform in sorted(selected, key=lambda item: item[0]):
        tree = transform(tree)
    return ast.fix_missing_locations(tree)


@register("strip_docstrings")
def strip_docstrings(tree: ast.Module) -> ast.Module:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                if isinstance(body[0].value.value, str):
                    if len(body) == 1:
                        body[0] = ast.Pass()
                    else:
                        del body[0]
    return tree


@register("strip_asserts")
def strip_asserts(tree: ast.Module) -> ast.Module:
    keep = [
        stmt
        for stmt in tree.body
        if not (isinstance(stmt, ast.Assert))
    ]
    tree.body = keep  # type: ignore[assignment]
    return tree
