"""rft: restricted renaming of private top-level functions and classes.

Mirrors the reference tool's RFT concept conservatively. Candidates are
top-level ``def``/``async def``/``class`` names that are:

- not dunder-prefixed (``__main__`` machinery, dunders stay),
- not imported names,
- not shadowed anywhere else in the module (no local variable, parameter,
  nested def, or comprehension target shares the name) - the classic safe
  heuristic that keeps string-free reflection working.

Renamed everywhere as ``ast.Name`` loads/stores plus the definition sites
themselves. Names referenced through strings (getattr/globals()) cannot be
seen by any AST pass; that limitation is inherent and documented.
"""

from __future__ import annotations

import ast
import hashlib
import hmac


def _new_name(original: str, salt: bytes) -> str:
    digest = hashlib.sha256(salt + original.encode()).hexdigest()[:8]
    return f"_op{digest}"


class RftRenamer:
    """Renames private top-level functions/classes across the module."""

    def __init__(self, salt: bytes):
        self.salt = salt
        self.renames: dict[str, str] = {}

    @classmethod
    def salt_for(cls, outer_key: bytes, module_name: str) -> bytes:
        """Single source of truth for rename-salt derivation.

        Used by the build pipeline and by tests that need to predict the
        deterministic rename map.
        """
        return hmac.new(outer_key, b"rft" + module_name.encode(), hashlib.sha256).digest()[:8]

    def process(self, tree: ast.Module) -> ast.Module:
        candidates = {
            n.name
            for n in tree.body
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            and not n.name.startswith("__")
        }
        imported = {
            alias.asname or alias.name.split(".")[0]
            for n in tree.body
            if isinstance(n, ast.ImportFrom | ast.Import)
            for alias in n.names
        }
        candidates -= imported
        shadowed = self._collect_shadowed(tree)
        candidates -= shadowed

        self.renames = {name: _new_name(name, self.salt) for name in sorted(candidates)}
        if not self.renames:
            return tree

        renames_map = self.renames

        class Renamer(ast.NodeTransformer):
            def __init__(self, mapping: dict[str, str]):
                self.mapping = mapping

            def visit_Name(self, node: ast.Name) -> ast.Name:
                if node.id in self.mapping:
                    node.id = self.mapping[node.id]
                return node

            def visit_FunctionDef(self, node: ast.FunctionDef):
                if node.name in self.mapping:
                    node.name = self.mapping[node.name]
                self.generic_visit(node)
                return node

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, node: ast.ClassDef):
                if node.name in self.mapping:
                    node.name = self.mapping[node.name]
                self.generic_visit(node)
                return node

        tree = Renamer(renames_map).visit(tree)
        ast.fix_missing_locations(tree)
        return tree

    def _collect_shadowed(self, tree: ast.Module) -> set[str]:
        """Any name bound inside a nested scope, or at top level by plain
        assignment - those make renaming ambiguous."""
        shadowed: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                args: list[ast.arg] = []
                a = node.args  # type: ignore[attr-defined]
                args.extend(a.posonlyargs + a.args + a.kwonlyargs)
                if a.vararg:
                    args.append(a.vararg)
                if a.kwarg:
                    args.append(a.kwarg)
                shadowed.update(x.arg for x in args)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                shadowed.add(node.id)
            elif isinstance(node, ast.comprehension):
                for t in node.targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            shadowed.add(n.id)
        # top-level plain assignments also count: `helper = something` makes
        # renaming a same-named def unsafe
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            shadowed.add(n.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                shadowed.add(node.target.id)
        return shadowed
