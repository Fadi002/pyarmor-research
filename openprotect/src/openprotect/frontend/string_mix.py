"""String constant encryption (mix-str).

Replaces every string literal in the module with a lookup call into a
per-module encrypted string table. The table travels as one AES-GCM sealed
blob inside the container payload and materializes on first lookup.

Known trade-offs (documented in docs/security.md): stringified annotations
and dynamic-evaluation consumers of source text are affected like any
constant-hiding transform; runtime values remain observable at use sites -
same as the reference implementation.
"""

from __future__ import annotations

import ast
import hashlib
import hmac

from ..protection.gcm import AesGcm
from ..protection.keys import hkdf_expand

_LOOKUP_NAME = "__pyarmor_str__"
_BLOB_NAME = "_OP_STRS"


class StringMixer:
    """Collects string constants and rewrites them into table lookups."""

    def __init__(self):
        self._table: list[str] = []
        self._index: dict[str, int] = {}

    @property
    def count(self) -> int:
        return len(self._table)

    def process(self, tree: ast.Module) -> ast.Module:
        mixer = self

        class Replacer(ast.NodeTransformer):
            def visit_Constant(self, node: ast.Constant):
                if isinstance(node.value, str):
                    idx = mixer._intern(node.value)
                    call = ast.Call(
                        func=ast.Name(id=_LOOKUP_NAME, ctx=ast.Load()),
                        args=[
                            ast.Constant(value=idx),
                            ast.Name(id=_BLOB_NAME, ctx=ast.Load()),
                        ],
                        keywords=[],
                    )
                    return ast.copy_location(call, node)
                return node

        tree = Replacer().visit(tree)
        ast.fix_missing_locations(tree)
        return tree

    def _intern(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self._table)
            self._table.append(value)
        return self._index[value]

    def finalize(self, outer_key: bytes, module_nonce: bytes) -> ast.stmt | None:
        """Seal the string table; returns the module-level blob assignment."""
        if not self._table:
            return None
        import json

        plaintext = json.dumps(self._table, ensure_ascii=False).encode("utf-8")
        mac = hmac.new(outer_key, b"strconv" + module_nonce, hashlib.sha256)
        iv = mac.digest()[:12]
        key = hkdf_expand(outer_key, b"str" + module_nonce)
        ct, tag = AesGcm(key).seal(iv, plaintext)
        blob = iv + ct + tag

        assign = ast.Assign(
            targets=[ast.Name(id=_BLOB_NAME, ctx=ast.Store())],
            value=ast.Constant(value=blob),
        )
        ast.fix_missing_locations(assign)
        return assign


def build_lookup(outer_key: bytes, module_nonce: bytes, blob: bytes):
    """Runtime-side lookup factory (mirrored by the standalone loader)."""
    import json

    iv, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    key = hkdf_expand(outer_key, b"str" + module_nonce)
    table = json.loads(_open(key, iv, ct, tag))

    def __pyarmor_str__(index: int, _blob: bytes = "") -> str:
        return table[index]

    return __pyarmor_str__


def _open(key: bytes, iv: bytes, ct: bytes, tag: bytes) -> bytes:
    from ..protection.gcm import AesGcm

    return AesGcm(key).open(iv, ct, tag)
