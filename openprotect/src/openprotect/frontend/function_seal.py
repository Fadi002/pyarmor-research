"""Per-function sealing: encrypt function bodies as individual containers.

Concept mirrors the reference implementation's per-function encrypted spans:
at rest, each function contributes only opaque ciphertext to the module;
plaintext bytecode materializes on the function's first call and is cached.

Each sealed blob holds a marshaled "mini-module" containing exactly one
decorator-free ``def``/``async def``. Rebuilding executes that mini-module
and takes the single function it defines - defaults, annotations, docstrings,
generators and coroutines behave correctly without hand-rolled
FunctionType surgery.

Documented deviations: decorators stay outside the seal (they decorate the
forwarding wrapper); default-expression evaluation shifts from import time
to first-call time; decrypted functions are cached rather than theatrically
re-encrypted - see docs/security.md for why that is honesty, not laziness.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import hmac
import struct

from ..compiler import builder
from ..protection.gcm import AesGcm
from ..protection.keys import hkdf_expand

_FACTORY_NAME = "__pyarmor_func_factory"


class FunctionSealer:
    """Rewrites top-level defs into forwarding wrappers + sealed blobs."""

    def __init__(self, filename: str):
        self.filename = filename
        self._plaintexts: list[bytes] = []
        self._constant_nodes: list[ast.Constant] = []
        self._sealed_values: list[bytes | None] = []

    # -- phase 1: rewrite tree -------------------------------------------

    def process(self, tree: ast.Module) -> ast.Module:
        new_body: list[ast.stmt] = []
        idx = 0
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                new_body.extend(self._replace(node, idx))
                idx += 1
            else:
                new_body.append(node)
        tree.body = new_body  # type: ignore[assignment]
        return tree

    def _replace(self, node, idx: int) -> list[ast.stmt]:
        self._plaintexts.append(self._marshal_bare_def(node))
        self._sealed_values.append(None)

        seal_name = f"_OP_SEAL_{idx}"
        const = ast.Constant(value=None)
        self._constant_nodes.append(const)
        store_seal = ast.Assign(
            targets=[ast.Name(id=seal_name, ctx=ast.Store())],
            value=const,
        )

        forward = ast.Call(
            func=ast.Name(id=_FACTORY_NAME, ctx=ast.Load()),
            args=[
                ast.Constant(value=idx),
                ast.Name(id=seal_name, ctx=ast.Load()),
            ],
            keywords=[
                # transport the received arguments as reserved keywords;
                # spreading (*args, **kwargs) here would merge the caller's
                # mapping contents into the factory's own parameters
                ast.keyword(arg="_op_args", value=ast.Name(id="args", ctx=ast.Load())),
                ast.keyword(arg="_op_kwargs", value=ast.Name(id="kwargs", ctx=ast.Load())),
            ],
        )
        body_stmt: ast.stmt
        if isinstance(node, ast.AsyncFunctionDef):
            body_stmt = ast.Return(value=ast.Await(value=forward))
        else:
            body_stmt = ast.Return(value=forward)

        wrapper = copy.deepcopy(node)
        wrapper.decorator_list = list(node.decorator_list)
        wrapper.args = ast.arguments(
            posonlyargs=[],
            args=[],
            vararg=ast.arg(arg="args", annotation=None),
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=ast.arg(arg="kwargs", annotation=None),
            defaults=[],
        )
        wrapper.body = [body_stmt]
        wrapper.returns = None

        ast.fix_missing_locations(store_seal)
        ast.fix_missing_locations(wrapper)
        return [store_seal, wrapper]

    def _marshal_bare_def(self, node) -> bytes:
        bare = copy.deepcopy(node)
        bare.decorator_list = []
        mini = ast.Module(body=[bare], type_ignores=[])

        ast.fix_missing_locations(mini)
        payload = builder.marshal_code(builder.compile_tree(mini, self.filename))
        # [u16 namelen][name][marshal] so the runtime knows what the
        # mini-module defined without guessing
        name_bytes = node.name.encode("utf-8")
        return struct.pack(">H", len(name_bytes)) + name_bytes + payload

    # -- phase 2: seal ----------------------------------------------------

    def seal_all(self, outer_key: bytes, module_nonce: bytes) -> None:
        """Seal every captured body; fills the placeholder constants."""
        for idx, plaintext in enumerate(self._plaintexts):
            idx_bytes = struct.pack(">I", idx)
            mac = hmac.new(outer_key, b"funciv" + module_nonce + idx_bytes, hashlib.sha256)
            iv = mac.digest()[:12]
            key = hkdf_expand(outer_key, b"func" + module_nonce + idx_bytes)
            ct, tag = AesGcm(key).seal(iv, plaintext)
            self._sealed_values[idx] = iv + ct + tag
            self._constant_nodes[idx].value = self._sealed_values[idx]

    @property
    def sealed_count(self) -> int:
        return len(self._plaintexts)
