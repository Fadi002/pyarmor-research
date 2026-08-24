"""Key material and derivation.

Model mirrors the observed PyArmor shape: one long-lived "outer" key baked
into the generated runtime package, plus per-module "inner" keys derived from
it so each container carries nothing reusable on its own.

With ``--seed`` every derivation is deterministic: same source + same seed +
same tool version produce byte-identical output (reproducible builds).
Without a seed, keys come from os.urandom and timestamps are recorded.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Optional

_KEY_LEN = 32


def generate_outer_key(seed: Optional[str] = None, module_tag: str = "") -> bytes:
    if seed is None:
        import os

        return os.urandom(_KEY_LEN)
    material = f"openprotect-outer:{module_tag}:{seed}".encode()
    return hashlib.sha256(material).digest()


def hkdf_expand(master: bytes, info: bytes, length: int = _KEY_LEN) -> bytes:
    """RFC 5869 expand-only step over HMAC-SHA256."""
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(master, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_inner_keys(outer: bytes, nonce: bytes) -> dict[str, bytes]:
    """Derive per-container keys.

    Deliberately independent of the module's import name: a protected stub
    may execute as ``__main__`` or under any import name, exactly like the
    observed reference behavior. The per-module nonce provides separation.
    Payload and undo regions get distinct keys so a shared IV never
    reuses a GCM (key, nonce) pair.
    """
    return {
        "enc": hkdf_expand(outer, b"enc" + nonce),
        "undo": hkdf_expand(outer, b"undo" + nonce),
    }


def encode_key(key: bytes) -> str:
    return base64.b64encode(key).decode("ascii")


def decode_key(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))
