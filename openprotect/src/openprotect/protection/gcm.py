"""GCM (Galois/Counter Mode) over the pure-Python AES cipher.

Implements SP 800-38D for 96-bit IVs, which is the only IV size this
project generates. Authenticated encryption: tampering fails verification
instead of decrypting to garbage - the property the reference runtime was
observed to skip checking.
"""

from __future__ import annotations

import hmac
import struct

from .aes import Aes

_R = 0xE1000000000000000000000000000000


def _gf_mult(x: int, y: int) -> int:
    """Multiplication in GF(2^128) using the GCM bit convention."""
    z = 0
    v = x
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _ghash(h: int, aad: bytes, ciphertext: bytes) -> bytes:
    data = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    data += ciphertext + b"\x00" * ((16 - len(ciphertext) % 16) % 16)
    data += struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)

    y = 0
    for off in range(0, len(data), 16):
        block = int.from_bytes(data[off : off + 16], "big")
        y = _gf_mult(y ^ block, h)
    return y.to_bytes(16, "big")


def _inc32(block: bytes) -> bytes:
    prefix, ctr = block[:12], struct.unpack(">I", block[12:])[0]
    return prefix + struct.pack(">I", (ctr + 1) & 0xFFFFFFFF)


class AesGcm:
    """AES-GCM authenticated encryption for 96-bit IVs."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 32):
            raise ValueError("key must be AES-128 or AES-256")
        self._aes = Aes(key)

    def _j0(self, iv: bytes) -> bytes:
        if len(iv) != 12:
            raise ValueError("this implementation requires a 96-bit IV")
        return iv + b"\x00\x00\x00\x01"

    def _keystream(self, j0: bytes, length: int) -> bytes:
        out = bytearray()
        counter = _inc32(j0)
        while len(out) < length:
            out += self._aes.encrypt_block(counter)
            counter = _inc32(counter)
        return bytes(out[:length])

    def seal(self, iv: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        j0 = self._j0(iv)
        stream = self._keystream(j0, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))

        h = int.from_bytes(self._aes.encrypt_block(b"\x00" * 16), "big")
        s = _ghash(h, aad, ciphertext)
        ek_j0 = self._aes.encrypt_block(j0)
        tag = bytes(a ^ b for a, b in zip(s, ek_j0))
        return ciphertext, tag

    def open(self, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        j0 = self._j0(iv)
        h = int.from_bytes(self._aes.encrypt_block(b"\x00" * 16), "big")
        s = _ghash(h, aad, ciphertext)
        ek_j0 = self._aes.encrypt_block(j0)
        computed = bytes(a ^ b for a, b in zip(s, ek_j0))
        if not hmac.compare_digest(computed, tag):
            raise ValueError("GCM authentication failed")
        stream = self._keystream(j0, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, stream))
