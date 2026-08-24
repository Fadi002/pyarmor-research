"""Stdlib-only cryptographic primitives.

We deliberately avoid third-party dependencies. Confidentiality uses a
SHA-256 counter-mode keystream; integrity/authentication uses HMAC-SHA256
(encrypt-then-MAC). These are well-understood constructions, adequate for
obfuscation-grade protection, and honestly documented as such: the runtime
must be able to decrypt its own containers, so this is NOT cryptographic
confidentiality against someone holding the generated runtime package.
"""

from __future__ import annotations

import hashlib
import hmac

_BLOCK = 32  # SHA-256 output size


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return _xor(plaintext, _keystream(key, nonce, len(plaintext)))


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return encrypt(key, nonce, ciphertext)  # XOR is self-inverse


def mac(mac_key: bytes, data: bytes) -> bytes:
    return hmac.new(mac_key, data, hashlib.sha256).digest()


def mac_verify(mac_key: bytes, data: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(mac(mac_key, data), tag)
