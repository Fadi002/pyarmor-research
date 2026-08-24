"""Pure-Python RSA-2048 with PSS/SHA-256 signatures (RFC 8017).

Used exclusively for license descriptors: the generated runtime package
embeds the public half; descriptors are signed at protect time and verified
at load time. Optional gmpy2 acceleration if present; otherwise plain int
arithmetic (fast enough - signing happens once per build, verifying once
per import).

Key generation can be seeded for reproducible builds: primes are drawn
from an HMAC-SHA256 DRBG stream instead of os.urandom.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import os

E = 65537
KEY_BITS = 2048
HLEN = 32  # SHA-256
SLEN = 32  # salt length


class Drbg:
    """HMAC-SHA256 DRBG for deterministic prime generation."""

    def __init__(self, seed_material: bytes):
        self._key = hmac.new(seed_material, b"openprotect-drbg", hashlib.sha256).digest()
        self._v = b"\x01" * 32

    def _update(self, provided: bytes) -> None:
        self._key = hmac.new(self._key, self._v + b"\x00" + provided, hashlib.sha256).digest()
        self._v = hmac.new(self._key, self._v, hashlib.sha256).digest()
        if provided:
            self._key = hmac.new(self._key, self._v + b"\x01" + provided, hashlib.sha256).digest()
            self._v = hmac.new(self._key, self._v, hashlib.sha256).digest()

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            self._v = hmac.new(self._key, self._v, hashlib.sha256).digest()
            out += self._v
        self._update(b"")
        return bytes(out[:n])


def _mgf1(seed: bytes, length: int) -> bytes:
    out = bytearray()
    for counter in itertools.count():
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        if len(out) >= length:
            break
    return bytes(out[:length])


def _pss_encode(message_hash: bytes, em_len: int, salt: bytes) -> bytes:
    m_prime = b"\x00" * 8 + message_hash + salt
    h = hashlib.sha256(m_prime).digest()
    ps_len = em_len - HLEN - len(salt) - 2
    db = b"\x00" * ps_len + b"\x01" + salt
    db_mask = _mgf1(h, em_len - HLEN - 1)
    masked = bytes(a ^ b for a, b in zip(db, db_mask))
    masked = bytes([masked[0] & 0x7F]) + masked[1:]  # emBits = 8*emLen - 1
    return masked + h + b"\xBC"


def _pss_verify(em: bytes, em_len: int, message_hash: bytes, salt_len: int) -> bool:
    if em[-1] != 0xBC or len(em) != em_len:
        return False
    h = em[em_len - HLEN - 1 : em_len - 1]
    masked = em[: em_len - HLEN - 1]
    db_mask = _mgf1(h, em_len - HLEN - 1)
    db = bytes(a ^ b for a, b in zip(masked, db_mask))
    db = bytes([db[0] & 0x7F]) + db[1:]
    ps_len = em_len - HLEN - salt_len - 2
    if db[:ps_len] != b"\x00" * ps_len or db[ps_len] != 0x01:
        return False
    salt_recovered = db[-salt_len:]
    m_prime = b"\x00" * 8 + message_hash + salt_recovered
    return hmac.compare_digest(hashlib.sha256(m_prime).digest(), h)


_SMALL_PRIMES = [
    p
    for p in range(3, 1000)
    if all(p % d for d in range(2, int(p**0.5) + 1))
]


def _is_probable_prime(n: int, rounds: int, rng) -> bool:
    if n < 2 or n % 2 == 0:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = 2 + (int.from_bytes(rng(64), "big") % (n - 3))
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int, rng) -> int:
    assert bits % 8 == 0
    while True:
        cand = bytearray(rng(bits // 8))
        cand[0] |= 0xC0  # top two bits set -> product has full width
        cand[-1] |= 0x01  # odd
        n = int.from_bytes(bytes(cand), "big")
        if _is_probable_prime(n, 16, rng):
            return n


def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def generate_keypair(rng=None) -> dict:
    """Returns {'n','e','d','p','q'}; e is fixed at 65537."""
    if rng is None:
        rng = os.urandom
    while True:
        p = _gen_prime(KEY_BITS // 2, rng)
        q = _gen_prime(KEY_BITS // 2, rng)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        try:
            d = pow(E, -1, phi)
        except ValueError:
            continue
        return {"n": n, "e": E, "d": d, "p": p, "q": q}


def sign(key: dict, message: bytes, salt: bytes | None = None) -> bytes:
    em_len = (KEY_BITS + 7) // 8
    if salt is None:
        salt = os.urandom(SLEN)
    em = _pss_encode(hashlib.sha256(message).digest(), em_len, salt)
    m = int.from_bytes(em, "big")
    return pow(m, key["d"], key["n"]).to_bytes(em_len, "big")


def verify(public: tuple[int, int], message: bytes, signature: bytes) -> bool:
    """public = (n, e)."""
    n, e = public
    em_len = (n.bit_length() + 7) // 8
    if len(signature) != em_len:
        return False
    m = pow(int.from_bytes(signature, "big"), e, n)
    em = m.to_bytes(em_len, "big")
    return _pss_verify(em, em_len, hashlib.sha256(message).digest(), SLEN)


# --- deterministic convenience -------------------------------------------


def generate_deterministic_keypair(seed_material: bytes) -> dict:
    drbg = Drbg(seed_material)
    while True:
        p = _gen_prime(KEY_BITS // 2, drbg.bytes)
        q = _gen_prime(KEY_BITS // 2, drbg.bytes)
        if p != q:
            break
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(E, -1, phi)
    return {"n": n, "e": E, "d": d, "p": p, "q": q}
