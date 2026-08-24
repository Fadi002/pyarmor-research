"""Standalone protected-module loader (OPC2 / AES-GCM / licensed).

Copied verbatim into every generated ``openprotect_runtime_*`` package:
standard library only, no ``openprotect`` imports. The build tool injects
prologue lines above the final block::

    _OUTER_KEY = b"..."            # container key root
    _LICENSE_PUBLIC_N = int(...)   # RSA modulus for license signatures
    _LICENSE_PUBLIC_E = 65537

Public contract::

    from openprotect_runtime_000000 import __pyarmor__
    __pyarmor__(__name__, __file__, b"OPENPRT1....")

Fails closed on: tampered containers, bad license signatures, expired
licenses, unsatisfied device bindings.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import marshal
import struct
import sys

_MAGIC = b"OPENPRT1"
_TAG_LEN = 16
_FACTORY_NAME = "__pyarmor_func_factory"

_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8]
_GF_R = 0xE1000000000000000000000000000000


def _aes_expand(key: bytes) -> list[list[int]]:
    nk = len(key) // 4
    words = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
    total = 4 * (nk + 7)
    for i in range(nk, total):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    return [sum(words[4 * r : 4 * r + 4], []) for r in range(len(words) // 4)]


def _aes_encrypt(rks: list[list[int]], block: bytes) -> bytes:
    def xtime(a):
        a <<= 1
        return (a ^ 0x1B) & 0xFF if a & 0x100 else a

    state = list(block)
    rounds = len(rks) - 1
    for i in range(16):
        state[i] ^= rks[0][i]
    for rnd in range(1, rounds):
        for i in range(16):
            state[i] = _SBOX[state[i]]
        for r in range(1, 4):
            row = [state[r + 4 * c] for c in range(4)]
            for c in range(4):
                state[r + 4 * c] = row[(c + r) % 4]
        for c in range(4):
            col = state[4 * c : 4 * c + 4]
            state[4 * c + 0] = xtime(col[0]) ^ (xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3]
            state[4 * c + 1] = col[0] ^ xtime(col[1]) ^ (xtime(col[2]) ^ col[2]) ^ col[3]
            state[4 * c + 2] = col[0] ^ col[1] ^ xtime(col[2]) ^ (xtime(col[3]) ^ col[3])
            state[4 * c + 3] = (xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime(col[3])
        for i in range(16):
            state[i] ^= rks[rnd][i]
    for i in range(16):
        state[i] = _SBOX[state[i]]
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        for c in range(4):
            state[r + 4 * c] = row[(c + r) % 4]
    for i in range(16):
        state[i] ^= rks[rounds][i]
    return bytes(state)


def _gf_mult(x: int, y: int) -> int:
    z = 0
    v = x
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _GF_R if v & 1 else v >> 1
    return z


def _gcm_open(aes_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """AES-GCM authenticated decryption (96-bit IV); raises on tamper."""
    rks = _aes_expand(aes_key)

    def block(b: bytes) -> bytes:
        return _aes_encrypt(rks, b)

    j0 = iv + b"\x00\x00\x00\x01"

    def keystream(n: int) -> bytes:
        out = bytearray()
        ctr = j0
        while len(out) < n:
            ctr = ctr[:12] + ((int.from_bytes(ctr[12:], "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")
            out += block(ctr)
        return bytes(out[:n])

    h = int.from_bytes(block(b"\x00" * 16), "big")
    data = ciphertext + b"\x00" * ((16 - len(ciphertext) % 16) % 16)
    data += b"\x00" * 8 + (len(ciphertext) * 8).to_bytes(8, "big")
    y = 0
    for off in range(0, len(data), 16):
        y = _gf_mult(y ^ int.from_bytes(data[off : off + 16], "big"), h)
    ek_j0 = block(j0)
    computed = bytes(a ^ b for a, b in zip(y.to_bytes(16, "big"), ek_j0))
    if not hmac.compare_digest(computed, tag):
        raise ValueError("container integrity check failed")
    return bytes(a ^ b for a, b in zip(ciphertext, keystream(len(ciphertext))))


def _expand(master: bytes, info: bytes, length: int = 32) -> bytes:
    import hashlib

    out = b""
    blk = b""
    counter = 1
    while len(out) < length:
        blk = hmac.new(master, blk + info + bytes([counter]), hashlib.sha256).digest()
        out += blk
        counter += 1
    return out[:length]


# --- license verification (RSA-PSS/SHA-256, RFC 8017 subset) --------------

_HLEN = 32
_SLEN = 32


def _mgf1(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _rsa_pss_verify(n: int, e: int, message: bytes, signature: bytes) -> bool:
    em_len = (n.bit_length() + 7) // 8
    if len(signature) != em_len:
        return False
    m = pow(int.from_bytes(signature, "big"), e, n)
    em = m.to_bytes(em_len, "big")
    if em[-1] != 0xBC:
        return False
    h = em[em_len - _HLEN - 1 : em_len - 1]
    masked = em[: em_len - _HLEN - 1]
    db = bytes(a ^ b for a, b in zip(masked, _mgf1(h, em_len - _HLEN - 1)))
    db = bytes([db[0] & 0x7F]) + db[1:]
    ps_len = em_len - _HLEN - _SLEN - 2
    if db[:ps_len] != b"\x00" * ps_len or db[ps_len] != 0x01:
        return False
    salt = db[-_SLEN:]
    import hashlib

    m_prime = b"\x00" * 8 + hashlib.sha256(message).digest() + salt
    return hmac.compare_digest(hashlib.sha256(m_prime).digest(), h)


def _current_fingerprints() -> list[str]:
    import os
    import uuid

    fps = []
    mac = f"{uuid.getnode():012x}"
    if mac != "000000000000":
        fps.append(f"mac:{mac}")
    env = os.environ.get("OPENPROTECT_DEVICE")
    if env:
        fps.append(f"str:{env}")
    return fps


def _license_check(public_n: int, public_e: int, desc_b64: str, sig_b64: str) -> dict:
    import datetime as _dt

    descriptor = base64.b64decode(desc_b64)
    signature = base64.b64decode(sig_b64)
    if not _rsa_pss_verify(public_n, public_e, descriptor, signature):
        raise RuntimeError("license signature verification failed")
    desc: dict = json.loads(descriptor.decode("utf-8"))

    if "exp" in desc and _dt.datetime.now(_dt.timezone.utc).date() > _dt.date.fromisoformat(desc["exp"]):
        raise RuntimeError(f"license expired on {desc['exp']}")

    required: list[str] = desc.get("dev", [])
    if required:
        available = set(_current_fingerprints())
        missing = [d for d in required if d not in available]
        if missing:
            raise RuntimeError(f"device binding not satisfied: {missing}")
    return desc


def make_func_factory(
    outer_key: bytes,
    module_nonce: bytes,
    module_globals: dict,
    wrap: bool = True,
    license_ctx: "dict | None" = None,
):
    """Builds the per-module function-decrypting factory.

    Sealed bodies (AES-GCM, per-function keys from outer key + module nonce
    + index) rebuild on first call and are cached.

    wrap=True (reference default): calls keep flowing through this factory
    hop - the hook point for periodic license revalidation - and rebuilds
    run in a snapshot of module globals, leaving the public name bound to
    the wrapper.
    wrap=False (--no-wrap): first rebuild executes directly in the live
    module globals and replaces the public name with the real function.
    """

    cache: dict[int, object] = {}
    _last_check = [0.0]

    def _revalidate():
        lic = license_ctx or None
        if not lic:
            return
        import time

        now = time.time()
        period_days = lic.get("period") or 0
        if period_days and now - _last_check[0] < period_days * 86400:
            return
        _license_check(lic["n"], lic["e"], lic["desc"], lic["sig"])
        _last_check[0] = now

    def __pyarmor_func_factory(index: int, sealed: bytes, _op_args: tuple = (), _op_kwargs: dict = {}):
        _revalidate()
        fn = cache.get(index)
        if fn is None:
            iv, ct, tag = sealed[:12], sealed[12:-_TAG_LEN], sealed[-_TAG_LEN:]
            idx_bytes = index.to_bytes(4, "big")
            fkey = _expand(outer_key, b"func" + module_nonce + idx_bytes)
            plaintext = _gcm_open(fkey, iv, ct, tag)
            (name_len,) = struct.unpack(">H", plaintext[:2])
            fname = plaintext[2 : 2 + name_len].decode("utf-8")
            code = marshal.loads(plaintext[2 + name_len :])
            if wrap:
                sandbox = dict(module_globals)
                exec(code, sandbox)
                fn = sandbox[fname]
            else:
                exec(code, module_globals)
                fn = module_globals[fname]
            cache[index] = fn
        return fn(*_op_args, **_op_kwargs)

    return __pyarmor_func_factory


def make_str_lookup(outer_key: bytes, module_nonce: bytes):
    """Per-module encrypted string-table lookup (mix-str)."""
    import json

    cache: dict[str, list[str]] = {}

    def __pyarmor_str__(index: int, blob: bytes) -> str:
        if "table" not in cache:
            iv, ct, tag = blob[:12], blob[12:-_TAG_LEN], blob[-_TAG_LEN:]
            skey = _expand(outer_key, b"str" + module_nonce)
            cache["table"] = json.loads(_gcm_open(skey, iv, ct, tag))
        return cache["table"][index]

    return __pyarmor_str__


def bcc_init(str_blob: "bytes | None", lic_header: "dict | None"):
    """Bootstrap for BCC-compiled modules (directly callable from prologue).

    Returns (string_lookup | None, license_info | None, periodic_hook).
    String blobs are self-describing: nonce[12] || iv[12] || ct || tag[16].
    """
    import json
    import time

    state: dict[str, object] = {}
    last_check = [0.0]

    license_info = None
    if lic_header:
        license_info = _license_check(
            _LICENSE_PUBLIC_N,  # type: ignore[name-defined]
            _LICENSE_PUBLIC_E,  # type: ignore[name-defined]
            lic_header["lic"],
            lic_header["lic_sig"],
        )
        state["lic"] = license_info
        last_check[0] = time.time()

    def _periodic():
        period_days = (license_info or {}).get("period", 0) if license_info else 0
        if not period_days:
            return
        now = time.time()
        if now - last_check[0] >= period_days * 86400:
            _license_check(
                _LICENSE_PUBLIC_N,  # type: ignore[name-defined]
                _LICENSE_PUBLIC_E,  # type: ignore[name-defined]
                lic_header["lic"],
                lic_header["lic_sig"],
            )
            last_check[0] = now

    lookup = None
    if str_blob:
        nonce = str_blob[:12]
        iv, ct, tag = str_blob[12:24], str_blob[24:-_TAG_LEN], str_blob[-_TAG_LEN:]
        skey = _expand(_OUTER_KEY, b"str" + nonce)  # type: ignore[name-defined]
        state["table"] = json.loads(_gcm_open(skey, iv, ct, tag))

        def __pyarmor_str__(index: int, _blob: bytes = b"") -> str:
            # second arg tolerated: the shared mix-str pass emits
            # __pyarmor_str__(idx, _OP_STRS); in bcc builds the table is
            # already initialized from the bootstrap blob.
            return state["table"][index]  # type: ignore[index]

        lookup = __pyarmor_str__

    return lookup, license_info, _periodic


def make_loader(outer_key: bytes, license_public: "tuple[int, int] | None" = None):
    def __pyarmor__(name: str, file: str, blob: bytes) -> None:
        if not blob.startswith(_MAGIC):
            raise RuntimeError(f"{name}: bad container magic")
        fmt_version, header_len = struct.unpack(">HH", blob[8:12])
        header: dict = json.loads(blob[12 : 12 + header_len].decode("utf-8"))

        here = ".".join(map(str, sys.version_info[:3]))
        built = header.get("pytag", here)
        if built.split(".")[:2] != here.split(".")[:2]:
            raise RuntimeError(
                f"{name}: container built for Python {built}, running on {here}"
            )

        license_info: dict | None = None
        license_ctx: dict | None = None
        if header.get("lic"):
            if not license_public:
                raise RuntimeError(f"{name}: container is licensed but runtime has no public key")
            license_info = _license_check(
                license_public[0], license_public[1], header["lic"], header["lic_sig"]
            )
            if header.get("sealed_funcs"):
                # import-time check already ran above; the factory re-checks
                # on wrapper calls when a period is configured
                license_ctx = {
                    "n": license_public[0],
                    "e": license_public[1],
                    "desc": header["lic"],
                    "sig": header["lic_sig"],
                    "period": (license_info or {}).get("period", 0),
                }

        nonce = base64.b64decode(header["nonce"])
        enc_key = _expand(outer_key, b"enc" + nonce)

        start = 12 + header_len
        plen = header["payload_len"]
        ct, tag = blob[start : start + plen], blob[start + plen : start + plen + _TAG_LEN]
        code = marshal.loads(_gcm_open(enc_key, nonce, ct, tag))

        target_globals = sys._getframe(1).f_globals  # noqa: SLF001 - loader by design
        if header.get("sealed_funcs"):
            target_globals[_FACTORY_NAME] = make_func_factory(
                outer_key,
                nonce,
                target_globals,
                wrap=header.get("wrap", True),
                license_ctx=license_ctx,
            )
        if header.get("mixed_strs"):
            target_globals["__pyarmor_str__"] = make_str_lookup(outer_key, nonce)
        exec(code, target_globals)
        if license_info is not None:
            target_globals["__pyarmor_license__"] = license_info

    return __pyarmor__


try:
    _OUTER_KEY  # noqa: F821 - injected by openprotect gen
except NameError:
    _OUTER_KEY = None

try:
    _LICENSE_PUBLIC_N  # type: ignore[name-defined] # noqa: F821
except NameError:
    _LICENSE_PUBLIC_N = None

try:
    _LICENSE_PUBLIC_E  # type: ignore[name-defined] # noqa: F821
except NameError:
    _LICENSE_PUBLIC_E = None

if _OUTER_KEY is not None:
    _LP = (_LICENSE_PUBLIC_N, _LICENSE_PUBLIC_E) if _LICENSE_PUBLIC_N else None
    __pyarmor__ = make_loader(_OUTER_KEY, _LP)
