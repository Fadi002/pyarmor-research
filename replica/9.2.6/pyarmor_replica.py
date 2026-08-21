"""
pyarmor-replica: standalone pure-Python PyArmor 9.2.6 obfuscator + runtime key.

Produces pyarmor-compatible dists that the real pyarmor_runtime_000000 executes.
Zero native pyarmor code â€” only CPython + cryptography lib.

Usage:
    python pyarmor_replica.py sample.py -o dist_dir          # obfuscate with existing runtime key
    python pyarmor_replica.py sample.py -o dist_dir --fresh   # fresh RSA key per dist
    python pyarmor_replica.py --gen-key -o mykey.bin          # generate standalone runtime key

Requires: cryptography, pyarmor (for Component/resoptions types only)
"""
import argparse
import ast
import hashlib
import os
import random
import shutil
import struct
import sys
import time
import types
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Resolve paths relative to this script (NOT the cwd)
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
PLAINTEXT = "core_data_1_plaintext.py"


def _find_template():
    """Locate the runtime pyd template: prefer local replica_gt2, fall back to
    the installed pyarmor package."""
    local = _HERE / "replica_gt2" / "dist" / "pyarmor_runtime_000000" / "pyarmor_runtime.pyd"
    if local.exists():
        return local
    try:
        import pyarmor
        return Path(pyarmor.__file__).parent / "cli" / "core" / "pyarmor_runtime.pyd"
    except ImportError:
        raise FileNotFoundError("No runtime pyd template found. Install pyarmor or place template in replica_gt2/dist/")


RUNTIME_TEMPLATE = _find_template()


# ---------------------------------------------------------------------------
# KDF: MD5(salt + pubkey_der + desc_hash + deob270) â€” re-implemented from
# the validated maker-side F-0013 and runtime-side F-0027 findings.
# ---------------------------------------------------------------------------
_SALT_ANCHOR = b"pyarmor-vax-"
_SALT_LEN = 20
_HEADER_BEFORE_SALT = 0x0C
_RAW270_DELTA = 16660
_RAW270_LEN = 270
_PAD_SEARCH_WINDOW = 16384
_PAD_LEN = 16


def _derive_from_data(data, salt_off):
    """Internal: derive AES key from pre-found salt offset."""
    salt = data[salt_off:salt_off + _SALT_LEN]
    header_off = salt_off - _HEADER_BEFORE_SALT
    header = data[header_off:header_off + 0x40]
    off_pubkey, len_pubkey, off_license_desc = struct.unpack_from("<III", header, 0x30)
    fields_base = header_off + 0x40

    pubkey_der = data[fields_base + off_pubkey: fields_base + off_pubkey + len_pubkey]
    desc_hdr = data[fields_base + off_license_desc: fields_base + off_license_desc + 8]
    desc_hash_len = struct.unpack_from("<I", desc_hdr, 4)[0]
    desc_hash = data[fields_base + off_license_desc + 32:
                     fields_base + off_license_desc + 32 + desc_hash_len]

    raw270_off = salt_off + _RAW270_DELTA
    raw270 = data[raw270_off:raw270_off + _RAW270_LEN]

    pad = None
    window = data[raw270_off:raw270_off + _PAD_SEARCH_WINDOW]
    for i in range(len(window) - _PAD_LEN):
        b0 = window[i]
        if b0 != 0 and all(window[i + j] == b0 for j in range(_PAD_LEN)):
            pad = window[i:i + _PAD_LEN]
            break
    if pad is None:
        raise ValueError("XOR pad not found")

    deob270 = bytes(b ^ pad[i % _PAD_LEN] for i, b in enumerate(raw270))
    return hashlib.md5(salt + pubkey_der + desc_hash + deob270).digest()


def derive_aes_key(runtime_pyd_path):
    """Derive the 16-byte AES key from a pyarmor_runtime.pyd (trial or self-built).
    If no salt anchor found (pristine template), auto-patch a runtime key into a temp copy.
    Returns (aes_key, actual_pyd_path) where actual_pyd_path is the patched file."""
    data = Path(runtime_pyd_path).read_bytes()
    salt_off = data.find(_SALT_ANCHOR)
    if salt_off == -1:
        # pristine template â€” patch a runtime key into a temp copy
        rk = generate_runtime_key()
        patched = bytearray(data)
        magic = struct.pack("<III", 0x6F2D728B, 1385940610, 0x4000) + b"pyarmor-vax"
        mi = patched.find(magic)
        if mi == -1:
            raise ValueError(f"data marker not found in {runtime_pyd_path}")
        patched[mi:mi+len(rk)] = rk
        tmp = Path(str(runtime_pyd_path) + ".patched")
        tmp.write_bytes(patched)
        data2 = tmp.read_bytes()
        key = _derive_from_data(data2, data2.find(_SALT_ANCHOR))
        return key, str(tmp)
    return _derive_from_data(data, salt_off), str(runtime_pyd_path)
    salt = data[salt_off:salt_off + _SALT_LEN]

    header_off = salt_off - _HEADER_BEFORE_SALT
    header = data[header_off:header_off + 0x40]
    off_pubkey, len_pubkey, off_license_desc = struct.unpack_from("<III", header, 0x30)
    fields_base = header_off + 0x40

    pubkey_der = data[fields_base + off_pubkey: fields_base + off_pubkey + len_pubkey]
    desc_hdr = data[fields_base + off_license_desc: fields_base + off_license_desc + 8]
    desc_hash_len = struct.unpack_from("<I", desc_hdr, 4)[0]
    desc_hash = data[fields_base + off_license_desc + 32:
                     fields_base + off_license_desc + 32 + desc_hash_len]

    raw270_off = salt_off + _RAW270_DELTA
    raw270 = data[raw270_off:raw270_off + _RAW270_LEN]

    # find 16-byte XOR pad (non-zero repeated byte) within search window
    pad = None
    window = data[raw270_off:raw270_off + _PAD_SEARCH_WINDOW]
    for i in range(len(window) - _PAD_LEN):
        b0 = window[i]
        if b0 != 0 and all(window[i + j] == b0 for j in range(_PAD_LEN)):
            pad = window[i:i + _PAD_LEN]
            break
    if pad is None:
        raise ValueError("XOR pad not found")

    deob270 = bytes(b ^ pad[i % _PAD_LEN] for i, b in enumerate(raw270))
    return hashlib.md5(salt + pubkey_der + desc_hash + deob270).digest()


# ---------------------------------------------------------------------------
# Runtime key generation (raw-PSS, LTC layout)
# ---------------------------------------------------------------------------
RUNTIME_MAGIC = 0x36F2D728B


def _fib_runtime_data(prefix=b"i."):
    a6 = bytearray(prefix + bytes(random.randrange(1, 255) for _ in range(30)))
    a6[2:10] = b"non-prof"
    struct.pack_into("<H", a6, 10, 29801)
    a6[12] = 115
    for i in range(13, 32):
        a6[i] = (a6[i-1] + a6[i-2]) & 0xFF
    return bytes(a6)


def _pack_runtime_key_defaults():
    flags = 1 << 24
    return struct.pack("<8I", flags, 0, 0, 0, 0, 0, 0, 0) + b"\x00"


def _rsa_pub_der_ltc(n, e):
    def enc_len(l):
        if l < 0x80:
            return bytes([l])
        b = l.to_bytes((l.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b
    def enc_int(x):
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + enc_len(len(b)) + b
    body = enc_int(n) + enc_int(e)
    return b"\x30" + enc_len(len(body)) + body


def _mgf1(seed, length):
    out = b""
    c = 0
    while len(out) < length:
        out += hashlib.sha256(seed + struct.pack(">I", c)).digest()
        c += 1
    return out[:length]


def _pss_encode_raw(msg, salt, emlen=128, modbits=1024, hl=32):
    h = hashlib.sha256(b"\x00" * 8 + msg + salt).digest()
    db_len = emlen - hl - 1
    db = b"\x00" * (db_len - len(salt) - 1) + b"\x01" + salt
    mask = _mgf1(h, db_len)
    masked = bytes(a ^ b for a, b in zip(db, mask))
    em = bytearray(masked + h + b"\xbc")
    em[0] &= 255 >> (8 * emlen - (modbits - 1))
    return bytes(em)


def _ltc_rsa_sign_raw(key, msg, saltlen=8):
    salt = bytes(range(1, saltlen + 1))
    em = _pss_encode_raw(msg, salt)
    n = key.public_key().public_numbers().n
    d = key.private_numbers().d
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(128, "big")


def generate_runtime_key(keycode=b"pyarmor-vax-000000",
                         private_key_bytes=None, key_size=1024):
    from cryptography.hazmat.primitives.asymmetric import rsa as _RSA
    from cryptography.hazmat.primitives import serialization as _SER

    if private_key_bytes is None:
        key = _RSA.generate_private_key(public_exponent=65537, key_size=key_size)
    else:
        key = _SER.load_pem_private_key(private_key_bytes, password=None)
    pub_der = _rsa_pub_der_ltc(
        key.public_key().public_numbers().n,
        key.public_key().public_numbers().e)

    buf = bytearray(0x4040)
    struct.pack_into("<Q", buf, 0, RUNTIME_MAGIC)
    kc = keycode if isinstance(keycode, bytes) else keycode.encode()
    buf[12:12+len(kc)] = kc
    struct.pack_into("<Q", buf, 32, int(time.time()))
    struct.pack_into("<Q", buf, 40, 0x2000000000)
    struct.pack_into("<I", buf, 48, 32)
    struct.pack_into("<I", buf, 52, len(pub_der))
    aligned = len(pub_der) + 32
    if aligned & 7:
        aligned = aligned - (aligned & 7) + 8
    struct.pack_into("<I", buf, 56, aligned)
    p = 64 + aligned

    a6 = _fib_runtime_data()
    a4 = _pack_runtime_key_defaults()
    a5 = b"\x00" * 5 + b"\x00"

    struct.pack_into("<I", buf, p + 0, 0)
    struct.pack_into("<I", buf, p + 4, 32 + len(a4) + len(a5))
    struct.pack_into("<I", buf, p + 8, 64)
    struct.pack_into("<I", buf, p + 12, len(a4))
    struct.pack_into("<I", buf, p + 16, 64 + len(a4))
    struct.pack_into("<I", buf, p + 20, len(a5))
    sig_off = 64 + len(a4) + len(a5)
    struct.pack_into("<I", buf, p + 24, sig_off)
    struct.pack_into("<I", buf, p + 28, 128)

    buf[64+32:64+32+len(pub_der)] = pub_der
    buf[p+32:p+32+32] = a6
    buf[p+64:p+64+len(a4)] = a4
    buf[p+sig_off-6:p+sig_off] = a5
    signed = bytes(buf[p+32:p+32+32+len(a4)+len(a5)])
    sig = _ltc_rsa_sign_raw(key, signed)
    buf[p+sig_off:p+sig_off+len(sig)] = sig
    total = sig_off + len(sig)
    struct.pack_into("<I", buf, p + 0, total)
    struct.pack_into("<I", buf, 8, 64 + aligned + total)
    return bytes(buf[:64+aligned+total])


def patch_runtime_pyd(pyd_path, runtime_key, out_path=None):
    data = bytearray(Path(pyd_path).read_bytes())
    magic = struct.pack("<III", 0x6F2D728B, 1385940610, 0x4000) + b"pyarmor-vax"
    i = data.find(magic)
    if i == -1:
        raise ValueError("runtime data marker not found")
    data[i:i+len(runtime_key)] = runtime_key
    out = out_path or pyd_path
    Path(out).write_bytes(data)
    return i


# ---------------------------------------------------------------------------
# Marshal writer (CPython 3.14 order + pyarmor co_info postamble)
# ---------------------------------------------------------------------------
TYPE_NONE, TYPE_FALSE, TYPE_TRUE = "N", "F", "T"
TYPE_INT, TYPE_STRING = "i", "s"
TYPE_TUPLE, TYPE_SMALL_TUPLE = "(", ")"
TYPE_CODE, TYPE_UNICODE = "c", "u"
TYPE_ASCII, TYPE_SHORT_ASCII = "a", "z"
TYPE_BINARY_FLOAT, TYPE_BINARY_COMPLEX = "g", "y"
TYPE_SLICE = ":"
CO_FLAG_PYTRANSFORM3 = 0x20000000


class MarshalWriter:
    def __init__(self, replacements):
        self.out = bytearray()
        self.repl = replacements

    def w_byte(self, b):
        self.out.append(b)

    def w_long(self, x):
        self.out += struct.pack("<i", x)

    def w_pstring(self, s, typ):
        self.w_byte(ord(typ))
        self.w_long(len(s))
        self.out += s

    def w_short_pstring(self, s, typ):
        self.w_byte(ord(typ))
        self.w_byte(len(s))
        self.out += s

    def w_str(self, s):
        b = s.encode("utf-8")
        if s.isascii():
            if len(b) < 256:
                self.w_short_pstring(b, TYPE_SHORT_ASCII)
            else:
                self.w_pstring(b, TYPE_ASCII)
        else:
            self.w_pstring(b, TYPE_UNICODE)

    def w_bytes(self, b):
        self.w_pstring(b, TYPE_STRING)

    def w_tuple(self, t):
        if len(t) < 256:
            self.w_byte(ord(TYPE_SMALL_TUPLE))
            self.w_byte(len(t))
        else:
            self.w_byte(ord(TYPE_TUPLE))
            self.w_long(len(t))
        for item in t:
            self.w_object(item)

    def w_float_bin(self, f):
        self.out += struct.pack("<d", f)

    def w_object(self, o):
        if o is None:
            self.w_byte(ord(TYPE_NONE))
        elif o is True:
            self.w_byte(ord(TYPE_TRUE))
        elif o is False:
            self.w_byte(ord(TYPE_FALSE))
        elif isinstance(o, int):
            self.w_byte(ord(TYPE_INT))
            self.w_long(o)
        elif isinstance(o, float):
            self.w_byte(ord(TYPE_BINARY_FLOAT))
            self.w_float_bin(o)
        elif isinstance(o, complex):
            self.w_byte(ord(TYPE_BINARY_COMPLEX))
            self.w_float_bin(o.real)
            self.w_float_bin(o.imag)
        elif isinstance(o, slice):
            self.w_byte(ord(TYPE_SLICE))
            self.w_object(o.start)
            self.w_object(o.stop)
            self.w_object(o.step)
        elif isinstance(o, bytes):
            self.w_bytes(o)
        elif isinstance(o, str):
            self.w_str(o)
        elif isinstance(o, tuple):
            self.w_tuple(o)
        elif isinstance(o, types.CodeType):
            self.w_code(o)
        else:
            raise TypeError(f"cannot marshal {type(o)}: {o!r}")

    def field(self, co, name, default):
        for kwargs in self.repl.get(id(co), []):
            if name in kwargs:
                return kwargs[name]
        return default

    CO_FAST_ARG_POS = 0x02
    CO_FAST_ARG_KW = 0x04
    CO_FAST_ARG_VAR = 0x08
    CO_FAST_HIDDEN = 0x10
    CO_FAST_LOCAL = 0x20
    CO_FAST_CELL = 0x40
    CO_FAST_FREE = 0x80

    @staticmethod
    def _kinds_for(co):
        w = MarshalWriter.__new__(MarshalWriter)
        w.repl = {}
        return w._kinds(co)

    def _kinds(self, co):
        varnames = co.co_varnames
        cellvars = co.co_cellvars
        freevars = co.co_freevars
        flags = co.co_flags
        n_pos = co.co_posonlyargcount
        n_pokw = co.co_argcount - n_pos
        n_kw = co.co_kwonlyargcount
        n_varargs = 1 if flags & 4 else 0
        n_varkw = 1 if flags & 8 else 0

        kinds = []
        cellset = set(cellvars)
        for i, name in enumerate(varnames):
            k = self.CO_FAST_LOCAL
            if i < n_pos:
                k |= self.CO_FAST_ARG_POS
            elif i < n_pos + n_pokw:
                k |= self.CO_FAST_ARG_POS | self.CO_FAST_ARG_KW
            elif i < n_pos + n_pokw + n_kw:
                k |= self.CO_FAST_ARG_KW
            elif i < n_pos + n_pokw + n_kw + n_varargs:
                k |= self.CO_FAST_ARG_VAR | self.CO_FAST_ARG_POS
            elif i < n_pos + n_pokw + n_kw + n_varargs + n_varkw:
                k |= self.CO_FAST_ARG_VAR | self.CO_FAST_ARG_KW
            if name in cellset:
                k |= self.CO_FAST_CELL
            kinds.append(k)
        for name in cellvars:
            if name not in varnames:
                kinds.append(self.CO_FAST_CELL)
        for name in freevars:
            if name not in varnames:
                kinds.append(self.CO_FAST_FREE)
        return bytes(kinds)

    def w_code(self, co):
        self.w_byte(ord(TYPE_CODE))
        self.w_long(self.field(co, "co_argcount", co.co_argcount))
        self.w_long(self.field(co, "co_posonlyargcount", co.co_posonlyargcount))
        self.w_long(self.field(co, "co_kwonlyargcount", co.co_kwonlyargcount))
        self.w_long(self.field(co, "co_stacksize", co.co_stacksize))
        self.w_long(self.field(co, "co_flags", co.co_flags))
        self.w_bytes(self.field(co, "co_code", co.co_code))
        consts = self.field(co, "co_consts", co.co_consts)
        self.w_object(consts)
        self.w_object(self.field(co, "co_names", co.co_names))
        varnames = self.field(co, "co_varnames", None)
        cellvars = co.co_cellvars
        freevars = co.co_freevars
        if varnames is None:
            varnames = co.co_varnames
            lpn = list(varnames) + [c for c in cellvars if c not in varnames] \
                + [f for f in freevars if f not in varnames]
        else:
            lpn = list(varnames)
        kinds = self._kinds(co)
        self.w_object(tuple(lpn))
        self.w_bytes(kinds)
        self.w_str(self.field(co, "co_filename", co.co_filename))
        self.w_str(self.field(co, "co_name", co.co_name))
        self.w_str(self.field(co, "co_qualname", co.co_qualname))
        self.w_long(self.field(co, "co_firstlineno", co.co_firstlineno))
        self.w_bytes(self.field(co, "co_linetable", co.co_linetable))
        self.w_bytes(self.field(co, "co_exceptiontable", co.co_exceptiontable))
        if self.field(co, "co_flags", co.co_flags) & CO_FLAG_PYTRANSFORM3:
            co_info = consts[-1]
            assert isinstance(co_info, bytes), (co.co_name, co_info)
            self.out += co_info

    def dumps(self, obj):
        self.w_object(obj)
        return bytes(self.out)


# ---------------------------------------------------------------------------
# Maker harness â€” drives the real pyarmor.cli.maker with Python-only natives
# ---------------------------------------------------------------------------
def _load_maker(plaintext):
    import importlib
    import pyarmor.cli
    importlib.import_module("pyarmor.cli")
    if "pyarmor.cli.maker" in sys.modules:
        return sys.modules["pyarmor.cli.maker"]
    mod = types.ModuleType("pyarmor.cli.maker")
    mod.__package__ = "pyarmor.cli"
    src = Path(plaintext).read_text(encoding="utf-8")
    exec(compile(src, str(plaintext), "exec"), mod.__dict__)
    sys.modules["pyarmor.cli.maker"] = mod
    return mod


def _gcm_keystream(key, iv, size):
    return AESGCM(key).encrypt(iv, b"\x00" * size, None)


MACROS = {
    "RUNTIME_MAGIC_NUMBER": 1865249419,
    "RUNTIME_MAGIC_VERSION": 1385940610,
    "RUNTIME_DATA_SIZE": 0x4000,
    "PYTRANSFORM3_REVISION": 3,
    "CO_FLAG_PYTRANSFORM3": 0x20000000,
    "BCC_METHOD_TABLE_INDEX": 5,
    "CO_MARSHAL_ARMOR_FUNC_OFF": 0,
    "CO_MARSHAL_FIX_CO_JIT_OFF": 2,
    "CO_MARSHAL_BCC_CALLER_OFF": 4,
    "CO_MARSHAL_MIX_ARGNAMES_OFF": 5,
    "TRIAL_LICENSE_NO": "pyarmor-vax-000000",
    "PYARMOR_MARSHAL_VERSION": 0x80,
    "MARSHAL_TYPE_ASTBODY": 8,
    "MARSHAL_TYPE_BCCBODY": 9,
    "CHECK_RUNTIME_KEY_OFF": 0,
    "CHECK_CO_CODE_OFF": 1,
    "CHECK_PARENT_FRAME_OFF": 2,
    "PRIVATE_MODULE_OFF": 3,
    "READONLY_MODULE_OFF": 20,
    "CLEAR_MODULE_CO_CODE_OFF": 4,
    "CLEAR_FRAME_LOCALS_OFF": 5,
    "SIMPLE_MODULE_OFF": 6,
    "SELF_CONTAINED_OFF": 7,
    "OBF_MODULE_OFF": 8,
    "OBF_CODE_OFF": 11,
    "ENABLE_JIT_IV_OFF": 14,
    "ENABLE_BCC_MODE_OFF": 15,
    "ENABLE_VMC_MODE_OFF": 21,
    "PYARMOR_LICENSE_OFF": 16,
    "BIND_RUNTIME_KEY_OFF": 18,
}


def build_obfuscator(runtime_pyd, plaintext=None):
    plaintext = plaintext or PLAINTEXT
    aes_key, actual_pyd = derive_aes_key(runtime_pyd)
    maker = _load_maker(plaintext)
    replacements = {}

    def marshal_object(obj):
        return MarshalWriter(replacements).dumps(obj)

    def fix_co_object(co, name, value):
        key = name.decode() if isinstance(name, bytes) else str(name)
        if key in ("co_freevars", "co_cellvars") and value is None:
            lpn = (list(co.co_varnames)
                   + [c for c in co.co_cellvars if c not in co.co_varnames]
                   + [f for f in co.co_freevars if f not in co.co_varnames])
            kinds = MarshalWriter._kinds_for(co)
            return (tuple(lpn), kinds)
        replacements.setdefault(id(co), []).append({key: value})
        return co

    def generate_co_code(self, ctx, co, data, size, flags, iv):
        head = flags & 0xFFFF
        foot = flags >> 16
        region = bytearray(data)
        body = region[head:size - foot]
        ks = _gcm_keystream(aes_key, iv, len(body))
        region[head:size - foot] = bytes(a ^ b for a, b in zip(body, ks))
        replacements.setdefault(id(co), []).append({"co_code": bytes(region)})
        return bytes(region)

    def generate_module_data(self, ctx, obj, mode):
        if mode == 0:
            return marshal_object(obj)
        if mode == 1:
            blob = bytearray(obj)
            size = len(blob) - 64
            struct.pack_into("<I", blob, 32, size)
            blob[2:6] = b"0000"
            blob[6:8] = b"00"
            v13 = 0
            blob[38] = v13 | blob[38] & 0xFC
            struct.pack_into("<I", blob, 24, 5)
            struct.pack_into("<I", blob, 12, 0x0A0D0E2B)
            struct.pack_into("<I", blob, 64 + 12,
                             struct.unpack_from("<I", blob, 36)[0])
            if (blob[37] & 7) != 0:
                iv = bytes(blob[36:40]) + bytes(blob[44:52])
                ct = blob[64:64 + size]
                ks = _gcm_keystream(aes_key, iv, len(ct))
                blob[64:64 + size] = bytes(a ^ b for a, b in zip(ct, ks))
            return bytes(blob)
        raise NotImplementedError(f"generate_module_data mode {mode}")

    NATIVES = {
        "self": types.SimpleNamespace(runtime_key=b""),
        "get_license_features": lambda self, ctx: None,
        "get_bcc_builder": lambda self, ctx: None,
        "get_name_refactor": lambda self, ctx: None,
        "generate_runtime_key": None,
        "generate_module_data": generate_module_data,
        "generate_co_code": generate_co_code,
        "fix_co_object": fix_co_object,
        "get_macro_value": lambda self, ctx, name: MACROS[name],
    }
    for k, v in MACROS.items():
        maker.pyarmor_core_1[k] = v
    for k, v in NATIVES.items():
        maker.pyarmor_core_1[k] = v

    bld = maker.pyarmor_core_122
    for meth_name in ("_build_ast_body", "_build_bcc_body", "process_pyc"):
        marker = "_replica_orig_" + meth_name
        if not hasattr(bld, marker):
            orig = getattr(bld, meth_name)
            setattr(bld, marker, orig)
            def patched(self, res, _orig=orig, _m=maker):
                blob = _orig(self, res)
                return _m.pyarmor_core_1["generate_module_data"](None, None, blob, 1)
            setattr(bld, meth_name, patched)

    class FakeCtx:
        python_version = (3, 14)
        runtime_outer = 0
        exclude_co_names = set()
        exclude_restrict_modules = []
        module_types = {}
        obfuscated_modules = []
        global_path = str(_HERE)
        local_path = str(_HERE)
        inline_plugin_marker = None
        cmd_options = {
            "obf_code": 1, "obf_module": 1, "wrap_mode": 1, "optimize": 1,
            "enable_rft": 0, "enable_bcc": 0, "enable_vmc": 0, "enable_jit": 0,
            "assert_call": 0, "assert_import": 0, "mix_str": 0, "mix_attr": 0,
            "mix_coname": 0, "mix_localnames": 1, "mix_argnames": 0,
            "readonly_module": 0, "restrict_module": 1,
            "import_check_license": 0, "clear_module_co": 1,
            "clear_frame_locals": 0, "self_contained": 0, "runtime_outer": 0,
            "obf_script": 1, "enable_trace": 0,
        }
        def runtime_hook(self, pkgname):
            return None
        def get_res_options(self, name, sect="finder"):
            import configparser
            options = {}
            if not hasattr(self, "cfg"):
                self.cfg = configparser.ConfigParser()
                self.cfg["builder"] = {}
                self.cfg["finder"] = {}
            if self.cfg.has_section(sect):
                options.update(self.cfg.items(sect))
            if sect == "finder":
                options.update(self.cmd_options.get("finder", {}))
            elif sect == "builder":
                options.update(self.cmd_options)
            return options

    class FakeModule:
        def __init__(self, src, fullname="replica", pkgname=""):
            self.fullname = fullname
            self.pkgname = pkgname
            self.is_pyc = False
            self.exclude_nodes = set()
            self.lines = src.splitlines(True)
            self.mtree = ast.parse(src, fullname)
        @property
        def frozenname(self):
            n = self.fullname.find(".__init__")
            return "<frozen %s>" % self.fullname[:None if n == -1 else n]
        def readlines(self, encoding=None):
            return self.lines
        def reparse(self, lines):
            self.mtree = ast.parse("".join(lines))
        def recompile(self, mtree=None, optimize=1):
            if mtree is None:
                mtree = self.mtree
            self.mco = compile(mtree, self.frozenname, "exec", optimize=optimize)
        def clean(self):
            pass

    return maker, FakeCtx, FakeModule, actual_pyd


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def obfuscate(src, runtime_pyd=None, fullname="replica", out=None):
    """Obfuscate a source string. Returns the blob (bytes)."""
    runtime_pyd = runtime_pyd or RUNTIME_TEMPLATE
    maker, FakeCtx, FakeModule, actual_pyd = build_obfuscator(runtime_pyd)
    ctx = FakeCtx()
    module = FakeModule(src, fullname)
    builder = maker.pyarmor_core_122(ctx)
    blob = builder.process(module)
    if out:
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        (out / (fullname + ".py")).write_text(
            "# Pyarmor 9.2.6 (trial), 000000, non-profits\n"
            "from pyarmor_runtime_000000 import __pyarmor__\n"
            f"__pyarmor__(__name__, __file__, {blob!r})\n")
        dst = out / "pyarmor_runtime_000000"
        dst.mkdir(exist_ok=True)
        # Copy the ACTUAL runtime pyd (may be patched for pristine templates)
        pyd_src = Path(actual_pyd)
        pyd_dst = dst / "pyarmor_runtime.pyd"
        if not pyd_dst.exists():
            shutil.copy2(pyd_src, pyd_dst)
        init = dst / "__init__.py"
        if not init.exists():
            init.write_text(
                "# Pyarmor 9.2.6 (trial), 000000\n"
                "from .pyarmor_runtime import __pyarmor__\n",
                encoding="utf-8")
        # Clean up temp patched file
        if actual_pyd != str(runtime_pyd) and Path(actual_pyd).exists():
            Path(actual_pyd).unlink(missing_ok=True)
    return blob


def _find_pristine_template():
    """Locate the PRISTINE runtime pyd (no key baked in) for --fresh mode."""
    try:
        import pyarmor
        return Path(pyarmor.__file__).parent / "cli" / "core" / "pyarmor_runtime.pyd"
    except ImportError:
        pass
    # fall back to any .pyd in cli/core/
    try:
        import pyarmor.cli.core as c
        for f in Path(c.__file__).parent.glob("*.pyd"):
            if f.name == "pyarmor_runtime.pyd":
                return f
    except ImportError:
        pass
    raise FileNotFoundError("No pristine template found â€” install pyarmor first")


def obfuscate_fresh(src, fullname="replica", out=None):
    """Obfuscate with a fresh RSA-1024 runtime key (fully self-contained)."""
    rk = generate_runtime_key()
    tpl = _find_pristine_template()
    out_dir = Path(out or ".")
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp_pyd = out_dir / "_tmp_runtime.pyd"
    patch_runtime_pyd(tpl, rk, out_path=tmp_pyd)
    blob = obfuscate(src, runtime_pyd=tmp_pyd, fullname=fullname, out=out)
    # The obfuscate copies from rt.parent which is out_dir â€” the pyd is named
    # _tmp_runtime.pyd there, but we need pyarmor_runtime.pyd. Fix:
    dst = out_dir / "pyarmor_runtime_000000"
    pyd_dst = dst / "pyarmor_runtime.pyd"
    if not pyd_dst.exists() and tmp_pyd.exists():
        shutil.copy2(tmp_pyd, pyd_dst)
    # Ensure __init__.py is the dist version (NOT the package version)
    init = dst / "__init__.py"
    if not init.exists() or "from .pyarmor_runtime" not in init.read_text():
        init.write_text(
            "# Pyarmor 9.2.6 (trial), 000000\n"
            "from .pyarmor_runtime import __pyarmor__\n",
            encoding="utf-8")
    tmp_pyd.unlink(missing_ok=True)
    return blob


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="PyArmor 9.2.6 replica obfuscator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python pyarmor_replica.py sample.py -o dist\n"
               "  python pyarmor_replica.py sample.py -o dist --fresh\n"
               "  python pyarmor_replica.py --gen-key -o mykey.bin\n")
    ap.add_argument("script", nargs="?", help="input .py file")
    ap.add_argument("-o", "--out", default="dist", help="output dir")
    ap.add_argument("--fresh", action="store_true",
                    help="generate a fresh RSA key (fully self-contained dist)")
    ap.add_argument("--gen-key", action="store_true",
                    help="generate a runtime key file (no obfuscation)")
    ap.add_argument("--runtime-pyd", default=None,
                    help="path to runtime pyd template (default: auto-detect)")
    args = ap.parse_args()

    if args.gen_key:
        rk = generate_runtime_key()
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(rk)
        print(f"runtime key: {len(rk)} bytes -> {out}")
        return

    if not args.script:
        ap.error("script path required (or use --gen-key)")

    src = Path(args.script).read_text(encoding="utf-8")
    fullname = Path(args.script).stem

    if args.fresh:
        obfuscate_fresh(src, fullname=fullname, out=args.out)
        print(f"fresh-key dist written to {args.out}")
    else:
        rt = args.runtime_pyd or str(RUNTIME_TEMPLATE)
        blob = obfuscate(src, runtime_pyd=rt, fullname=fullname, out=args.out)
        print(f"blob len: {len(blob)}, dist written to {args.out}")


if __name__ == "__main__":
    main()
