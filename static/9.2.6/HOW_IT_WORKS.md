# How pyarmor_static.py works

## Blob structure

A protected `.py` file contains a call such as `__pyarmor__(__name__, __file__, b'PY000000...')`, where the last argument is an encrypted blob. The original program's code lives inside that blob. `pyarmor_runtime.pyd`, a compiled native module shipped alongside the script, is the only component capable of decrypting it.

I open `pyarmor_runtime.pyd` with `Path.read_bytes()` and treat it as a byte array to search and slice. I never import or execute the file.

## Key derivation

The runtime derives its AES key at startup from static, embedded byte ranges. `derive_key()` reproduces the derivation in Python:

1. I search the raw `.pyd` bytes for the marker `b"pyarmor-vax-"` (`_SALT_ANCHOR`). The 20 bytes starting there are the salt.
2. A header sits 12 bytes (`_HEADER_BEFORE_SALT`) before the salt. Three little-endian 32-bit offsets inside it, read via `struct.unpack_from("<III", header, 0x30)`, locate an embedded RSA public key blob and a signed license descriptor, relative to the header's end.
3. A fixed offset from the salt (`_RAW270_DELTA_FROM_SALT = 16660`) holds a 270-byte region obfuscated at rest. I unmask it by XOR against a 16-byte repeating pad, which I find by scanning forward for the first run of 16 identical non-zero bytes. This step bit me: a run of alignment padding elsewhere in the file is also 16 identical bytes, and matching that first derives the wrong key. Zero is excluded for exactly that reason.
4. The key is `hashlib.md5(salt + pubkey_der + license_desc_hash + deob270).digest()`, used as the AES-128 key without truncation.

Every value is computed relative to the salt anchor's position in the specific `.pyd` being read, with no absolute file offset hardcoded. The same code runs unmodified against five separately-built runtime files, one per Python version.

### PyInit_pyarmor_runtime (sub_63306820)

`sub_63306820` (Python 3.14 build, image base `0x63300000`) is `PyInit_pyarmor_runtime`. The binary has no symbols, so `sub_63306820` is an IDA-generated name. The excerpt shows cipher/hash/PRNG registration, embedded key material, RSA-PSS verification of a signed descriptor, and the call that produces the AES key.

```c
// sub_63306820 = PyInit_pyarmor_runtime
v35 = sub_6331F620(Str2: "aes");          // find_cipher("aes")
v36 = sub_6331F8C0(Str2: "sprng");        // find_prng("sprng")
v37 = sub_6331F770(Str2: "sha256");       // find_hash("sha256")

// optional external-key-file branch (off in this build/sample):
if ( (byte_6338405C & 1) != 0 ) {
    v75 = sub_63303280(a1: v33, a2: ".pyarmor.ikey");
    // ... reads an external key blob if present; skipped here
}

// XOR-unmask an embedded region using a length-dependent pad (elided: an
// SSE-based 16-byte-chunk loop, then a tail loop for the remainder)

v41 = (char *)&unk_63384060 + dword_63384058;

// RSA import (in, inlen, key) -- imports the embedded public key
v42 = sub_63321410(a1: ..., a2: ..., a3: v33 + 24);

// RSA-PSS verify (sig, siglen, hash, hashlen, padding=3, hash_idx, saltlen, stat, key)
v42 = sub_63321C70(
    a1: &v41[*((int *)v41 + 6)], a2: *((unsigned int *)v41 + 7),
    a3: v41 + 32, a4: *((unsigned int *)v41 + 1),
    a5: 3, a6: *(_DWORD *)(v33 + 104), a7: *(_DWORD *)(v33 + 96),
    a8: v111, a9: v33 + 24);
if ( LODWORD(v111[0]) == 0 )               // integrity gate: signature must verify
    /* ... hard-fail path ... */;

// (further down, in the v56==1 branch) the actual KDF call:
sub_63303900(a1: v33, a2: v43 + 32);

// then the GCM key gets installed into a persistent context:
sub_633081B0(a1: v41, a2: v111);
sub_63380DF0(a1: *(_QWORD *)(v33 + 152) + 24LL, a2: 0, a3: v111, a4: 16);  // gcm_init(ctx, cipher, key, 16)
```

The salt at the address `derive_key()` computes for this `.pyd` reads as the ASCII string `pyarmor-vax-000000`.

## Blob extraction and target version

`extract_blobs()` parses the target `.py` file with `ast.parse()`, not `exec()` or `eval()`, and walks the AST for a call to a function named `__pyarmor__`. Its last argument, read with `ast.literal_eval()`, is the encrypted blob.

`detect_target_version()` reads `blob[9]` and `blob[10]` for the `(major, minor)` Python version the blob targets. If that does not match the running interpreter, `_reexec_if_needed()` relaunches under a matching `py -X.Y` (or `pythonX.Y`) on PATH. Python's internal code-object format changed shape starting in 3.11; running under the matching interpreter avoids reimplementing each version's rules.

## Blob decryption

Blob header layout, offsets relative to the blob start:

| Offset | Meaning |
|---|---|
| `0:8` | magic, `b'PY000000'` |
| `9:11` | target Python `(major, minor)` |
| `20:24` | type tag: `8` (every sample observed) or `9` (implemented, unexercised against a real file) |
| `28:32` | ciphertext offset |
| `32:36` | ciphertext length |
| `36:52` | 12-byte GCM IV |
| `37` | low 3 bits: whether a decrypt runs |

`decrypt_blob()` decrypts the ciphertext span with `AES.new(key, AES.MODE_GCM, nonce=iv).decrypt(...)`, calling `.decrypt()` only. The runtime never calls `.verify()` or checks a GCM tag, so the decrypt output alone cannot distinguish a correct key from an incorrect one. Rather than trust the bytes blindly, `decrypt_blob()` checks two values the plaintext is expected to contain after decryption, an IV echo and a fixed type marker; a mismatch raises `DecryptError`.

## Marshal parsing

The decrypted bytes form a CPython `marshal` stream, the format used for `.pyc` files. The stream tripped me up once: PyArmor's writer occasionally declares a constants-tuple shorter than what it wrote, appending the remaining entries directly afterward with no header. Reading the declared count and stopping leaves the stream mis-parsed from that point on. `_read_consts_then_names()` reads the declared constants, then checks whether what follows looks like a names-tuple (checked against the code object's defined names where enough context exists); if not, it is folded in as additional constants, and the check repeats.

PyArmor injects native `PyCFunction` objects, including `C_ENTER_CO_OBJECT_INDEX` (the function `../../hooking/9.2.6/pyarmor_hook.py` detours), directly into a code object's constants. A native function cannot be reconstructed from a file on disk. I represent these as `Placeholder` objects, and `_drop_marshal_placeholders()` strips them before the constants tuple is handed to `types.CodeType`.

## Code object reconstruction and per-function decryption

`build_code_object()` builds each `RawCode` record into a `types.CodeType` via `.replace()` on a throwaway compiled template rather than the `CodeType` constructor directly, since constructor argument order differs across Python versions and `.replace()` takes keywords. `co_nlocals` is passed explicitly — this one bit me. Without it, `.replace()` produces a broken object on 3.10 and below, and raises outright on 3.11 and above: same omission, two failure modes.

`decrypt_vm_span()` resolves per-function encryption at this stage. A protected function's `co_consts` contains a marker constant starting with `b"__pyarmor_enter_"`, followed by a 20-byte descriptor. Byte 8 of the descriptor is a flag (`1` or `3` in every sample observed); byte 11 is the span's start offset in `co_code` (always `20`, matching the fixed length of the marker call idiom); bytes 12-13 are the span length as a little-endian `uint16`. The GCM IV comes from `co_code[0:12]` when `flag == 3`, or from the 12 bytes following the span when `flag == 1`. The span decrypts with the same master key from `derive_key()`, via `AES.new(key, AES.MODE_GCM, nonce=iv).decrypt(...)`.

Disassembling this span was a dead end until I understood what the bytes were: raw, they produced invalid opcodes or crashed the disassembler, because they were ciphertext, not bytecode. Decrypted, the same span is ordinary CPython bytecode.

`print_report()` walks the reconstructed tree (module, then each nested function/class body) and prints each object's constants, names, and a `dis.dis()` disassembly, marking functions whose `co_consts` still show the enter/exit marker pair. `vm_protected_markers()` collects that list up front.
