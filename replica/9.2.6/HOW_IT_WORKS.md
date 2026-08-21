# How PyArmor 9.2.6 Works

> AI-assisted: Documentation was written with AI support

Addresses reference the 9.2.6 build on Windows x64: `pytransform3.pyd` at `0x70180000`, `pyarmor_runtime.pyd` at `0x63300000`.

## Architecture

PyArmor has two components:

1. **Obfuscator** (`pytransform3.pyd` + `pyarmor.cli.maker`) runs during `pyarmor gen` and produces encrypted blobs.
2. **Runtime** (`pyarmor_runtime_000000.pyd`) ships with the protected script and decrypts/executes blobs at runtime.

The obfuscator is a compiled native binary (`pytransform3.pyd`). The pipeline logic lives in `core.data.1`, an AES-encrypted Python source blob in the engine's `.data` section. The native engine decrypts it, compiles it via `Py_CompileStringExFlags`, and imports it as `pyarmor.cli.maker`. The imported Python code calls back into native crypto primitives (AES-GCM, MD5 KDF, RSA-PSS, marshal writer) via an 8-pointer C-API blob.

```
pyarmor gen script.py
  |
  +-- pytransform3.pyd (native engine)
  |   +-- init_ctx() -- decrypts core.data.1 -> imports pyarmor.cli.maker
  |   +-- generate_obfuscated_script() -- drives the maker
  |   +-- generate_module_data() -- encrypts module blobs
  |   +-- generate_co_code() -- encrypts per-function spans
  |   +-- generate_runtime_key() -- RSA keygen + PSS signing
  |   +-- fix_co_object() -- mutates code object fields in-place
  |   +-- get_macro_value() -- reads macro constants
  |   +-- get_license_features() -- queries license bits
  |   +-- get_bcc_builder() -- BCC engine (server-gated)
  |   +-- get_name_refactor() -- RFT engine (server-gated)
  |
  +-- pyarmor.cli.maker (recovered as core_data_1_cleaned.py)
      +-- ScriptObfuscator.process() -- main obfuscation pipeline
      +-- CodeObjectReformer -- wraps bodies with anchors
      +-- ArmorCodePatcher -- NOP-oparg prologue + enter/exit stubs
      +-- serialize_script -- custom 0x80 marshal
      +-- RuntimeKeyBuilder -- 0x4040 buffer + RSA-PSS
      +-- RuntimeExtensionBuilder -- patches .pyd + writes __init__.py
```

## The 8-Pointer C-API Blob

When `pytransform3.pyd` loads, it calls `init_ctx` which decrypts `core.data.1`, compiles it, and imports it as `pyarmor.cli.maker`. Then `generate_obfuscated_script` calls `init_c_api`, which receives a 64-byte blob with 8 function pointers:

```c
// From generate_obfuscated_script (0x701827d0):
// Builds a 64-byte blob of 8 pointers:
ptr[0] = sub_70184CC0  // get_license_features
ptr[1] = sub_70186400  // get_bcc_builder
ptr[2] = sub_701861D0  // get_name_refactor
ptr[3] = sub_70184680  // generate_runtime_key
ptr[4] = sub_70185AF0  // generate_module_data
ptr[5] = sub_70185A30  // generate_co_code
ptr[6] = sub_701821C0  // fix_co_object
ptr[7] = sub_70181700  // get_macro_value
```

The Python maker unpacks these via ctypes:
```python
# init_c_api (core_data_1_cleaned.py)
shared_state = {}  # native function table
shared_state['get_license_features'] = PYFUNCTYPE(c_int, py_object, py_object)(ptr[0])
shared_state['get_bcc_builder'] = PYFUNCTYPE(py_object, py_object, py_object)(ptr[1])
shared_state['generate_module_data'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, c_int)(ptr[4])
shared_state['generate_co_code'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, c_char_p, c_int, c_int, c_char_p)(ptr[5])
shared_state['fix_co_object'] = PYFUNCTYPE(py_object, py_object, c_char_p, py_object)(ptr[6])
shared_state['get_macro_value'] = PYFUNCTYPE(py_object, c_char_p)(ptr[7])
```

## Key Derivation

The runtime derives a 16-byte AES key using MD5:

```
key = MD5(salt || pubkey_der || desc_hash || deob270)
```

### Native Implementation (sub_70185970)

```c
// sub_70185970 (pytransform3.pyd):
// a1 = runtime_key blob (0x4040 bytes)
// a2 = offset to embedded pubkey in runtime key
// a3 = data to encrypt
// a4 = data length
// a5 = cipher_id (from state+56)

v5 = *(int*)(a1 + 56);                    // cipher_id offset
v7 = a1 + 64;                             // payload base
sub_701970D0(v13);                         // MD5_init (472-byte ctx)
sub_70197380(v13, a1+12, 20);             // MD5_update(runtime_key[12:32], 20) = keycode
sub_70197380(v13, v7+rk[48], rk[52]);     // MD5_update(embedded_pubkey, len)
sub_70197380(v13, v7+v5+32, rk[v5+36]);  // MD5_update(license_desc_hash, len)
sub_70197380(v13, &unk_701E21C0, 270);    // MD5_update(static_270B_DER_pubkey)
sub_70197130(v13, v12);                    // MD5_final -> 16-byte key
sub_701858D0(a5, a3, a4, v12, a2);        // AES-GCM encrypt
```

### What Each Input Means

| Input | Source | Size | Description |
|-------|--------|------|-------------|
| salt | runtime_key[12:32] | 20B | Keycode (e.g. "pyarmor-vax-000000") |
| pubkey_der | runtime_key[64+off@48] | 140B | LTC RSA-2048 DER public key |
| desc_hash | runtime_key[64+off@56+32] | var | Signed license descriptor hash |
| deob270 | unk_701E21C0 | 270B | Static DER RSA-2048 pubkey (XOR-deobfuscated) |

The same key is used for both module-data encryption and per-function co_code encryption. Per-function differentiation is purely the IV.

## Module Data Encryption

### The 64-Byte Header

Built by `generate_module_data` (sub_70185AF0) and `_build_marshal_header`:

```python
# core_data_1_cleaned.py - _build_marshal_header()
header = pack('8sBBBBIBBBBIIIII16s8x',
    b'PYARMOR',           # magic (overwritten to PY000000)
    0,                    # version
    pyver_major,          # Python major
    pyver_minor,          # Python minor
    0,                    # reserved
    0,                    # reserved
    PYARMOR_MARSHAL_VERSION,  # 0x80
    0,                    # revision
    1, 0,                 # platform
    marshal_type,         # 8=AST, 9=BCC
    0,                    # reserved
    64,                   # header size
    size,                 # ciphertext size
    flags,                # OBF_CODE | OBF_MODULE | BIND_RUNTIME_KEY | ...
    random_salt           # 16 bytes
)
```

### The Product Code Patch

`generate_module_data` overwrites bytes 2-7 with the product code from the license token:

```c
// sub_70185AF0 (pytransform3.pyd):
*(_DWORD*)(v12 + 2) = *(_DWORD*)(v11 + 28);   // bytes 2-5 = product_code dword
*((_WORD*)v12 + 3) = *((_WORD*)(v11 + 16));    // bytes 6-7 = product_code word
```

On trial: product code is `000000`, so magic becomes `PY000000`.

### Encryption Gate

Byte 37 & 7 determines whether the body is encrypted:

```c
// sub_70185AF0:
if ((v12[37] & 7) != 0) {
    // Encrypt the body region
    sub_70185970(runtime_key, IV, data+64, size-64, cipher_id);
}
```

### Split IV Assembly

The 12-byte IV is assembled from two header regions:

```python
# Runtime reads IV as:
IV = header[36:40] + header[44:52]  # 12 bytes total
```

The maker writes it as:
```python
# core_data_1_cleaned.py - _build_marshal_header()
header[36:40] = iv_part1    # 4 bytes
header[44:52] = iv_part2    # 8 bytes
```

## Per-Function Encryption

### The argindex Constant

Each wrapped function has a 20-byte descriptor stored in `co_consts`:

```python
# core_data_1_cleaned.py - _patch_co_consts()
argindex = pack('QBBBBII',
    0,                              # reserved
    flags | (ivmode << 1) | (jit << 2) | (clear_frame << 4),
    iv_position,                    # offset to IV in code buffer
    0,                              # reserved
    head_size,                      # size of non-encrypted head stub
    region_length,                  # length of encrypted body
    0                               # depth counter (runtime-managed)
)
```

### C_ENTER (sub_63304440) - The Decrypt Engine

When a wrapped function is called, the interpreter hits the head stub which calls `__pyarmor_enter__`. This is the native C_ENTER function:

```c
// sub_63304440 (pyarmor_runtime.pyd):
// a1 = module state
// a2 = frame

v5 = frame + dword_6339C048;  // v5 = code buffer base (0xD0 for py3.14)

// Increment depth counter
v7 = frame->depth + 1;
frame->depth = v7;

if (v7 != 1) {
    // Not first entry - just return None
    return None;
}

// First entry: decrypt the function body
// Read IV from code buffer
v12 = *(unsigned char*)(v5 + 41);  // iv_position from argindex
if (flag & 2)
    iv_ptr = v5 + v12;             // head mode: IV at start
else
    iv_ptr = v5 + region_len + v12 + headsize;  // tail mode: IV at end

// De-armor the IV (replace obfuscated bytes with 'R')
for (i = 0; i < 8; i++) {
    if ((iv[i] + 66) <= 1)  // if byte is 0xBE or 0xBF
        iv[i] = 0x52;       // replace with 'R'
}

// GCM decrypt in-place
gcm_init(state+152+24);         // sub_63380EB0 - init with module key
gcm_add_iv(state+152+24, iv, 12); // sub_63381600
gcm_process(state+152+24, 0, 0);  // sub_63380F10 - finalize IV
gcm_process(state+152+24, code+headsize, region_len, code+headsize, 0);
                                    // sub_633811E0 - decrypt in-place (dir=0)
```

### C_LEAVE (sub_63304930) - Re-encrypt on Return

When the function returns, the interpreter hits the footer stub which calls `__pyarmor_exit__`. This is C_LEAVE:

```c
// sub_63304930 (pyarmor_runtime.pyd):
// Same skeleton as C_ENTER but reversed

v7 = frame->depth - 1;
frame->depth = v7;

if (v7 != 0) {
    return None;  // Not last exit - just return
}

// Last exit: re-encrypt the body
gcm_init(state+152+24);
gcm_add_iv(state+152+24, iv, 12);
gcm_process(state+152+24, 0, 0);
gcm_process(state+152+24, code+headsize, region_len, code+headsize, 1);
                                    // dir=1 = encrypt
```

The depth counter prevents issues with recursion. Decryption happens only at depth 0->1, re-encryption only at 1->0.

## Runtime Key Generation

### The 0x4040-Byte Structure

Built by `generate_runtime_key` (sub_701829C0):

```python
# core_data_1_cleaned.py - _pack_runtime_key()
buf = bytearray(0x4040)
pack_into('<Q', buf, 0, 0x36F2D728B)   # magic
buf[12:12+len(keycode)] = keycode       # e.g. "pyarmor-vax-000000"
pack_into('<Q', buf, 32, int(time()))   # timestamp
pack_into('<Q', buf, 40, 0x2000000000)  # flags
pack_into('<I', buf, 48, 32)            # pubkey offset
pack_into('<I', buf, 52, len(pub_der))  # pubkey length
# ... payload at +64 with fib header, a4, a5, RSA-PSS signature
```

### The Non-Standard PSS

The runtime verifies with a non-standard PSS:

```python
# Standard PSS:
H = SHA256(0x00*8 || SHA256(msg) || salt)

# PyArmor PSS (raw-region):
H = SHA256(0x00*8 || msg || salt)  # NO pre-digest of msg
```

The signing uses LTC's `rsa_sign_hash` with:
- padding = 3 (PSS)
- prng = NULL (deterministic salt from sprng_read)
- saltlen = 8

### Patching the Template

The runtime key is patched into the template `.pyd` via the III20s marker:

```python
# core_data_1_cleaned.py - patch_extension()
marker = pack('III20s', RUNTIME_MAGIC_NUMBER, RUNTIME_VERSION, RUNTIME_DATA_SIZE, b'pyarmor-vax')
i = data.find(marker)
data[i:i+len(runtime_key)] = runtime_key
```

## The Runtime Loader

### __pyarmor__ Export (sub_63305500)

The `__pyarmor__` export is the main entry point. It takes `(name, path, bytes, mode)`:

```c
// sub_63305500 (pyarmor_runtime.pyd):
PyArg_ParseTuple(args, "OOy#|i", &name, &path, &blob, &blob_size, &mode);

// Query mode (mode & 0xF == 1):
if (mode & 0xF == 1) {
    // Return hdinfo or keyinfo
    return buildvalue("s", hdinfo);
}

// Load mode:
// Walk blob headers to find matching version + product code
for (hdr = blob; ; hdr += hdr[14]) {
    if (hdr[9] == major && hdr[10] == minor) {
        // Version match
        if (memcmp(hdr+2, product_code, 6) == 0) {
            // Product code match
            // Decrypt module data
            gcm_init(state+152+24);
            gcm_add_iv(state+152+24, hdr+40, 12);
            gcm_process(state+152+24, 0, 0);
            gcm_process(state+152+24, data, size, data, 1);
            // Parse marshal
            code = parse_marshal(data);
            // Execute
            module = PyImport_ExecCodeModuleObject(name, code, path);
            return module;
        }
    }
    if (hdr[14] == 0) break;  // end of headers
}
```

### The Custom Marshal Parser (sub_6330ACC0)

The marshal parser is a complete port of CPython 3.14's `marshal.c`. The only extension is the `co_info` postamble for wrapped code objects:

```c
// sub_6330ACC0 (pyarmor_runtime.pyd) - case 'c':
// Standard fields: argcount, posonlyargcount, kwonlyargcount, stacksize, flags
// Then: code, consts, names, varnames, filename, name, qualname
// Then: firstlineno, linetable, exceptiontable
// Extension: if (co_flags & 0x20000000) {
//     Read co_info postamble after exceptiontable
//     Patch co_names with natives from slot table
// }
```

## The Replica Tool

The replica tool (`pyarmor_replica.py`) produces identical output using:

1. **Recovered maker source** (`core_data_1_cleaned.py`) drives the real pipeline
2. **Pure-Python natives** replace the 8 C-API primitives:
   - `generate_module_data`: marshal writer + AES-GCM encrypt
   - `generate_co_code`: AES-GCM per-function armor
   - `fix_co_object`: per-field replacement map (no C mutation)
   - `get_macro_value`: returns real macro constants
   - `get_license_features`: returns None (trial)
   - `get_bcc_builder`/`get_name_refactor`: return None (server-gated)

3. **Fresh RSA-1024 runtime key** self-signed with raw-PSS, patched into template `.pyd`

Usage:
```bash
# Obfuscate
python pyarmor_replica.py script.py -o dist

# Fresh RSA key
python pyarmor_replica.py script.py -o dist --fresh

# Generate key only
python pyarmor_replica.py --gen-key -o mykey.bin
```
