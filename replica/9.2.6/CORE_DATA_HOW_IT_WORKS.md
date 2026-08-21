# How core.data.1 Works

> AI-assisted: Documentation was written with AI support

This document covers `core_data_1_cleaned.py` — where it comes from and how it fits into the PyArmor obfuscation pipeline.

## What Is core.data.1?

`core.data.1` is a 299,632-byte file inside `pytransform3.pyd` (PyArmor's obfuscation engine). It is encrypted Python source that gets decrypted, compiled, and imported at runtime as `pyarmor.cli.maker`.

The obfuscator is a compiled native binary (`pytransform3.pyd`). The pipeline logic lives in `core.data.1`, an AES-encrypted Python source blob in the engine's `.data` section. The native engine decrypts it, compiles it via `Py_CompileStringExFlags`, and imports it as `pyarmor.cli.maker`. The imported Python code calls back into native crypto primitives (AES-GCM, MD5 KDF, RSA-PSS, marshal writer) via an 8-pointer C-API blob.

## Where It Comes From

The file was recovered by:

1. Reading the 16-byte AES key from `pytransform3.pyd` at VA `unk_701E3A60` (PE file offset ~0x62260)
2. Reading the 12-byte nonce: 8-byte config_value at `dword_701E3A70` plus LE constant `0x8a5b0ee5`
3. Decrypting the full 299,632-byte blob with stock AES-GCM-CTR (no tag verification)
4. The output is printable Python — the `pyarmor.cli.maker` module

## What It Contains

The cleaned source (`core_data_1_cleaned.py`) has readable names and comments. The key components:

### Top-Level Functions

| Function | Purpose |
|---|---|
| `generate_random_bytes(n)` | Generate N random bytes (1-255 range) for padding/filler |
| `generate_interp_fingerprint()` | Fingerprint the Python interpreter via C API symbol addresses + MD5 |
| `decrypt_pe_overlay(pe_data)` | XOR-decrypt a PE binary overlay section |
| `init_c_api(blob)` | Unpack 8 native function pointers from the C-API blob into `shared_state` |
| `generate_obfuscated_script(ctx, module)` | Main entry: obfuscate one module |
| `generate_runtime_package(ctx, output, platforms)` | Build the runtime package (patch .pyd + write __init__.py) |
| `generate_runtime_key(ctx, outer)` | Generate a runtime key blob (RSA keygen + PSS signing) |
| `dispatch_special_build(args)` | Dispatch to special build modes (rft, bcc, mini, vmc, ecc) |
| `pre_build(ctx)` | Pre-build setup: variable types, RFT mode init |
| `post_build(ctx)` | Post-build cleanup: extra libs packaging |
| `fetch_ci_server(url, header)` | Fetch data from the PyArmor CI server |

### Classes

| Class | Purpose |
|---|---|
| `RuntimeKeyBuilder` | Builds the 0x4040-byte runtime key (RSA + PSS signing) |
| `RuntimeExtensionBuilder` | Builds the runtime package: patches .pyd with runtime key, writes __init__.py |
| `ScriptObfuscator` | Main obfuscation engine — drives the full pipeline |
| `PreBuildProcessor` | Pre-build setup: initializes variable types, RFT mode, and license checks |
| `ExtraLibsBuilder` | Extra libraries builder: packages additional .py files into extra_libs.zip |
| `ASTPatcher` | AST node transformer: patches assert, call, import, and string nodes |
| `AssertCallTransformer` | Wraps function calls with `__assert_armored__` checks |
| `AssertImportTransformer` | Wraps import statements with `__assert_armored__` checks |
| `StringObfuscator` | Encrypts string constants in the AST |
| `CodeObjectReformer` | Wraps code bodies with assert/enter/exit anchors at the AST level |
| `AttributeObfuscator` | Encrypts attribute names in the AST |
| `VMCMarkerCollector` | Generates VMC blocks for advanced protection |
| `CodeObjectPatchInfo` | Stores assert/enter/exit/arg indices and sizes for code objects |
| `InlineMarkerProcessor` | Installs runtime hooks and handles module-level setup |
| `BaseCodePatcher` | Base class for bytecode patchers: common instruction traversal |
| `BCCCodePatcher` | Patches code objects for BCC mode |
| `ArmorCodePatcher` | Replaces function bodies with NOP-oparg prologue + enter/exit stubs |
| `JitIVBuilder_8bit` | Generates 8-bit JIT programs for IV computation |
| `LocalVariableRenamer` | Renames local variables for obfuscation |
| `VMCCodePatcher` | VMC code patcher |
| `ASTTreeTraveler` | AST tree traversal utility |
| `NameFilter` | Filters names by include/exclude patterns |
| `ModuleTypeInfo` | Tracks module types (obfuscated, plain, etc.) |
| `ModuleAnalyzer` | Analyzes module imports and dependencies |
| `PackageRelationsBuilder` | Builds relationships between packages and modules |
| `VMCCompiler` | VMC compiler |

### The 8-Pointer C-API Blob

When `pytransform3.pyd` loads, it calls `init_ctx` which decrypts `core.data.1`, compiles it, and imports it as `pyarmor.cli.maker`. Then `generate_obfuscated_script` calls `init_c_api`, which receives a 64-byte blob with 8 function pointers:

```python
# init_c_api (core_data_1_cleaned.py)
shared_state = {}  # native function table
shared_state['get_license_features'] = PYFUNCTYPE(c_int, py_object, py_object)(ptr[0])
shared_state['get_bcc_builder'] = PYFUNCTYPE(py_object, py_object, py_object)(ptr[1])
shared_state['get_name_refactor'] = PYFUNCTYPE(py_object, py_object, py_object)(ptr[2])
shared_state['generate_runtime_key'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, py_object, py_object, py_object)(ptr[3])
shared_state['generate_module_data'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, c_int)(ptr[4])
shared_state['generate_co_code'] = PYFUNCTYPE(py_object, py_object, py_object, py_object, c_char_p, c_int, c_int, c_char_p)(ptr[5])
shared_state['fix_co_object'] = PYFUNCTYPE(py_object, py_object, c_char_p, py_object)(ptr[6])
shared_state['get_macro_value'] = PYFUNCTYPE(py_object, c_char_p)(ptr[7])
```

### The Obfuscation Pipeline

```
generate_obfuscated_script(ctx, module)
  |
  +-- ScriptObfuscator.process(module)
      |
      +-- 1. Read source lines
      +-- 2. InlineMarkerProcessor.handle(module) -- install runtime hook
      +-- 3. Parse AST
      |
      +-- 4. AST transforms (in order):
      |   +-- NameRefactor (if enable_rft)
      |   +-- BccBuilder (if enable_bcc)
      |   +-- AssertCall (if assert_call)
      |   +-- AssertImport (if assert_import)
      |   +-- StringObfuscator (if mix_str)
      |   +-- CodeObjectReformer -- wraps bodies with assert/enter/exit anchors
      |   +-- AttributeObfuscator (if obf_code > 1 or mix_attr)
      |
      +-- 5. Recompile AST -> bytecode
      |
      +-- 6. Bytecode transforms:
      |   +-- BCCCodePatcher (if enable_bcc)
      |   +-- LocalVariableRenamer (if mix_localnames)
      |   +-- ArmorCodePatcher -- NOP-oparg prologue + enter/exit stubs
      |
      +-- 7. serialize_script -> encrypted blob
```

### The Reform Engine (CodeObjectReformer)

The `CodeObjectReformer` walks every function/class/module node and wraps its body:

**For assert-only mode:**
```python
# Original:
def foo():
    return 42

# After reform:
__assert_armored__ = lambda _x_: _x_  # anchor
def foo():
    return 42
```

**For obf_code mode:**
```python
# Original:
def foo():
    return 42

# After reform:
__assert_armored__ = lambda _x_: _x_          # anchor
(lambda _x_: 1976)(pyarmor_12345)               # marker constant
def foo():
    try:
        return 42
    except:
        (lambda _y_: _y_)(pyarmor_12345)       # footer marker
```

### The Armor Code Patcher (ArmorCodePatcher)

The `ArmorCodePatcher` does the real protection. It finds the anchors inserted by the reform and replaces the function body with a decrypt-and-call stub.

**Head Stub (Entry):**
```python
# Original entry bytecode is replaced with:
NOP random           # NOP out original RESUME
LOAD_CONST enter     # __pyarmor_enter__
PUSH_NULL
LOAD_CONST arg       # argindex descriptor
BUILD_TUPLE 1
PUSH_NULL
CALL_FUNCTION_EX 0   # call __pyarmor_enter__(arg)
POP_TOP
NOP random           # filler
LOAD_CONST assert    # __pyarmor_assert__
STORE_FAST/__assert_armored__
```

**Footer Stub (Exit):**
```python
# At the end of the function:
LOAD_CONST exit      # __pyarmor_exit__
PUSH_NULL
LOAD_CONST arg       # same argindex
BUILD_TUPLE 1
PUSH_NULL
CALL_FUNCTION_EX 0   # call __pyarmor_exit__(arg)
POP_TOP
RETURN_VALUE
```

**What Gets Encrypted:**
The original function body (between the head stub and the footer) is encrypted with AES-GCM. The encrypted data is stored as a constant in the code object.

### The argindex Constant

Each wrapped function has a 20-byte descriptor stored in `co_consts`:

```python
# CodeObjectPatchInfo._patch_co_consts()
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

### The Marshal Writer

The marshal writer (`serialize_script`) is a faithful port of CPython 3.14's `marshal.c` with one extension: for wrapped functions (`co_flags & 0x20000000`), a `co_info` postamble is appended after the exception table.

### Module Data Encryption

The 64-byte header:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 2 | Magic `"PY"` |
| 2 | 6 | Product code (overwrites magic to `"PY000000"`) |
| 12 | 4 | Python bytecode magic (0x0A0D0E2B for 3.14) |
| 28 | 4 | Flags (OBF_CODE, OBF_MODULE, BIND_RUNTIME_KEY, etc.) |
| 36 | 4 | IV part 1 |
| 37 | 1 | Encryption gate (byte 37 & 7 != 0 means encrypted) |
| 44 | 8 | IV part 2 |
| 64+ | var | Encrypted module data |

### Key Derivation

```
key = MD5(salt || pubkey_der || desc_hash || deob270)
```

Four inputs from the runtime key:
- `salt`: 20-byte keycode
- `pubkey_der`: LTC RSA PKCS#1 DER public key (140 bytes)
- `desc_hash`: signed license descriptor hash
- `deob270`: 270-byte static DER RSA-2048 pubkey

### Runtime Key Generation

Built by `RuntimeKeyBuilder.build()`:
- 0x4040-byte buffer
- Magic `0x36F2D728B` + keycode + timestamp
- RSA-1024 public key (LTC DER)
- Fibonacci-expanded "non-profits" header + license flags
- RSA-PSS signature (non-standard: `H = SHA256(0x00*8 || raw_msg || salt)`)
