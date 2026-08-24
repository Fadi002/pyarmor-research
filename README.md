# pyarmor-research

Reverse-engineering notes and tooling for PyArmor.

> AI-assisted: Documentation was written with AI support

Scope:

- runtime behavior of the native PyArmor runtime;
- the protected blob format;
- key derivation and decryption;
- reconstruction of Python code objects;
- obfuscation engine recovery and replica generation;
- runtime capture used to validate static reconstruction.

In-depth research currently targets PyArmor 9.2.6. Findings are version-scoped unless another version has been tested explicitly.

## Hooking

[`hooking/`](hooking/) captures protected code while the runtime has decrypted it in memory.

The hook targets the runtime function used to enter a protected code object and copies the decrypted object before the runtime re-encrypts its bytecode.

This gives the static tooling an execution-time reference, limited to code paths reached during the capture run.

## Static

[`static/`](static/) reconstructs protected code from the shipped `.py` file and native runtime, without executing the protected program.

Pipeline: parse the embedded blob, derive the runtime key from data in `pyarmor_runtime.pyd`, decrypt, parse the resulting `marshal` stream, rebuild Python code objects.

Covers code that does not run during a capture, at the cost of depending on the inferred format. Runtime captures detect reconstruction errors.

## Replica

[`replica/`](replica/) produces PyArmor-compatible distributions from pure Python. A full obfuscation engine replica.

Unlike static reconstruction (which reads blobs), the replica writes blobs that the real `pyarmor_runtime_000000` executes. It drives the recovered maker source with Python-only natives, generates fresh RSA runtime keys, and produces self-contained dists.

See [`replica/9.2.6/HOW_IT_WORKS.md`](replica/9.2.6/HOW_IT_WORKS.md) for the technical explanation.

## openprotect

[`openprotect/`](openprotect/) is a small attempt at building PyArmor-style protection from scratch, as an open-source tool instead of research notes.

It covers the other direction from the replica: rather than reproducing PyArmor's exact output, it implements the same class of protection independently - AST obfuscation, AES-GCM containers with enforced integrity checks, per-function encrypted bodies, string-table encryption, identifier renaming, RSA-PSS signed licenses, whole-module native compilation via Cython, and an exact deobfuscation round-trip for your own builds.

Pure Python, zero dependencies, tested on CPython 3.10 through 3.14. A comparison table against PyArmor 9.2.6 and full CLI documentation live in [`openprotect/README.md`](openprotect/README.md).

## Version scope

PyArmor's internal format is not a documented compatibility interface. Key-derivation inputs, blob layout, native runtime functions, and per-function encoding can change between releases.

Research therefore lives under the exact version investigated:

```text
pyarmor-research/
├── hooking/
│   ├── README.md
│   └── 9.2.6/
│       ├── README.md
│       └── pyarmor_hook.py
│
├── static/
│   ├── README.md
│   └── 9.2.6/
│       ├── README.md
│       ├── HOW_IT_WORKS.md
│       └── pyarmor_static.py
│
└── replica/
    ├── README.md
    └── 9.2.6/
        ├── README.md
        ├── HOW_IT_WORKS.md
        ├── CORE_DATA_HOW_IT_WORKS.md
        ├── core_data_1_cleaned.py
        ├── core_data_1_plaintext.py
        └── pyarmor_replica.py

openprotect/
├── README.md
├── pyproject.toml
├── src/openprotect/
└── tests/
```
