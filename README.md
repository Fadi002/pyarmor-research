# pyarmor-research

Reverse-engineering notes and tooling for PyArmor.

Scope:

- runtime behavior of the native PyArmor runtime;
- the protected blob format;
- key derivation and decryption;
- reconstruction of Python code objects;
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
└── static/
    ├── README.md
    └── 9.2.6/
        ├── README.md
        └── pyarmor_static.py
```