# Hooking research

Runtime-side PyArmor research. The tooling captures protected code after the runtime decrypts it and before the runtime re-encrypts it.

## Runtime capture

In the versions studied (currently 9.2.6), a protected function's bytecode stays encrypted in memory and is decrypted in place before execution; the runtime re-encrypts it after the function returns.

The hook:

1. loads the target's PyArmor runtime module;
2. locates `C_ENTER_CO_OBJECT_INDEX`;
3. detours that function;
4. copies the returned `PyCodeObject` while its `co_code` is plaintext;
5. restores execution to the original runtime code.

## Coverage

Runtime capture only includes code paths reached during a run.

It does not capture:

- functions never called;
- untaken branches;
- disabled features;
- error paths not triggered.

Static analysis is the opposite: it operates on the complete protected file without requiring execution.

## Layout

```text
hooking/
├── README.md
└── 9.2.6/
    ├── README.md
    └── pyarmor_hook.py
```

The hook is version-specific: runtime layout, symbol availability, and offsets may change between PyArmor releases.
