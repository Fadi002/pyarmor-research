# Static research

Offline reconstruction of PyArmor-protected Python programs.

The tooling reads the protected `.py` file and native runtime as bytes. It never imports or executes the protected program.

## Method

The static tooling:

1. locates the encrypted PyArmor blob in the `.py` file;
2. extracts the required runtime data from `pyarmor_runtime.pyd`;
3. derives the encryption key;
4. decrypts the blob;
5. parses the resulting Python `marshal` data;
6. reconstructs Python code objects;
7. handles the additional encrypted spans used by protected functions.

The format is inferred from the runtime binary and validated against sample files and runtime captures. It is not based on a PyArmor format specification.

## Static analysis limits

Static reconstruction can cover code paths that are never executed.

It cannot reconstruct native runtime objects created only after `pyarmor_runtime.pyd` loads. In 9.2.6, protected functions contain native `PyCFunction` objects including `C_ENTER_CO_OBJECT_INDEX`; the static parser represents these as placeholders and removes them before constructing `CodeType` objects.

Runtime captures expose discrepancies between the inferred format and the runtime representation.

## Layout

```text
static/
├── README.md
└── 9.2.6/
    ├── README.md
    └── pyarmor_static.py
```

Each version has its own parser and findings because PyArmor's internal format can change between releases.
