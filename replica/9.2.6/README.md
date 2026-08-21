# PyArmor Replica

Pure-Python tool that produces PyArmor 9.2.6-compatible distributions the real `pyarmor_runtime_000000` executes.

> AI-assisted: Documentation was written with AI support

## Install

```bash
pip install pyarmor cryptography
```

## Usage

```bash
# Obfuscate
python pyarmor_replica.py sample.py -o dist

# Run
python dist/sample.py

# Fresh RSA key per dist (self-contained)
python pyarmor_replica.py sample.py -o dist --fresh

# Generate runtime key only
python pyarmor_replica.py --gen-key -o mykey.bin
```

## How It Works

See [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for the full technical explanation.

Short version: source is compiled, function bodies are replaced with decrypt stubs, originals are AES-GCM encrypted, serialized with a custom marshal writer, and wrapped in a bootstrap script. The runtime decrypts each function in-place on first call.

## Files

| File | Description |
|------|-------------|
| `pyarmor_replica.py` | Standalone obfuscator + runtime key generator |
| `core_data_1_cleaned.py` | Cleaned maker engine source (readable names + comments) |
| `core_data_1_plaintext.py` | Original recovered maker engine source (299 KB) |
| `HOW_IT_WORKS.md` | Technical deep-dive |
| `CORE_DATA_HOW_IT_WORKS.md` | core.data.1 explanation |
| `README.md` | This file |

## Requirements

- Python 3.14+
- `pyarmor` for type definitions used by the recovered maker source
- `cryptography` for AES-GCM and RSA key generation

## Limitations

- PyArmor 9.2.6 / CPython 3.14 only
- BCC/RFT modes require server license constants (unavailable on trial)
- Maker source is from one specific build
