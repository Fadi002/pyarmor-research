# openprotect

> AI-assisted: Documentation was written with AI support

A small attempt at building PyArmor-style protection from scratch in pure Python.
It grew out of the research in this repo: after documenting how the real thing
works internally (see `../hooking`, `../static`, `../replica`), the obvious next
question was whether an open version of the same ideas could stand on its own.
This folder is that answer, and it works.

Clean-room by design. Nothing here reads PyArmor's files, extracts its keys, or
opens its containers. It produces its own format and ships its own runtime.
Works on CPython 3.10 through 3.14 with zero third-party dependencies.

## Quick start

```bash
pip install -e .
openprotect gen --seed demo hello.py     # -> dist/hello.py + dist/openprotect_runtime_xxx/
python dist/hello.py                     # same output as the original
openprotect deobfuscate dist/hello.py    # gives you back the original bytes
```

The `pyarmor` command also points here, so muscle memory works.

## CLI reference

### gen

```bash
openprotect gen [options] SCRIPT_OR_PACKAGE...
```

Protects one script, or a whole package folder with `-r`.

```bash
openprotect gen hello.py                       # basic, output in dist/
openprotect gen -O build mypkg/ -r             # package tree into build/
openprotect gen mypkg/ -r --exclude "test_*"   # skip matching paths
```

Protection options:

| Option | What it does |
|---|---|
| --level minimal/standard/strong | preset: minimal = container only; standard = sealed functions; strong adds more |
| --obf-code 0/1/2 | override the level preset for per-function protection |
| --no-wrap | rebuilt functions replace their wrappers after first call |
| --enable rft | rename private top-level functions and classes |
| --enable bcc | compile the module to a native .pyd via Cython (needs a C compiler) |

String constants are encrypted automatically at standard level and above.

Reproducibility:

| Option | What it does |
|---|---|
| --seed STRING | same source + same seed = byte-identical output |
| --no-recovery | leave out the undo map, so deobfuscate cannot reverse it |

Licensing:

```bash
openprotect gen --expired 2027-06-30 app.py              # dies after that date
openprotect gen --bind-device AA-BB-CC-DD-EE-FF app.py   # tied to one MAC
openprotect gen --bind-device "str:office1" app.py       # or any label string
openprotect gen --bind-data "customer-42" app.py         # embedded user data
openprotect gen --period 7 app.py                        # re-check license every 7 days
```

These combine. The license is RSA-PSS signed and checked before anything runs;
expired or wrong-machine builds refuse to start.

Bundling:

```bash
openprotect gen --pack onefile app.py                    # via PyInstaller
openprotect gen --pack onedir --packer nuitka app.py     # or Nuitka
```

PyInstaller is auto-detected first; use `--packer nuitka` to switch. Nuitka's
onefile mode needs spare memory for its final compression step, so on smaller
machines prefer onedir.

Native compilation:

```bash
openprotect gen --enable bcc app.py    # -> app.py stub + app.cp3XX-....pyd
```

No bytecode exists anywhere in this build, not even in memory. Requires Cython
and a C compiler. License checks are compiled into the native module itself,
and expired builds refuse at import.

### deobfuscate

```bash
openprotect deobfuscate dist/hello.py                # writes hello.restored.py
openprotect deobfuscate dist/hello.py -O orig.py     # or pick the path
```

Gives back your exact original bytes, as long as the build was not made with
--no-recovery. Works on both normal and bcc builds.

### inspect / verify

```bash
openprotect inspect dist/hello.py     # prints container metadata as JSON
openprotect verify dist/hello.py      # checks integrity, exit code 0 on pass
```

### init / cfg

```bash
openprotect init        # writes an openprotect.toml template
openprotect cfg         # shows the config it found
```

A minimal openprotect.toml looks like this (requires Python 3.11+ to read):

```toml
[protection]
level = "standard"

[output]
directory = "dist"
```

CLI flags always win over the file.

### global flags

-v/--version, -q/--silent, -d/--debug work on every command.

## How close is it to PyArmor?

Compared against PyArmor 9.2.6, tested directly on this machine:

| | PyArmor 9.2.6 | openprotect |
|---|---|---|
| Module encryption | AES-GCM blob, MD5-based key schedule | AES-GCM blob, HKDF-SHA256 key schedule |
| Tamper detection | Tag computed but never checked | Every tag verified, fails closed |
| Per-function bodies | Encrypted spans, re-encrypted after each call | Sealed separately, decrypted once and cached |
| String protection | Encrypted table, lazy decrypt | Same design |
| Identifier renaming (rft) | Cross-module, paid tier | Single module, free |
| Licensing | RSA-PSS custom variant, expiry, binding | RSA-PSS standard, expiry, binding, period |
| Native compilation (bcc) | Per function, paid tier | Whole module via Cython, free |
| Super mode / JIT | Yes, native | Not possible in pure Python |
| restrict/private modes | Yes | Not yet |
| Deobfuscate your own build | No | Yes, exact round-trip |
| Reproducible builds | No | Yes, with --seed |
| Runtime size | ~640 KB native .pyd | 14 KB of readable Python |
| Dependencies | Proprietary native engine | None |

Where PyArmor genuinely wins: its runtime re-encrypts function bodies after
every call, so a memory dump taken between calls sees ciphertext again. This
project keeps decrypted functions cached for the life of the process, because
honestly wiping interpreter-managed objects from pure Python is not a thing,
and pretending otherwise would be security theater. Its cross-module renaming
also goes wider than ours, and restrict/private modes are still on the todo
list.

Where this project wins: integrity checking that actually happens, standard
auditable crypto instead of custom variants, reproducible builds, source
recovery, and a runtime you can read in one sitting.

## Tests

69 tests across five interpreters (3.10 to 3.14): unit coverage for the crypto
and container layers, integration tests for every feature, and a differential
harness that runs original versus protected programs and compares stdout,
stderr, and exit codes byte-for-byte across fixtures covering classes,
closures, decorators, generators, async, threading, dataclasses, metaclasses,
exception handling, context managers, and package layouts with relative and
dynamic imports.

```bash
$env:PYTHONPATH='src'
py -3.13 -m unittest discover -s tests -t . -p "test_*.py"
```

## Scope statement

This is an independent implementation for research and for people who want
a PyArmor-like workflow without proprietary dependencies. It cannot read
files protected by real PyArmor, and deliberately never will: that road
requires extracting someone else's keys. Security claims are kept modest
throughout. Obfuscation raises the cost of analysis; it does not make code
uncrackable, and anyone who tells you otherwise is selling something.
