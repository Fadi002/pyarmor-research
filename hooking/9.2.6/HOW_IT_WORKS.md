# How pyarmor_hook.py works

## C_ENTER and the decrypt window

A protected function's bytecode is encrypted at rest and decrypted in memory, in place, immediately before that function runs, then re-encrypted the instant it returns. Capture requires intercepting execution during the window between decrypt and re-encrypt, for each protected function, on each call.

The runtime performs this decryption inside one C function, exposed internally as a Python-callable named `C_ENTER_CO_OBJECT_INDEX`. Every protected function's bytecode calls it at the top. `pyarmor_hook.py` locates that function inside the loaded runtime and copies its output before the caller (CPython bytecode execution) resumes.

## Runtime discovery

`find_runtime()` opens the target `.py` file as text, regexes out the `pyarmor_runtime_XXXXXX` package name PyArmor embeds in it, then walks up from the script's directory (also checking a `dist/` subfolder at each level) for `<name>/pyarmor_runtime.pyd`. `load_runtime()` imports that package as a normal Python module, the one point where PyArmor-authored code executes, and resolves its Windows module handle (`HMODULE`) via `GetModuleHandleW` so later steps can read and patch its memory directly.

## Locating C_ENTER

The runtime's layout, and therefore where `C_ENTER_CO_OBJECT_INDEX` ends up in memory, isn't fixed or documented, and can shift between builds or between runs under ASLR. Hardcoding an address was a dead end, so I found the function by watching the runtime's own import table instead.

I patch the runtime's Import Address Table (IAT), specifically the resolved-import slot for `PyImport_ExecCodeModuleObject` (the CPython C API function that executes a freshly-decrypted module's code object). `_find_iat_slot()` locates that slot by scanning the `.idata` section for an 8-byte pointer matching the real function's address. A naive `ff 15` caller scan is easy to get wrong here: the call site references the IAT slot address, not the imported function directly, so I match the resolved pointer instead. Once found, I overwrite the IAT entry with the address of a ctypes callback (`import_hook`).

When the runtime calls what it treats as `PyImport_ExecCodeModuleObject` to execute the module it just decrypted, it calls `_on_import()` instead. That function inspects the incoming code object's `co_consts` for a `builtin_function_or_method` named `C_ENTER_CO_OBJECT_INDEX`. Once found, `_read_ml_meth()` reads the underlying `PyCFunctionObject`'s `m_ml->ml_meth` field, the native function pointer behind that Python-visible callable, giving me the address of `C_ENTER_CO_OBJECT_INDEX` with no address hardcoded anywhere.

`_on_import()` returns `NULL` instead of letting the real exec proceed, aborting this first load. Calling the real exec from inside the callback caused nested callbacks on the same thread, which corrupted the callback chain and crashed around `NULL+0x10`, so the first load has to abort. `run()` retries it after the detour is in place.

## Detour installation

`install_detour()` installs an inline hook at the resolved `C_ENTER_CO_OBJECT_INDEX` address:

1. Copy the function's first 16 bytes (`HOOK_LEN`).
2. Allocate an executable page containing those 16 original bytes, followed by a 6-byte absolute jump (`FF 25 00 00 00 00` plus an 8-byte target) back to `C_ENTER_CO_OBJECT_INDEX + 16`. This trampoline replays the original prologue, then resumes execution where the patch stops.
3. Overwrite the function's first 16 bytes, in place, with the same style of absolute jump, targeting a Python `ctypes.CFUNCTYPE` callback.

Every subsequent call to `C_ENTER_CO_OBJECT_INDEX` lands in the Python callback first. The callback calls the trampoline, which runs the original prologue and lets the function finish its decrypt, inspects the result, then returns control. One thing that bit me here was object lifetime: `hook`/`orig_fn`/`tramp` are stashed on `self` so the garbage collector does not free them while the patch is live. Letting any of the three get collected turns into an intermittent `0xC0000005` while the runtime is still calling into this address.

## Capture

`C_ENTER_CO_OBJECT_INDEX`'s return value is a `bytes` object whose first 8 bytes are a pointer to the `PyCodeObject` it just decrypted. The callback reads that pointer with `PyBytes_AsString`/`PyBytes_Size`, casts it to a Python object with `ctypes.cast(ptr, ctypes.py_object).value`, and if it is a `types.CodeType`, calls `_snapshot_code()`.

The window is tighter than it looks: `co_code` is re-encrypted in place the moment the corresponding `C_LEAVE` fires, which can happen almost immediately after entry for a short function. So `_snapshot_code()` copies every field of the code object, including a fresh `bytes()` copy of `co_code`, into a new `types.CodeType` inside the callback, before re-encryption can occur. A `(co_name, snap.co_code)` pair deduplicates repeated calls to the same function.

## Coverage

A plain import only triggers `C_ENTER` for code that executes at import time: the module body and anything called unconditionally from it. Code behind `if __name__ == "__main__":`, or defined but never called, never runs, so import alone never captures it.

`run()` closes that gap with two mechanisms. `exec_target()` always imports the target as a named module (via `importlib.util.spec_from_file_location`), never as `__main__`; running it as `__main__` takes a different code path in the runtime that bypasses the IAT-hook discovery above, so the named import is the only route that lands in the hook. `force_call()` walks every top-level function the module defines and calls each directly, synthesizing a placeholder positional argument (`"CTF_SOLVED"`) for every required parameter and keyword-only argument without a default, so `__main__`-guarded logic executes at least once and its `C_ENTER` calls are captured. A function raising on the placeholder input is non-fatal; it has already executed past its own decrypt point.

`run()` executes in two passes. Pass 1 discovers `C_ENTER`'s address via the IAT hook, then restores the original IAT entry. Pass 2 re-imports the module with the inline detour permanently in place and performs the capture.

## Report

`report()` iterates every uniquely-captured code object and prints its `co_names`, `co_consts`, the hex of its `co_code`, and a `dis.Bytecode(co).dis()` disassembly. Each object is captured from `C_ENTER`'s own return value during execution, so the disassembly reflects the bytecode the interpreter executes.

## C_ENTER_CO_OBJECT_INDEX (sub_63304440)

`sub_63304440` (Python 3.14 build, image base `0x63300000`) is the function registered as `C_ENTER_CO_OBJECT_INDEX`, which `pyarmor_hook.py` detours. `sub_63304440` is an IDA-generated name because the binary has no symbols. Its role is inferred from the decompiled behavior. The excerpt omits the trial-expiry timestamp check and the reentrancy counter at `a2+48`.

```c
// sub_63304440, aka C_ENTER_CO_OBJECT_INDEX
v19 = sub_63380EB0(a1: v14 + 24);            // GCM reset, on a persistent per-thread context
if ( v19 == 0 ) {
    v19 = sub_63381600(a1: v17, a2: &Time, a3: v18);      // GCM set-IV
    if ( v19 == 0 ) {
        v19 = sub_63380F10(a1: v17, a2: 0, a3: 0);         // GCM add-AAD, called with (NULL, 0): no AAD used
        if ( v19 == 0 ) {
            v19 = sub_633811E0(                            // GCM process: decrypt the span in place
                a1: v17,
                a2: (unsigned int)v5 + v16,                 // ciphertext pointer, into the function's own co_code
                a3: v15,                                    // span length
                a4: (unsigned int)v5 + v16,                 // output pointer: same address, decrypt-in-place
                a5: 0);                                     // direction flag: 0 = decrypt
            if ( v19 == 0 ) {
                if ( (*(_BYTE *)(a2 + 40) & 8) != 0 ) {
                    // flag bit set: copy the now-decrypted bytes over co_code's
                    // matching span, completing the in-place patch (byte/dword/
                    // qword-granularity copy loop, elided here)
                }
                goto LABEL_5;   // success path, falls through to the caller
            }
        }
    }
}
```

This is an AES-GCM decrypt of a span inside `co_code`, using a persistent GCM context (`v14 + 24`, not freshly initialized per call) as a stream cipher; no `gcm_done`/tag-check call exists in this function. No custom bytecode VM appears anywhere in this path.


