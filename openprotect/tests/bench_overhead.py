"""Measure protection cost and runtime overhead (spec section 20)."""

import os
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from openprotect.gen import Options, protect_path

FIXTURES = pathlib.Path(os.path.join(os.path.dirname(__file__), "fixtures"))
HELLO = FIXTURES / "hello.py"


def bench(name, fn, runs=3):
    best = min(_one(fn) for _ in range(runs))
    print(f"{name:34s} {best:8.1f} ms")


def _one(fn):
    t0 = time.perf_counter()
    fn()
    return (time.perf_counter() - t0) * 1000


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="op-bench-"))
    src = tmp / "hello.py"
    src.write_text(HELLO.read_text(encoding="utf-8"), encoding="utf-8")

    orig_size = len(src.read_bytes())

    def protect():
        d = tmp / f"b{time.time_ns()}"
        protect_path(src, d, Options(seed="bench"))

    bench("gen (single module, seeded)", protect)

    dist = tmp / "dist"
    protect_path(src, dist, Options(seed="bench"))
    stub = dist / "hello.py"
    rt = next(dist.glob("openprotect_runtime_*"))
    stub_kb = stub.stat().st_size / 1024
    runtime_kb = sum(p.stat().st_size for p in rt.rglob("*")) / 1024
    print(f"{'stub size':34s} {stub_kb:8.1f} KB")
    print(f"{'runtime package size':34s} {runtime_kb:8.1f} KB")
    print(f"{'original size':34s} {orig_size/1024:8.1f} KB")

    code_snip = (
        "import subprocess, sys, time\n"
        f"t0=time.perf_counter()\n"
        f"subprocess.run([sys.executable, r'{stub}'], capture_output=True)\n"
        "print((time.perf_counter()-t0)*1000)\n"
    )
    bench_file = tmp / "bench_run.py"
    bench_file.write_text(code_snip, encoding="utf-8")

    proc_times = []
    for _ in range(3):
        out = os.popen(f'"{sys.executable}" "{bench_file}"').read().strip()
        if out:
            proc_times.append(float(out.splitlines()[-1]))
    if proc_times:
        print(f"{'protected process wall time':34s} {min(proc_times):8.1f} ms")

    # interpreter baseline for comparison
    base_snip = (
        "import subprocess, sys, time\n"
        f"t0=time.perf_counter()\n"
        f"subprocess.run([sys.executable, r'{src}'], capture_output=True)\n"
        "print((time.perf_counter()-t0)*1000)\n"
    )
    bf = tmp / "bench_base.py"
    bf.write_text(base_snip, encoding="utf-8")
    base_times = []
    for _ in range(3):
        out = os.popen(f'"{sys.executable}" "{bf}"').read().strip()
        if out:
            base_times.append(float(out.splitlines()[-1]))
    if base_times:
        print(f"{'baseline process wall time':34s} {min(base_times):8.1f} ms")

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
