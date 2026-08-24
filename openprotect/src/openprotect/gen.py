"""The gen orchestrator: source in, protected distribution out."""

from __future__ import annotations

import ast
import dataclasses
import datetime as _dt
import hashlib
import hmac
import os
import pathlib
import zlib

from . import __version__
from .compiler import builder
from .frontend import transforms as tx
from .protection import container, keys
from .runtime import generator as rtgen

LEVELS = ("minimal", "standard", "strong")

_LEVEL_TRANSFORMS: dict[str, list[str]] = {
    "minimal": [],
    "standard": ["strip_docstrings"],
    "strong": ["strip_docstrings"],
}


@dataclasses.dataclass
class Options:
    level: str = "standard"
    seed: str | None = None
    no_recovery: bool = False
    excludes: list[str] = dataclasses.field(default_factory=list)
    expired: str | None = None
    period: int | None = None
    bind_devices: list[str] = dataclasses.field(default_factory=list)
    bind_data: str | None = None
    obf_code: int | None = None  # 0=plain bodies, 1=sealed, 2=sealed (strong)
    wrap: bool = True
    enable_rft: bool = False

    @property
    def licensed(self) -> bool:
        return bool(self.expired or self.bind_devices or self.bind_data or self.period)

    @property
    def effective_obf_code(self) -> int:
        if self.obf_code is not None:
            return self.obf_code
        return {"minimal": 0, "standard": 1, "strong": 2}.get(self.level, 1)


@dataclasses.dataclass
class ProtectedModule:
    module_name: str
    stub_text: str
    container: bytes


def _nonce(outer: bytes, module_name: str, seed: str | None) -> bytes:
    if seed is None:
        return os.urandom(12)
    material = hmac.new(outer, b"nonce:" + module_name.encode() + b":" + seed.encode(), hashlib.sha256)
    return material.digest()[:12]


def protect_source(
    source: str,
    module_name: str,
    filename: str,
    outer_key: bytes,
    opts: Options,
    license_header: dict | None = None,
) -> ProtectedModule:
    tree = ast.parse(source, filename=filename)
    tree = tx.apply_transforms(tree, _LEVEL_TRANSFORMS[opts.level])

    from .frontend.function_seal import FunctionSealer
    from .frontend.rft import RftRenamer
    from .frontend.string_mix import StringMixer

    sealer: FunctionSealer | None = None
    mixer = StringMixer()
    if opts.effective_obf_code >= 1:
        sealer = FunctionSealer(filename)
    if opts.level != "minimal":
        tree = mixer.process(tree)

    if opts.enable_rft:
        renamer = RftRenamer(RftRenamer.salt_for(outer_key, module_name))
        tree = renamer.process(tree)

    if sealer is not None:
        tree = sealer.process(tree)

    nonce = _nonce(outer_key, module_name, opts.seed)
    if sealer is not None and sealer.sealed_count:
        sealer.seal_all(outer_key, nonce)
    str_assign = mixer.finalize(outer_key, nonce) if mixer.count else None
    if str_assign is not None:
        tree.body.insert(0, str_assign)

    code = builder.compile_tree(tree, filename)
    payload = builder.marshal_code(code)

    undo_blob: bytes | None = None
    if not opts.no_recovery:
        undo_blob = zlib.compress(source.encode("utf-8"), 9)

    created = (
        None
        if opts.seed is not None
        else _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )
    header = {
        "tool": f"openprotect {__version__}",
        "module": module_name,
        "pytag": builder.python_tag(),
        "file": filename.replace("\\", "/"),
        "level": opts.level,
        "flags": {"transforms": list(_LEVEL_TRANSFORMS[opts.level])},
        "sealed_funcs": bool(sealer and sealer.sealed_count),
        "mixed_strs": mixer.count > 0,
        "wrap": opts.wrap,
        "created": created,
    }
    if license_header:
        header.update(license_header)
    inner = keys.derive_inner_keys(outer_key, nonce)
    blob = container.pack(header, payload, undo_blob, nonce, inner["enc"], inner["undo"])

    runtime_id = rtgen.make_runtime_id(opts.seed)
    pkg = f"openprotect_runtime_{runtime_id}"
    stamp = "" if opts.seed is not None else f", {_dt.datetime.now().isoformat(timespec='seconds')}"
    lines = [
        f"# openprotect {__version__}, {runtime_id}{stamp}",
        f"from {pkg} import __pyarmor__",
        f"__pyarmor__(__name__, __file__, {blob!r})",
    ]
    return ProtectedModule(module_name=module_name, stub_text="\n".join(lines) + "\n", container=blob)


def _is_excluded(rel: pathlib.Path, excludes: list[str]) -> bool:
    import fnmatch

    parts = rel.as_posix()
    for pattern in excludes:
        if fnmatch.fnmatch(parts, pattern) or fnmatch.fnmatch(rel.name, pattern):
            return True
    return False


def prepare_license(opts: "Options") -> "tuple[dict | None, dict | None]":
    """Shared license preparation for gen and bcc pipelines."""
    if not opts.licensed:
        return None, None
    from .protection import license as licensing
    from .protection import rsa as _rsa

    if opts.seed:
        seed_material = hashlib.sha256(f"openprotect-license:{opts.seed}".encode()).digest()
        key = _rsa.generate_deterministic_keypair(seed_material)
    else:
        key = _rsa.generate_keypair()
    descriptor = licensing.build_descriptor(
        opts.expired, opts.bind_devices, opts.bind_data, opts.period
    )
    desc_b64, sig_b64 = licensing.sign_descriptor(key, descriptor)
    return key, {"lic": desc_b64, "lic_sig": sig_b64}


def protect_path(source_root: pathlib.Path, dist_dir: pathlib.Path, opts: Options) -> list[pathlib.Path]:
    """Protect a file or a package directory recursively into dist_dir."""
    outer = keys.generate_outer_key(opts.seed, module_tag=source_root.stem)
    license_key, license_header = prepare_license(opts)

    rtgen.generate_runtime_package(dist_dir, rtgen.make_runtime_id(opts.seed), outer, license_key)

    if source_root.is_file():
        targets = [(source_root, pathlib.Path(source_root.name))]
    else:
        targets = sorted(
            (p, p.relative_to(source_root.parent))
            for p in source_root.rglob("*.py")
            if "__pycache__" not in p.parts and not _is_excluded(p.relative_to(source_root.parent), opts.excludes)
        )

    written: list[pathlib.Path] = []
    for abs_path, rel_path in targets:
        module_name = ".".join(rel_path.with_suffix("").parts) or rel_path.stem
        result = protect_source(
            abs_path.read_text(encoding="utf-8"),
            module_name,
            str(abs_path),
            outer,
            opts,
            license_header,
        )
        out_file = dist_dir / rel_path
        if out_file.resolve() == abs_path.resolve():
            raise SystemExit(
                f"refusing to overwrite source {abs_path} with its own protected output; "
                "choose a different --output directory"
            )
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(result.stub_text, encoding="utf-8")
        written.append(out_file)
    return written
