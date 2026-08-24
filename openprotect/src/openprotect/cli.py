"""Command line interface.

Verbs mirror the observed PyArmor 9.x workflow; extras (deobfuscate) are
openprotect-specific and documented as such.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openprotect",
        description="Open-source Python obfuscation (PyArmor-compatible workflow)",
    )
    parser.add_argument("-v", "--version", action="version", version=f"openprotect {__version__}")
    parser.add_argument("-q", "--silent", action="store_true", help="suppress normal output")
    parser.add_argument("-d", "--debug", action="store_true", help="verbose diagnostics")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("gen", aliases=["generate", "g"], help="generate protected scripts + runtime")
    gen.add_argument("inputs", nargs="+", help="scripts or package directories")
    gen.add_argument("-O", "--output", default="dist", help="output directory")
    gen.add_argument("-r", "--recursive", action="store_true", help="recurse into directories")
    gen.add_argument("--exclude", action="append", default=[], metavar="PATTERN")
    gen.add_argument("--level", choices=("minimal", "standard", "strong"), default=None)
    gen.add_argument("--seed", default=None, help="deterministic build seed")
    gen.add_argument("--no-recovery", action="store_true", help="omit the undo map")
    lic = gen.add_argument_group("runtime key / licensing")
    lic.add_argument("-e", "--expired", default=None, metavar="DATE", help="ISO date after which scripts refuse to run")
    lic.add_argument("--period", type=int, default=None, metavar="N", help="revalidation period in days (enforced per wrapper call)")
    lic.add_argument("-b", "--bind-device", dest="bind_devices", action="append", default=[], metavar="DEV", help="MAC address or 'str:value' device binding; repeatable")
    lic.add_argument("--bind-data", default=None, metavar="STRING", help="opaque data surfaced as __pyarmor_license__['data']")
    obf = gen.add_argument_group("obfuscation levels")
    obf.add_argument("--obf-code", type=int, choices=(0, 1, 2), default=None, help="0=plain bodies, 1=sealed functions (default), 2=sealed+strong preset")
    obf.add_argument("--no-wrap", action="store_true", help="let rebuilt functions replace their wrappers after first call")
    obf.add_argument("--enable", action="append", default=[], metavar="FEATURE", help="enable extra feature: rft (identifier renaming)")
    pk = gen.add_argument_group("bundling")
    pk.add_argument("--pack", choices=("onefile", "onedir"), default=None, help="bundle the protected script into a standalone executable")
    pk.add_argument("--packer", default=None, help="bundler to use: pyinstaller or nuitka (auto-detected when omitted)")

    deob = sub.add_parser("deobfuscate", help="recover original source from a protected stub")
    deob.add_argument("script", help="protected .py stub")
    deob.add_argument("-O", "--output", default=None, help="output path")

    ins = sub.add_parser("inspect", help="show container metadata (unverified)")
    ins.add_argument("script", help="protected .py stub")

    ver = sub.add_parser("verify", help="verify container integrity against its runtime key")
    ver.add_argument("script", help="protected .py stub")

    ini = sub.add_parser("init", help="write an openprotect.toml template")
    ini.add_argument("-f", "--force", action="store_true")

    cfg = sub.add_parser("cfg", help="print resolved configuration")
    cfg.add_argument("--project", action="store_true", help="read openprotect.toml")

    return parser


_TEMPLATE = """\
# openprotect configuration
[protection]
level = "standard"

[output]
directory = "dist"
"""


def _load_config() -> dict:
    path = pathlib.Path("openprotect.toml")
    if not path.exists():
        return {}
    try:
        import tomllib
    except ModuleNotFoundError:
        if not getattr(_load_config, "_warned", False):
            print("note: openprotect.toml requires Python >= 3.11; ignoring it", file=sys.stderr)
            _load_config._warned = True  # type: ignore[attr-defined]
        return {}
    with path.open("rb") as fh:
        return tomllib.load(fh)  # type: ignore[name-defined]


def _resolve(args: argparse.Namespace) -> argparse.Namespace:
    """Layer config file defaults under explicit CLI choices."""
    cfg = _load_config()
    protection = cfg.get("protection", {})
    output = cfg.get("output", {})
    if args.command in ("gen", "generate", "g"):
        args.level = args.level or protection.get("level", "standard")
        if args.output == "dist" and "directory" in output:
            args.output = output["directory"]
        if not args.exclude:
            args.exclude = list(cfg.get("packages", {}).get("exclude", []))
    return args


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = _resolve(parser.parse_args(argv))
    verbose = not getattr(args, "silent", False)

    if args.command in ("gen", "generate", "g"):
        from .gen import Options, prepare_license, protect_path

        unsupported = set(args.enable) - {"rft", "bcc"}
        if unsupported:
            parser.error(
                f"--enable {','.join(sorted(unsupported))}: not supported by the pure-Python "
                "implementation (native-only upstream features)"
            )
        bcc_mode = "bcc" in args.enable

        opts = Options(
            level=args.level,
            seed=args.seed,
            no_recovery=args.no_recovery,
            excludes=args.exclude,
            expired=args.expired,
            period=args.period,
            bind_devices=list(args.bind_devices),
            bind_data=args.bind_data,
            obf_code=args.obf_code,
            wrap=not args.no_wrap,
            enable_rft="rft" in args.enable,
        )

        if bcc_mode:
            from pathlib import Path as _P

            from .bcc import build_bcc_module
            from .protection.keys import generate_outer_key

            license_key, license_header = prepare_license(opts)
            written = []
            for entry in args.inputs:
                src = _P(entry)
                outer_key = generate_outer_key(opts.seed, module_tag=src.stem)
                result = build_bcc_module(
                    src.read_text(encoding="utf-8"),
                    src.stem,
                    str(src),
                    outer_key,
                    _P(args.output),
                    seed=opts.seed,
                    no_recovery=opts.no_recovery,
                    enable_rft=opts.enable_rft,
                    license_key=license_key,
                    license_header=license_header,
                )
                written.append(result.stub_path)
                for w in result.warnings:
                    print(f"warning: {w}")
            if verbose:
                print(f"done: {len(written)} native module(s) -> {args.output}")
            return 0

        dist = pathlib.Path(args.output)
        written: list[pathlib.Path] = []
        for entry in args.inputs:
            source_root = pathlib.Path(entry)
            target_dir = dist / source_root.stem if source_root.is_dir() else dist
            written += protect_path(source_root, target_dir, opts)
        if verbose:
            for w in written:
                print(f"protected {w}")
            print(f"done: {len(written)} module(s) -> {dist}")

        if args.pack:
            from .packagers import pack

            if len(written) != 1:
                parser.error("--pack currently supports exactly one input script")
            artifact = pack(
                written[0],
                dist,
                mode=args.pack,
                tool=args.packer,
                out_dir=dist / "pack",
            )
            if verbose:
                print(f"packed -> {artifact}")
        return 0

    if args.command == "deobfuscate":
        from pathlib import Path

        stub = Path(args.script)
        out = Path(args.output) if args.output else default_output_for(stub)

        if "_OP_UNDO" in stub.read_text(encoding="utf-8"):
            from .bcc import recover_bcc_source
            from .deobfuscate import load_outer_key

            outer_key, _rid = load_outer_key(stub)
            source, _hdr = recover_bcc_source(stub, outer_key)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(source, encoding="utf-8", newline="")
        else:
            from .deobfuscate import deobfuscate as _deobfuscate_opc2

            _deobfuscate_opc2(stub, out)
        if verbose:
            print(f"recovered -> {out}")
        return 0

    if args.command == "inspect":
        from .inspection import format_report, inspect

        print(format_report(inspect(args.script)))
        return 0

    if args.command == "verify":
        from .inspection import verify

        ok = verify(args.script)
        if verbose:
            print("OK" if ok else "FAILED: integrity check")
        return 0 if ok else 1

    if args.command == "init":
        target = pathlib.Path("openprotect.toml")
        if target.exists() and not args.force:
            print("openprotect.toml already exists (use --force)", file=sys.stderr)
            return 1
        target.write_text(_TEMPLATE, encoding="utf-8")
        if verbose:
            print(f"wrote {target}")
        return 0

    if args.command == "cfg":
        cfg = _load_config()
        if verbose:
            print(cfg if cfg else "(no openprotect.toml found)")
        return 0

    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
