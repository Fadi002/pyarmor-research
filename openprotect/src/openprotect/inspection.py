"""Container inspection and integrity verification commands."""

from __future__ import annotations

import json
from typing import Any

from .deobfuscate import DeobfuscateError, extract_container, load_outer_key
from .protection import container, keys


def inspect(stub_or_blob: str) -> dict[str, Any]:
    path_stubbed = stub_or_blob.endswith(".py")
    if path_stubbed:
        from pathlib import Path

        data = extract_container(Path(stub_or_blob))
    else:
        from pathlib import Path

        data = Path(stub_or_blob).read_bytes()
    header = container.read_header_unverified(data)
    return header


def verify(stub_or_blob: str) -> bool:
    from pathlib import Path

    p = Path(stub_or_blob)
    if p.suffix == ".py":
        data = extract_container(p)
        outer_key, _rid = load_outer_key(p)
    else:
        raise DeobfuscateError(
            "raw containers need their runtime package; pass the protected .py stub"
        )
    try:
        header = container.read_header_unverified(data)
        import base64

        nonce = base64.b64decode(header["nonce"])
        inner = keys.derive_inner_keys(outer_key, nonce)
        container.unpack(data, inner["enc"], inner["undo"])
        return True
    except container.ContainerError:
        return False


def format_report(header: dict[str, Any]) -> str:
    return json.dumps(header, indent=2, sort_keys=True)
