"""OPC2: openprotect container format, version 2 (AES-GCM).

Changes from v1: payload and undo blobs are sealed with AES-GCM
(authenticated encryption) instead of CTR+HMAC; the GCM tag travels at the
end of each sealed region. Layout:

    offset  size  field
    0       8     magic  b"OPENPRT1"
    8       2     format version (u16) = 2
    10      2     header length (u16)
    12      H     header: UTF-8 JSON object
    ..      P     sealed payload: AES-GCM ciphertext + 16-byte tag
    ..      U     sealed undo blob: AES-GCM ciphertext + 16-byte tag (optional)
    end     -     nothing else; authenticity is per-region via GCM tags

Header JSON fields:

    fmt        container format version (2)
    tool       producing tool version string
    module     module dotted name for metadata only (loader is name-agnostic)
    pytag      "major.minor.micro" of the interpreter that compiled the code
    nonce      base64 12-byte IV (GCM) / 16-byte nonce (legacy derivation)
    flags      dict of enabled transforms/options
    undo       true when a sealed undo blob is present
    payload_len ciphertext byte length (excluding tags)
    created    ISO timestamp, omitted under --seed

Key model: one outer key baked into the generated runtime package;
per-container keys derived HKDF-style from outer key + nonce.
Fully documented so independent readers are possible (docs/format.md).
"""

from __future__ import annotations

import base64
import json
import struct
from typing import Any, Optional

MAGIC = b"OPENPRT1"
FORMAT_VERSION = 2
_TAG_LEN = 16


class ContainerError(Exception):
    pass


def pack(
    header_fields: dict[str, Any],
    payload: bytes,
    undo_blob: Optional[bytes],
    nonce: bytes,
    enc_key: bytes,
    undo_key: bytes,
) -> bytes:
    """Seal payload/undo with AES-GCM using ``nonce``.

    Payload and undo use DIFFERENT derived keys so sharing one IV across
    regions never reuses a (key, nonce) pair - reuse would be catastrophic
    for GCM confidentiality/authenticity.
    """
    from .gcm import AesGcm

    gcm = AesGcm(enc_key)
    sealed_payload, payload_tag = gcm.seal(nonce, payload)
    if undo_blob is not None:
        sealed_undo, undo_tag = AesGcm(undo_key).seal(nonce, undo_blob)
    else:
        sealed_undo, undo_tag = b"", b""

    header = dict(header_fields)
    header["fmt"] = FORMAT_VERSION
    header["nonce"] = base64.b64encode(nonce).decode("ascii")
    header["undo"] = undo_blob is not None
    header["payload_len"] = len(sealed_payload)
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

    out = bytearray()
    out += MAGIC
    out += struct.pack(">HH", FORMAT_VERSION, len(header_bytes))
    out += header_bytes
    out += sealed_payload + payload_tag
    if undo_blob is not None:
        out += sealed_undo + undo_tag
    return bytes(out)


def unpack(blob: bytes, enc_key: bytes, undo_key: bytes) -> tuple[dict[str, Any], bytes, Optional[bytes]]:
    """Open an OPC2 container. Raises ContainerError on any tampering."""
    from .gcm import AesGcm

    if len(blob) < 8 + 4 or not blob.startswith(MAGIC):
        raise ContainerError("not an OPC container")
    fmt_version, header_len = struct.unpack(">HH", blob[8:12])
    if fmt_version != FORMAT_VERSION:
        raise ContainerError(f"unsupported container format version {fmt_version}")
    header_end = 12 + header_len
    try:
        header: dict[str, Any] = json.loads(blob[12:header_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerError("corrupt container header") from exc

    gcm = AesGcm(enc_key)
    nonce = base64.b64decode(header["nonce"])
    payload_len: int = header["payload_len"]

    payload_region = blob[header_end : header_end + payload_len + _TAG_LEN]
    if len(payload_region) != payload_len + _TAG_LEN:
        raise ContainerError("container truncated")
    ct, tag = payload_region[:-_TAG_LEN], payload_region[-_TAG_LEN:]
    try:
        payload = gcm.open(nonce, ct, tag)
    except ValueError as exc:
        raise ContainerError("integrity check failed: container corrupted or tampered") from exc

    undo_blob: Optional[bytes] = None
    if header.get("undo"):
        rest = blob[header_end + payload_len + _TAG_LEN :]
        if len(rest) <= _TAG_LEN:
            raise ContainerError("container truncated in undo region")
        try:
            undo_blob = AesGcm(undo_key).open(nonce, rest[:-_TAG_LEN], rest[-_TAG_LEN:])
        except ValueError as exc:
            raise ContainerError("undo region failed integrity check") from exc

    return header, payload, undo_blob


def read_header_unverified(blob: bytes) -> dict[str, Any]:
    """Best-effort header read for `inspect` on possibly-corrupt files."""
    if not blob.startswith(MAGIC):
        raise ContainerError("not an OPC container")
    _, header_len = struct.unpack(">HH", blob[8:12])
    return json.loads(blob[12 : 12 + header_len].decode("utf-8"))
